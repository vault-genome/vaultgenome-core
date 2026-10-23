// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package awssigv4 signs AWS API requests with Signature Version 4
// (AWS4-HMAC-SHA256), written from AWS's specification — the IAM User
// Guide's "Create a signed AWS API request" and "Elements of an AWS API
// request signature" (library 302dde356a9c…, 556a095c096d…) — and held to
// AWS's own test suite (aws-c-auth at 84a26ea, tests/aws-signing-test-suite/v4,
// Apache-2.0, in testdata): for every case the canonical request, the
// string to sign, the signature and the Authorization header come out
// byte for byte (ADR 0036, part three).
//
// It signs in the Authorization header; the query-string form (presigned
// URLs) is not here, because nothing in the product presigns. The path is
// URI-encoded once more over its wire form, as every service but Amazon
// S3 expects; S3's single encoding is not here either.
package awssigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Algorithm is the signing algorithm's name in the string to sign and the
// Authorization header.
const Algorithm = "AWS4-HMAC-SHA256"

const (
	timeFormat  = "20060102T150405Z"
	dateFormat  = "20060102"
	termination = "aws4_request"
)

// Credentials are an access key, its secret, and — for temporary
// credentials — the session token.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// String names the access key and never the secret or the token.
func (c Credentials) String() string {
	return fmt.Sprintf("awssigv4.Credentials{AccessKeyID: %q, SecretAccessKey: <redacted>, SessionToken: <%d bytes>}", c.AccessKeyID, len(c.SessionToken))
}

// GoString is String, so %#v does not print the secret either.
func (c Credentials) GoString() string { return c.String() }

// Field is one header field as it is sent: its name in any case, its value.
type Field struct {
	Name  string
	Value string
}

// Request is what is signed: the method, the path and the query as they go
// on the wire (percent-encoded; the query without its '?'), the header
// fields in the order they are sent — repeated names included — and the
// body.
type Request struct {
	Method string
	Path   string
	Query  string
	Header []Field
	Body   []byte
}

// Options are the signature's scope and the choices the specification
// leaves to the service.
type Options struct {
	Region  string
	Service string
	// Time is the request's time; its UTC date and time go into X-Amz-Date
	// and the credential scope.
	Time time.Time
	// NormalizePath removes "." and ".." segments and repeated slashes from
	// the path before it is encoded; every service but Amazon S3 expects it.
	NormalizePath bool
	// SignBody adds X-Amz-Content-Sha256, the body's SHA-256, and signs it.
	SignBody bool
	// OmitSessionToken adds X-Amz-Security-Token after the signature instead
	// of signing it, for the services that ask for that. KMS signs it.
	OmitSessionToken bool
}

// Signature is the outcome: the three strings the signature is made over
// and from, the signature, the Authorization header, and the header fields
// the request gains, in the order they are added.
type Signature struct {
	CanonicalRequest string
	StringToSign     string
	Signature        string
	Authorization    string
	Header           []Field
}

// Sign signs r with c under o.
func Sign(r Request, c Credentials, o Options) (Signature, error) {
	if err := checkInputs(r, c, o); err != nil {
		return Signature{}, err
	}
	t := o.Time.UTC()
	amzDate := t.Format(timeFormat)
	date := t.Format(dateFormat)
	scope := date + "/" + o.Region + "/" + o.Service + "/" + termination

	bodyHash := sha256.Sum256(r.Body)
	payloadHash := hex.EncodeToString(bodyHash[:])

	var added []Field
	added = append(added, Field{Name: "X-Amz-Date", Value: amzDate})
	if c.SessionToken != "" && !o.OmitSessionToken {
		added = append(added, Field{Name: "X-Amz-Security-Token", Value: c.SessionToken})
	}
	if o.SignBody {
		added = append(added, Field{Name: "X-Amz-Content-Sha256", Value: payloadHash})
	}
	signed := make([]Field, 0, len(r.Header)+len(added))
	signed = append(signed, r.Header...)
	signed = append(signed, added...)

	canonHeaders, signedHeaders := canonicalHeaders(signed)
	path := r.Path
	if path == "" {
		path = "/"
	}
	if o.NormalizePath {
		path = normalizePath(path)
	}
	query, err := canonicalQuery(r.Query)
	if err != nil {
		return Signature{}, err
	}
	canonical := strings.Join([]string{
		r.Method,
		uriEncode(path, true),
		query,
		canonHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	canonHash := sha256.Sum256([]byte(canonical))
	stringToSign := Algorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(canonHash[:])

	key := signingKey(c.SecretAccessKey, date, o.Region, o.Service)
	sig := hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))
	authorization := Algorithm + " Credential=" + c.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + sig

	if c.SessionToken != "" && o.OmitSessionToken {
		added = append(added, Field{Name: "X-Amz-Security-Token", Value: c.SessionToken})
	}
	added = append(added, Field{Name: "Authorization", Value: authorization})
	return Signature{
		CanonicalRequest: canonical,
		StringToSign:     stringToSign,
		Signature:        sig,
		Authorization:    authorization,
		Header:           added,
	}, nil
}

// signingKey derives the key of the scope: DateKey = HMAC("AWS4"+secret,
// date), then the region, the service and "aws4_request" in turn.
func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	k = hmacSHA256(k, []byte(region))
	k = hmacSHA256(k, []byte(service))
	return hmacSHA256(k, []byte(termination))
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// canonicalHeaders lowercases the names, sorts them, trims each value and
// turns its runs of spaces into one, and joins the values of a repeated
// name with commas in the order they were sent.
func canonicalHeaders(fields []Field) (canonical, signed string) {
	values := make(map[string][]string, len(fields))
	var names []string
	for _, f := range fields {
		n := strings.ToLower(f.Name)
		if _, seen := values[n]; !seen {
			names = append(names, n)
		}
		values[n] = append(values[n], trimAll(f.Value))
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(strings.Join(values[n], ","))
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

// trimAll removes leading and trailing spaces and turns each run of spaces
// inside into one space.
func trimAll(v string) string {
	v = strings.Trim(v, " ")
	if !strings.Contains(v, "  ") {
		return v
	}
	var b strings.Builder
	b.Grow(len(v))
	space := false
	for i := 0; i < len(v); i++ {
		if v[i] == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// normalizePath removes "." and ".." segments (RFC 3986 §5.2.4) and empty
// segments — repeated slashes — and keeps a trailing slash.
func normalizePath(p string) string {
	segments := strings.Split(p, "/")
	var out []string
	for _, s := range segments {
		switch s {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	last := segments[len(segments)-1]
	res := "/" + strings.Join(out, "/")
	if last == "" || last == "." || last == ".." {
		res += "/"
	}
	return res
}

// canonicalQuery decodes each name and value of the query as sent,
// URI-encodes them again, sorts by name and then by value — after
// encoding — and joins them; a name without '=' has the empty value.
func canonicalQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	type pair struct{ k, v string }
	var pairs []pair
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		dk, err := percentDecode(k)
		if err != nil {
			return "", fmt.Errorf("awssigv4: query name %q: %w", k, err)
		}
		dv, err := percentDecode(v)
		if err != nil {
			return "", fmt.Errorf("awssigv4: query value %q: %w", v, err)
		}
		pairs = append(pairs, pair{uriEncode(dk, false), uriEncode(dv, false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&"), nil
}

// uriEncode is the specification's UriEncode: every byte but the
// unreserved ones (A–Z, a–z, 0–9, '-', '.', '_', '~') as '%' and two
// uppercase hexadecimal digits; '/' kept when keepSlash.
func uriEncode(s string, keepSlash bool) string {
	const hexUpper = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unreserved(c) || (keepSlash && c == '/') {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexUpper[c>>4])
		b.WriteByte(hexUpper[c&0x0f])
	}
	return b.String()
}

func unreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// percentDecode decodes %XX escapes; '+' is a plus sign (RFC 3986), not a
// space.
func percentDecode(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
			return "", errors.New("a '%' not followed by two hexadecimal digits")
		}
		b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
		i += 2
	}
	return b.String(), nil
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// checkInputs refuses what the specification cannot sign, or what would be
// signed one way and sent another: a field the signer adds already present,
// a value with a control character, a missing host.
func checkInputs(r Request, c Credentials, o Options) error {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return errors.New("awssigv4: an access key ID and a secret access key are required")
	}
	if !isToken(c.AccessKeyID) {
		return errors.New("awssigv4: the access key ID has a character a credential scope cannot carry")
	}
	if !scopePart(o.Region) || !scopePart(o.Service) {
		return fmt.Errorf("awssigv4: region %q and service %q must be lowercase letters, digits and '-'", o.Region, o.Service)
	}
	if o.Time.IsZero() {
		return errors.New("awssigv4: the request's time is required")
	}
	if !isToken(r.Method) {
		return fmt.Errorf("awssigv4: method %q is not an HTTP token", r.Method)
	}
	if r.Path != "" && r.Path[0] != '/' {
		return fmt.Errorf("awssigv4: path %q does not start with '/'", r.Path)
	}
	if strings.ContainsAny(r.Path, "?#") || strings.ContainsAny(r.Query, "#") {
		return errors.New("awssigv4: the path carries a '?' or '#', or the query a '#'")
	}
	host := false
	for _, f := range r.Header {
		if !isToken(f.Name) {
			return fmt.Errorf("awssigv4: header name %q is not an HTTP token", f.Name)
		}
		for i := 0; i < len(f.Value); i++ {
			if f.Value[i] < 0x20 || f.Value[i] == 0x7f {
				return fmt.Errorf("awssigv4: header %s carries a control character", f.Name)
			}
		}
		switch strings.ToLower(f.Name) {
		case "host":
			host = true
		case "authorization", "x-amz-date":
			return fmt.Errorf("awssigv4: the request already carries %s", f.Name)
		case "x-amz-security-token":
			if c.SessionToken != "" {
				return errors.New("awssigv4: the request already carries X-Amz-Security-Token")
			}
		case "x-amz-content-sha256":
			if o.SignBody {
				return errors.New("awssigv4: the request already carries X-Amz-Content-Sha256")
			}
		}
	}
	if !host {
		return errors.New("awssigv4: the host header is required")
	}
	for i := 0; i < len(c.SessionToken); i++ {
		if c.SessionToken[i] < 0x21 || c.SessionToken[i] > 0x7e {
			return errors.New("awssigv4: the session token has a character a header cannot carry")
		}
	}
	return nil
}

func scopePart(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// isToken: RFC 9110 §5.6.2 tchar.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}
