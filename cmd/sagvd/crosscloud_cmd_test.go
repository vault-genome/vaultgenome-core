// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ai-continuity-platform/core/internal/genome/bundle"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/vault/kms"
	"github.com/stretchr/testify/require"
)

// sealedGenomeKey seals a genome the way acpctl does and writes its key
// file; it returns the bundle's key ID, the key file and the key.
func sealedGenomeKey(t *testing.T, dir string) (string, string, []byte) {
	t.Helper()
	blob, dek, err := bundle.SealBytes(bundle.Header{
		ContentKind:     bundle.ContentDir,
		ContentRef:      "/adapters/1",
		ContentSnapshot: []byte(`{"components":[]}`),
	}, []byte("lora delta"))
	require.NoError(t, err)
	r, err := bundle.NewReader(bytes.NewReader(blob))
	require.NoError(t, err)
	kid := r.Header.KeyID
	path := filepath.Join(dir, kid+".key")
	require.NoError(t, os.WriteFile(path, dek, 0o600))
	return kid, path, dek
}

func TestReadKeyFiles_ReleasesOnlyPrivateMatchingKeys(t *testing.T) {
	dir := t.TempDir()
	kid, path, dek := sealedGenomeKey(t, dir)
	generic := filepath.Join(dir, "generic.key")
	require.NoError(t, os.WriteFile(generic, bytes.Repeat([]byte{7}, 32), 0o600))

	got, err := readKeyFiles([]string{kid + ":" + path, "vault-dek-1:" + generic})
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, kid, string(got[0].KeyID))
	require.Equal(t, dek, got[0].Plaintext)
	require.Equal(t, "vault-dek-1", string(got[1].KeyID))

	open := filepath.Join(dir, "open.key")
	require.NoError(t, os.WriteFile(open, dek, 0o644))
	short := filepath.Join(dir, "short.key")
	require.NoError(t, os.WriteFile(short, dek[:31], 0o600))
	_, _, otherDEK := sealedGenomeKey(t, t.TempDir())
	other := filepath.Join(dir, "other.key")
	require.NoError(t, os.WriteFile(other, otherDEK, 0o600))

	for name, tc := range map[string]struct {
		entries []string
		want    string
	}{
		"no path":           {[]string{kid}, "must be KID:PATH"},
		"no kid":            {[]string{":" + path}, "must be KID:PATH"},
		"missing file":      {[]string{kid + ":" + filepath.Join(dir, "absent")}, "no such file"},
		"readable by group": {[]string{kid + ":" + open}, "chmod 600"},
		"not a key":         {[]string{kid + ":" + short}, "not a 32-byte key"},
		"another key":       {[]string{kid + ":" + other}, "this key is not " + kid},
		"same kid twice":    {[]string{kid + ":" + path, kid + ":" + path}, "given twice"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readKeyFiles(tc.entries)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestCrossCloudRestoreCmd_RefusesBeforeContactingAnyone(t *testing.T) {
	dir := t.TempDir()
	kid, path, _ := sealedGenomeKey(t, dir)
	base := []string{"-config", filepath.Join(dir, "absent.json"), "-decision-id", "dec-1",
		"-destination-kind", "gcp-sev-snp", "-destination-endpoint", "https://dest.example:8443"}

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no config":       {[]string{"-decision-id", "d"}, "-config required"},
		"no decision":     {[]string{"-config", "c"}, "-decision-id required"},
		"no kind":         {[]string{"-config", "c", "-decision-id", "d"}, "-destination-kind required"},
		"no endpoint":     {[]string{"-config", "c", "-decision-id", "d", "-destination-kind", "gcp-sev-snp"}, "-destination-endpoint required"},
		"plain http":      {[]string{"-config", "c", "-decision-id", "d", "-destination-kind", "gcp-sev-snp", "-destination-endpoint", "http://10.0.0.8:8443", "-key-file", kid + ":" + path}, "plain http"},
		"no key":          {base, "-key-file KID:PATH required"},
		"hex key refused": {append(append([]string(nil), base...), "-key", kid+":"+strings.Repeat("ab", 32)), "flag provided but not defined: -key"},
		"unknown kind":    {[]string{"-config", "c", "-decision-id", "d", "-destination-kind", "vmware", "-destination-endpoint", "https://d", "-key-file", kid + ":" + path}, "-destination-kind"},
		"bad key file":    {append(append([]string(nil), base...), "-key-file", kid+":"+filepath.Join(dir, "absent")), "no such file"},
		"missing config":  {append(append([]string(nil), base...), "-key-file", kid+":"+path), "absent.json"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runCrossCloudRestoreCmd(tc.args)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestBuildCoordinationOutput_ClassifiesFailures(t *testing.T) {
	out := buildCoordinationOutput(kms.CoordinationResult{}, shared_errors.Authority(shared_errors.CodeRequiredFieldMissing, "operator stop in force", nil), 4)
	require.Equal(t, "failed", out.Status)
	require.Equal(t, "authority", out.Error.Category)
	require.Equal(t, 4, out.AuditChainLength)

	out = buildCoordinationOutput(kms.CoordinationResult{}, errors.New("plain"), 0)
	require.Equal(t, "unknown", out.Error.Category)
	require.Equal(t, "unknown", out.Error.Code)

	out = buildCoordinationOutput(kms.CoordinationResult{PolicyVersion: "v1;revocation=2"}, nil, 3)
	require.Equal(t, "ok", out.Status)
	require.Nil(t, out.Error)
	require.Equal(t, "v1;revocation=2", out.PolicyVersion)
}

func TestCrossCloudConfirmCmd_RefusesBeforeContactingAnyone(t *testing.T) {
	dir := t.TempDir()
	notBundle := filepath.Join(dir, "x.genome")
	require.NoError(t, os.WriteFile(notBundle, []byte("not a bundle"), 0o644))
	blob, _, err := bundle.SealBytes(bundle.Header{ContentKind: bundle.ContentDir, ContentRef: "/a", ContentSnapshot: []byte(`{"components":[]}`)}, []byte("p"))
	require.NoError(t, err)
	good := filepath.Join(dir, "g.genome")
	require.NoError(t, os.WriteFile(good, blob, 0o644))
	base := []string{"-config", filepath.Join(dir, "absent.json"), "-decision-id", "d", "-destination-endpoint", "https://dest:8443"}

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no config":      {[]string{"-decision-id", "d"}, "-config required"},
		"no decision":    {[]string{"-config", "c"}, "-decision-id required"},
		"no endpoint":    {[]string{"-config", "c", "-decision-id", "d"}, "-destination-endpoint required"},
		"no genome":      {base, "-bundle or -key-id required"},
		"negative wait":  {append(append([]string(nil), base...), "-key-id", "k", "-wait", "-1s"), "-wait must not be negative"},
		"plain http":     {[]string{"-config", "c", "-decision-id", "d", "-destination-endpoint", "http://10.1.1.1:8443", "-key-id", "k"}, "plain http"},
		"not a bundle":   {append(append([]string(nil), base...), "-bundle", notBundle), "not a v3"},
		"other key":      {append(append([]string(nil), base...), "-bundle", good, "-key-id", "genome-000000000000-g0-000000000000"), "not -key-id"},
		"empty snapshot": {append(append([]string(nil), base...), "-bundle", good), "no files"},
		"missing config": {append(append([]string(nil), base...), "-key-id", "k"), "absent.json"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runCrossCloudConfirmCmd(tc.args)
			require.ErrorContains(t, err, tc.want)
		})
	}
}
