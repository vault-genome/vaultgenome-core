// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The error prints its cause after its message ("category[code]: message:
// cause"). A message that carries the cause as well — formatted into it,
// through its Error(), or in a variable built from it beforehand — says
// everything twice. Every caller in the module is held to leaving the
// cause to the error.

const errorsImportPath = "github.com/vault-genome/vaultgenome-core/internal/shared/errors"

var constructors = map[string]bool{"Structural": true, "Authority": true, "Operational": true, "Integrity": true, "Incident": true}

// causePrintedTwice names each call of a constructor in f whose message
// carries the cause the error prints after it anyway.
func causePrintedTwice(fset *token.FileSet, f *ast.File) []string {
	alias := ""
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == errorsImportPath {
			alias = "errors"
			if imp.Name != nil {
				alias = imp.Name.Name
			}
		}
	}
	if alias == "" || alias == "_" || alias == "." {
		return nil
	}
	var found []string
	reported := map[token.Pos]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch fn := n.(type) {
		case *ast.FuncDecl:
			body = fn.Body
		case *ast.FuncLit:
			body = fn.Body
		}
		if body == nil {
			return true
		}
		// What each variable of the function is built from, so that a
		// message assembled before the call is read too.
		built := map[string][]ast.Expr{}
		ast.Inspect(body, func(m ast.Node) bool {
			if as, ok := m.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
				for i, l := range as.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						built[id.Name] = append(built[id.Name], as.Rhs[i])
					}
				}
			}
			return true
		})
		ast.Inspect(body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok || len(call.Args) != 3 || reported[call.Pos()] {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !constructors[sel.Sel.Name] {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != alias {
				return true
			}
			cause := types.ExprString(call.Args[2])
			if cause == "nil" {
				return true
			}
			messages := []ast.Expr{call.Args[1]}
			if id, ok := call.Args[1].(*ast.Ident); ok {
				messages = append(messages, built[id.Name]...)
			}
			for _, msg := range messages {
				if mentions(msg, cause) {
					reported[call.Pos()] = true
					found = append(found, fmt.Sprintf("%s: %s.%s: the message carries %s, which the error prints after it",
						fset.Position(call.Pos()), alias, sel.Sel.Name, cause))
					break
				}
			}
			return true
		})
		// The body's nested function literals were read with it.
		return false
	})
	return found
}

func mentions(e ast.Expr, cause string) bool {
	hit := false
	ast.Inspect(e, func(n ast.Node) bool {
		if x, ok := n.(ast.Expr); ok && types.ExprString(x) == cause {
			hit = true
		}
		return !hit
	})
	return hit
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}

// TestNoCallerPrintsTheCauseTwice walks every non-test Go file of the
// module (nested modules are their own trees, and cannot import this
// package).
func TestNoCallerPrintsTheCauseTwice(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	fset := token.NewFileSet()
	var found []string
	files := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor", "node_modules":
				return filepath.SkipDir
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		for _, s := range causePrintedTwice(fset, f) {
			rel, _ := filepath.Rel(root, s)
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 300 {
		t.Fatalf("read %d Go files; the walk missed the tree", files)
	}
	for _, s := range found {
		t.Error(s)
	}
}

// TestCausePrintedTwiceSeesEveryForm holds the check to each form it
// exists to catch, so that it cannot go blind unnoticed.
func TestCausePrintedTwiceSeesEveryForm(t *testing.T) {
	t.Parallel()
	const src = `package p

import (
	"fmt"

	se "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

func bad(err error, family string, b struct{ err error }) []error {
	msg := fmt.Sprintf("built: %v", err)
	msg += ": with a tail"
	return []error{
		se.Integrity("c", fmt.Sprintf("formatted: %v", err), err),
		se.Structural("c", fmt.Sprintf("through Error: %s", err.Error()), err),
		se.Operational("c", family+": joined: "+err.Error(), err),
		se.Authority("c", err.Error(), err),
		se.Incident("c", msg, err),
		se.Integrity("c", fmt.Sprintf("a field: %v", b.err), b.err),
	}
}

func good(err error, family string) []error {
	msg := fmt.Sprintf("context %d", 3)
	return []error{
		se.Integrity("c", "the context", err),
		se.Structural("c", fmt.Sprintf("%s: the context %d", family, 3), err),
		se.Operational("c", msg, err),
		se.Authority("c", fmt.Sprintf("no cause attached: %v", err), nil),
	}
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	found := causePrintedTwice(fset, f)
	if len(found) != 6 {
		t.Fatalf("found %d of the 6 forms: %q", len(found), found)
	}
	for _, s := range found {
		if line, _ := strconv.Atoi(strings.Split(s, ":")[1]); line < 13 || line > 18 {
			t.Errorf("a finding outside the bad function: %s", s)
		}
	}
}
