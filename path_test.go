package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathWithinRootForMissingChild(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "missing")
	if !pathWithinRoot(child, root) {
		rootResolved, rootErr := filepath.EvalSymlinks(root)
		parentResolved, parentErr := filepath.EvalSymlinks(filepath.Dir(child))
		t.Fatalf("missing child rejected: root=%q resolved=%q err=%v parent=%q resolved=%q err=%v cwd=%q",
			root, rootResolved, rootErr, filepath.Dir(child), parentResolved, parentErr, mustWorkingDir())
	}
}

func mustWorkingDir() string {
	wd, _ := os.Getwd()
	return wd
}
