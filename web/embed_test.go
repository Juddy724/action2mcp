package web

import (
	"bytes"
	"io/fs"
	"os"
	"testing"
)

func TestEmbeddedFilesMatchDisk(t *testing.T) {
	names := []string{"app.js", "index.html", "style.css"}
	for _, name := range names {
		got, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Fatalf("embed %s: %v", name, err)
		}
		want, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("disk %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s embed bytes differ from disk (%d vs %d)", name, len(got), len(want))
		}
		if _, err := fs.Stat(FS, "web/"+name); err == nil {
			t.Fatalf("embed path web/%s should not exist; paths stay package-relative", name)
		}
	}
}
