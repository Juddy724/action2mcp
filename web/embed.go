// Package web embeds the console assets. Paths are app.js, index.html, and
// style.css — the same paths the server used after fs.Sub of the old web/ tree.
package web

import (
	"embed"
	"io/fs"
)

//go:embed app.js index.html style.css
var files embed.FS

// FS is the console file tree.
var FS fs.FS = files
