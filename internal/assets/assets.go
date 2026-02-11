package assets

import (
	"embed"
)

//go:embed static
var Static embed.FS

//go:embed authenticate
var Fragments embed.FS

//go:embed email
var Email embed.FS
