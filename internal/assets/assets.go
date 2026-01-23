package assets

import (
	"embed"
)

//go:embed images
var Images embed.FS

//go:embed authenticate
var Fragments embed.FS
