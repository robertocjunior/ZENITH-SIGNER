package main

import (
	"embed"

	"zenith-signer/internal/app"
)

//go:embed templates/*
var templateFS embed.FS

func main() {
	app.RunWithTemplates(templateFS)
}
