package main

import (
	"os"

	"zenith-signer/internal/app"
)

func main() {
	app.RunWithTemplates(os.DirFS("."))
}
