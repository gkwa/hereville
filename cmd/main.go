package main

import (
	"os"

	"github.com/taylormonacelli/hereville"
)

func main() {
	code := hereville.Execute()
	os.Exit(code)
}
