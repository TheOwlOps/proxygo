// 9router-cli is the Go port of the npm `9router` launcher
// (~/workspace/9router/cli). It starts/stops/inspects the Go 9Router
// server binary, opens the dashboard, and resets the dashboard
// password — see internal/cli for the JS→Go mapping and adaptations.
package main

import (
	"os"

	"9router-go/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
