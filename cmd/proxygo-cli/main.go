// proxygo-cli is the Go port of the upstream npm launcher
// (cli/ in the upstream source tree). It starts/stops/inspects the
// Go ProxyGo server binary, opens the dashboard, and resets the
// dashboard password — see internal/cli for the JS→Go mapping and
// adaptations.
package main

import (
	"os"

	"proxygo/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
