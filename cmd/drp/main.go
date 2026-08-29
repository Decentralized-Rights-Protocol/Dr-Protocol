package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("drp commands: version")
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("DRP Protocol %s\n", protocol.Version)
	default:
		fmt.Printf("unknown command %q\n", os.Args[1])
		flag.CommandLine.SetOutput(os.Stdout)
	}
}
