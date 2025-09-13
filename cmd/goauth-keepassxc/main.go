package main

import (
	"context"
	"log"
	"os"

	"github.com/xakep666/gkpxc/dockercred"
	"github.com/xakep666/gkpxc/goauthcred"
)

func main() {
	log.SetOutput(os.Stderr) // because stdout is used for responses

	kr, err := dockercred.SetupKeyring("goauth-keepassxc")
	if err != nil {
		log.Fatalln("Keyring for private key open failed:", err)
	}

	err = goauthcred.Serve(context.Background(),
		goauthcred.ServeParams{
			Input:   os.Stdin,
			Output:  os.Stdout,
			Keyring: kr,
			Args:    os.Args,
		},
	)
	if err != nil {
		log.Fatalln("Serve failed:", err)
	}
}
