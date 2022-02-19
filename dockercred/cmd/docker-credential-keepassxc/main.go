package main

import (
	"log"

	"github.com/docker/docker-credential-helpers/credentials"

	"github.com/xakep666/gkpxc/dockercred"
)

func main() {
	kr, err := dockercred.SetupKeyring("docker-credential-keepassxc")
	if err != nil {
		log.Fatalln("Keyring for private key open failed:", err)
	}

	credentials.Serve(&dockercred.KeepassXCHelper{Keyring: kr})
}
