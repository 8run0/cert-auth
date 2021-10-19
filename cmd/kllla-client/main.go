package main

import "github.com/8run0/kllla/internal/client"

func main() {
	client.GetRegistrationCertificate()
	client.RegisterNewName("bruno")
	client.NewTokenForKey("bruno")
}
