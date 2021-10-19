package main

import (
	"github.com/8run0/kllla/internal/client"
	"github.com/8run0/kllla/internal/server"
)

func main() {
	client.RegisterNewName("token-svr")
	tokenSvr := server.NewTokenServer()
	tokenSvr.ListenAndServe()
}
