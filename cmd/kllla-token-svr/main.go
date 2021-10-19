package main

import "github.com/8run0/kllla/internal/server"

func main() {
	tokenSvr := server.NewTokenServer()
	tokenSvr.ListenAndServe()
}
