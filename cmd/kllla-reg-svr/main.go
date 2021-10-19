package main

import "github.com/8run0/kllla/internal/server"

func main() {
	regSvr := server.NewRegistration()
	regSvr.ListenAndServe()
}
