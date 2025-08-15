package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	passwords := map[string]string{
		"alice": "password123",
		"bob":   "secret456",
		"carol": "mypass789",
	}

	for user, password := range passwords {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %s\n", user, string(hash))
	}
}