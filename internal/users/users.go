package users

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type UserStore struct {
	Users []User `json:"users"`
}

func LoadUsers(filename string) (*UserStore, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read users file: %w", err)
	}

	var store UserStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse users file: %w", err)
	}

	return &store, nil
}

func (us *UserStore) Authenticate(username, password string) (*User, error) {
	for _, user := range us.Users {
		if user.Username == username {
			if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
				return nil, fmt.Errorf("invalid credentials")
			}
			return &user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (us *UserStore) GetUser(username string) (*User, error) {
	for _, user := range us.Users {
		if user.Username == username {
			return &user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}