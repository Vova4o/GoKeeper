package passwordhash

import (
    "testing"
)

func TestHashPassword(t *testing.T) {
    password := "mysecretpassword"
    hashedPassword, err := HashPassword(password)
    if err != nil {
        t.Fatalf("HashPassword returned an error: %v", err)
    }

    if hashedPassword == "" {
        t.Fatal("Hashed password is empty")
    }
}

func TestCheckPasswordHash(t *testing.T) {
    password := "mysecretpassword"
    hashedPassword, err := HashPassword(password)
    if err != nil {
        t.Fatalf("HashPassword returned an error: %v", err)
    }

    if !CheckPasswordHash(password, hashedPassword) {
        t.Fatal("CheckPasswordHash returned false, expected true")
    }

    wrongPassword := "wrongpassword"
    if CheckPasswordHash(wrongPassword, hashedPassword) {
        t.Fatal("CheckPasswordHash returned true for wrong password, expected false")
    }
}