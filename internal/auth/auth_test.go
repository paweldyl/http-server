package auth

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "mypassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("HashPassword failed: %v", err)
	}
	if hash == password {
		t.Error("Hash should not be equal to password")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password1 := "mypassword123"
	hashedPassword1, err := HashPassword(password1)
	if err != nil {
		t.Errorf("something went wrong while hashing password, err: %v", err)
	}
	password2 := "differetpass"
	hashedPassword2, err := HashPassword(password2)
	if err != nil {
		t.Errorf("something went wrong while hashing password, err: %v", err)
	}

	correctHashPassedErr := CheckPasswordHash(password1, hashedPassword1)
	if correctHashPassedErr != nil {
		t.Errorf("error returned even tho same hash is passed. err: %v", correctHashPassedErr)
	}
	differentHashErr := CheckPasswordHash(password1, hashedPassword2)
	if differentHashErr == nil {
		t.Errorf("checkPasswordHash returned nil for incorrect hash")
	}
}

func TestMakeJWT(t *testing.T) {
	userid := uuid.New()
	secret := "backendSecret"
	_, err := MakeJWT(userid, secret)
	if err != nil {
		t.Errorf("error while creating token: %v", err)
	}
}

func TestValidateJWT(t *testing.T) {
	userid := uuid.New()
	secret := "backendSecret"
	badSecret := "badSecret"
	tokenString, err := MakeJWT(userid, secret)
	if err != nil {
		t.Errorf("error while creating token: %v", err)
	}
	_, corrDataErr := ValidateJWT(tokenString, secret)
	if corrDataErr != nil {
		t.Errorf("error while checking correct token: %v", corrDataErr)
	}

	_, badSecretErr := ValidateJWT(tokenString, badSecret)
	if badSecretErr == nil {
		t.Errorf("no error while giving bad secret: %v", badSecretErr)
	}
}

func TestGetBearerToken(t *testing.T) {
	headers := http.Header{}

	_, err := GetBearerToken(headers)
	if err == nil {
		t.Errorf("Expected error with empty headers")
	}

	headers.Add("Authorization", "Bearer abc123")
	token, err := GetBearerToken(headers)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if token != "abc123" {
		t.Errorf("Expected token abc123, got %v", token)
	}
}
