package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	byteHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}

	return string(byteHash), nil
}

func CheckPasswordHash(password string, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err := token.SignedString([]byte(tokenSecret))
	return signedString, err
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	strID, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}
	userId, err := uuid.Parse(strID)
	return userId, err
}

func GetBearerToken(headers http.Header) (string, error) {

	auth := headers.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return "", errors.New("no bearer in auth")
	}
	tokenWithoutBearer := strings.Replace(auth, "Bearer", "", 1)
	trimmedToken := strings.TrimSpace(tokenWithoutBearer)
	return trimmedToken, nil
}

func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func GetAPIKey(headers http.Header) (string, error) {
	auth := headers.Get("Authorization")
	if !strings.HasPrefix(strings.TrimSpace(strings.ToLower(auth)), "apikey ") {
		return "", errors.New("no api key in auth")
	}
	tokenWithoutBearer := strings.Replace(auth, "ApiKey", "", 1)
	trimmedToken := strings.TrimSpace(tokenWithoutBearer)
	return trimmedToken, nil
}
