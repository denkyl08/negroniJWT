package negroniJWT

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"net/http"
	"sync"
	"time"
)

const (
	context_key = "jwt"
)

var (
	once              sync.Once
	privKeyPEMEncoded []byte
	pubKeyPEMEncoded  []byte
	failRequest       bool
)

func Init(failRequest bool) {
	failRequest = failRequest
	once.Do(generateKeys)
}

func generateKeys() {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	privKeyPEMEncoded = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE context_key",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
	pubANS1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		panic(err)
	}
	pubKeyPEMEncoded = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC context_key",
		Bytes: pubANS1,
	})
}

func getClaims(token string) (claims map[string]interface{}, err error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return pubKeyPEMEncoded, nil
	})
	if err != nil {
		return nil, err
	}
	if parsedToken.Valid {
		return parsedToken.Claims, nil
	}
	return nil, errors.New("Token is invalid")
}

// Middleware the main middleware function. Use with negroni.HandlerFunc to apply middleware like so :
// n := negroni.Classic()
// n.Use(negroni.HandlerFunc(negroniJWT.Middleware))
func Middleware(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	var authToken string = r.Header.Get("Authorization")
	claims, err := getClaims(authToken)
	if err == nil || failRequest == false {
		if err == nil {
			context.Set(r, context_key, claims)
		}
		next(rw, r)
	} else {
		rw.WriteHeader(401)
	}
}

// GenerateToken generates the base64 encoded JSON Web Token including the claims map provided and and expiration time.
func GenerateToken(claims map[string]interface{}, expiration time.Time) (s string, err error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	t.Claims = claims
	t.Claims["exp"] = expiration.Unix()
	return t.SignedString(privKeyPEMEncoded)
}

// Get attempts to retrieve the claims map for request. If there was an error decoding the JSON Web Token.
func Get(r *http.Request) (claims map[string]interface{}, ok bool) {
	c, ok := context.GetOk(r, context_key)
	if !ok {
		return claims, ok
	}
	claims, castOk := c.(map[string]interface{})
	return claims, castOk
}
