package negroniJWT

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/docker/libtrust"
	"github.com/gorilla/context"
	"math/big"
	"net/http"
	"strings"
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
	pubKeyId          string
	privKey           *rsa.PrivateKey
	failRequest       bool
)

func Init(alwaysFailRequest bool) {
	failRequest = alwaysFailRequest
	once.Do(generateKeys)
}

func generateKeys() {
	var err error
	privKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	privKeyPEMEncoded = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
	pubANS1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		panic(err)
	}
	pubKeyPEMEncoded = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubANS1,
	})
	libTrustPubKey, err := libtrust.UnmarshalPublicKeyPEM(pubKeyPEMEncoded)
	if err != nil {
		panic(err)
	}
	pubKeyId = libTrustPubKey.KeyID()
}

func Bundle() (p []byte, err error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore:    time.Unix(1000, 0),
		NotAfter:     time.Unix(100000, 0),
		SubjectKeyId: []byte(pubKeyId),

		BasicConstraintsValid: true,
		IsCA: false,
	}
	out, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(nil)
	if err = pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: out,
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func getClaims(token string) (claims map[string]interface{}, err error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(pubKeyPEMEncoded)
	})
	if err != nil {
		return nil, err
	}
	if parsedToken.Valid {
		return parsedToken.Claims.(jwt.MapClaims), nil
	}
	return nil, errors.New("Token is invalid")
}

// Middleware the main middleware function. Use with negroni.HandlerFunc to apply middleware like so :
// n := negroni.Classic()
// n.Use(negroni.HandlerFunc(negroniJWT.Middleware))
func Middleware(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	var authToken string = strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
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
	t.Header["typ"] = "JWT"
	t.Header["alg"] = "RS256"
	t.Header["kid"] = pubKeyId
	claims["exp"] = expiration.Unix()
	t.Claims = jwt.MapClaims(claims)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyPEMEncoded)
	if err != nil {
		return "", err
	}
	return t.SignedString(privKey)
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
