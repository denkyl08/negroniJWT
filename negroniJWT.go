package negroniJWT

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/docker/libtrust"
	"golang.org/x/net/context"
)

const (
	context_key = "jwt"
)

var (
	once              sync.Once
	privKeyPEMEncoded []byte
	pubKeyPEMEncoded  []byte
	privateKeyPath    string
	publicKeyPath     string
	pubKeyId          string
	privKey           *rsa.PrivateKey
	failRequest       bool
)

func Init(alwaysFailRequest bool, privKeyPath, pubKeyPath string) {
	privateKeyPath = privKeyPath
	publicKeyPath = pubKeyPath
	_, privKeyError := os.Stat(privateKeyPath)
	_, pubKeyError := os.Stat(publicKeyPath)
	failRequest = alwaysFailRequest
	if os.IsNotExist(privKeyError) || os.IsNotExist(pubKeyError) {
		fmt.Println("[negroniJWT] No Keys found, generating RS256 private and public keys")
		once.Do(generateKeys)
	} else {
		fmt.Println("[negroniJWT] Loading keys")
		once.Do(loadKeys)
	}
}

func writePEMToFile(filename string, b *pem.Block) {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(f, b)
	if err != nil {
		panic(err)
	}
}

func loadKeys() {
	privBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		panic(err)
	}

	pubBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		panic(err)
	}

	privKeyPEMEncodedBytes, _ := pem.Decode(privBytes)
	privKeyPEMEncoded = pem.EncodeToMemory(privKeyPEMEncodedBytes)
	pubKeyPEMEncodedBytes, _ := pem.Decode(pubBytes)
	pubKeyPEMEncoded = pem.EncodeToMemory(pubKeyPEMEncodedBytes)
}

func generateKeys() {
	var err error
	privKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	privateKeyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	writePEMToFile(privateKeyPath, privateKeyPEMBlock)
	privKeyPEMEncoded = pem.EncodeToMemory(privateKeyPEMBlock)
	pubANS1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		panic(err)
	}
	publicKeyPEMBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubANS1,
	}
	writePEMToFile(publicKeyPath, publicKeyPEMBlock)
	pubKeyPEMEncoded = pem.EncodeToMemory(publicKeyPEMBlock)
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

	ctx, err := newContextWithClaims(r)
	if err == nil || failRequest == false {
		if err == nil {
			next(rw, r.WithContext(ctx))
		} else {
			next(rw, r)
		}
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
	claims, castOk := r.Context().Value(context_key).(map[string]interface{})
	return claims, castOk
}

func newContextWithClaims(r *http.Request) (context.Context, error) {
	ctx := r.Context()

	var authToken string = strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
	if authToken == "" {
		authToken = r.FormValue("auth_code")
	}
	claims, err := getClaims(authToken)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, context_key, claims), err
}
