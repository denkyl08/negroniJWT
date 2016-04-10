package negroniJWT

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

const (
	user = "Bob"
)

func startTestServer(failRequest bool, t *testing.T, loginFunc, validToken, invalidToken func(http.ResponseWriter, *http.Request)) {
	Init(failRequest)
	n := negroni.Classic()
	n.Use(negroni.HandlerFunc(Middleware))
	m := mux.NewRouter()
	m.HandleFunc("/login", loginFunc).Methods("POST")
	m.HandleFunc("/validToken", validToken).Methods("GET")
	m.HandleFunc("/invalidToken", invalidToken).Methods("GET")
	n.UseHandler(m)
	go http.ListenAndServe(":3333", n)
}

func TestBundle(t *testing.T) {
	Init(false)
	p, err := Bundle()
	if err != nil {
		t.Errorf("unable to create cert: %s", err)
	}

	pemBlock, p := pem.Decode(p)
	if pemBlock == nil {
		t.Fatalf("unable to decode certbundle")
	}
	_, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("unable to parse token auth root certificate: %s", err)
	}
}

func TestValidClaims(t *testing.T) {
	loginFunc := func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, []byte(user)) {
			return
		}
		claims := make(map[string]interface{})
		claims["Username"] = user
		// generate JWT token with encrypted claims
		token, err := GenerateToken(claims, time.Now().Add(1*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(token))
	}

	validToken := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := Get(r)
		if !ok {
			t.Fatal("Claims retrieval shows not ok.")
			w.WriteHeader(401)
			return
		}
		username, ok := claims["Username"]
		if !ok {
			t.Fatal("Claims do not contain a key called Username")
			w.WriteHeader(401)
			return
		}

		usernameString, ok := username.(string)
		if !ok {
			t.Fatal("Claim username is not a string")
			w.WriteHeader(401)
			return
		}

		if usernameString != user {
			t.Fatal("Claim username is not a string 'Bob'")
			w.WriteHeader(401)
			return
		}

		w.Write([]byte("Hello Bob"))
	}

	invalidToken := func(w http.ResponseWriter, r *http.Request) {
		_, ok := Get(r)
		if ok {
			t.Fatal("expected ok to be falsy")
		} else {
			w.WriteHeader(401)
			w.Write([]byte("Permission Denied"))
			return
		}

		w.Write([]byte("Hello Bob"))
	}

	startTestServer(false, t, loginFunc, validToken, invalidToken)
	client := &http.Client{}

	// retrieve token
	resp, err := http.Post("http://localhost:3333/login", "text/plain", bytes.NewBufferString("Bob"))
	if err != nil {
		t.Fatal("Error logging in, ", err.Error())
	}
	token, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("Error Reading login response, ", err.Error())
	}

	// test case where token is valid
	req, err := http.NewRequest("GET", "http://localhost:3333/validToken", nil)
	if err != nil {
		t.Fatal("Error generating request, ", err.Error())
	}
	req.Header.Add("Authorization", string(token))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal("Error doing GET to /validToken, ", err.Error())
	}
	if resp.StatusCode != 200 {
		t.Fatal("Expected status code of 200, got ", resp.Status)
	}
	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("Error Reading /validToken response, ", err.Error())
	}
	if !bytes.Equal(response, []byte("Hello Bob")) {
		t.Fatal("Expected 'Hello Bob' response, got ", string(response))
	}

	// test case where token is invalid
	req, err = http.NewRequest("GET", "http://localhost:3333/invalidToken", nil)
	if err != nil {
		t.Fatal("Error generating request, ", err.Error())
	}
	req.Header.Add("Authorization", string(token[1:]))
	resp, err = client.Do(req)
	if resp.StatusCode != 401 {
		t.Fatal("Expected error code of 401, got ", resp.Status)
	}

	// test case where token is expired
	time.Sleep(2 * time.Second)
	req, err = http.NewRequest("GET", "http://localhost:3333/invalidToken", nil)
	if err != nil {
		t.Fatal("Error generating request, ", err.Error())
	}
	req.Header.Add("Authorization", string(token))
	resp, err = client.Do(req)
	if resp.StatusCode != 401 {
		t.Fatal("Expected error code of 401, got ", resp.Status)
	}
}
