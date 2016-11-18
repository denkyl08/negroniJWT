negroniJWT (Updated)
====================

This is an updated version of negroniJWT compatible with go1.7.3+. This uses golang's native [context](https://golang.org/pkg/context) instead of gorilla/context which was being used before in [negroniJWT](https://godoc.org/github.com/denkyl08/negroniJWT)

JSON Web Token Auth middleware for [Negroni](https://github.com/codegangsta/negroni).

GoDoc can be found [here](https://godoc.org/github.com/yadvendar/negroniJWT).

All credits to the original author [here](https://godoc.org/github.com/denkyl08/negroniJWT)

##About
------------

This is some simple middleware for handling JSON Web Token authorization. Token encoding and decoding is done using dgrijalva's [jwt-go](https://github.com/dgrijalva/jwt-go). Claims from request are retrieved using negroniJWT.Get(r) and uses golang's native [context](https://golang.org/pkg/context) so it's safe for concurrent use.


## Initialization
---------------------
```go
import(
    "github.com/codegangsta/negroni"
    "github.com/yadvendar/negroniJWT"
)

func main() {
    
    // false means request without a valid token always fails
    // true means that you must check _, ok := negroniJWT.Get(request)
    // "jwt" is the private key filename and "jwt.pub" is the public key filename
	negroniJWT.Init(false, "jwt", "jwt.pub")
    
    n := negroni.Classic()
    n.Use(negroni.HandlerFunc(negroniJWT.Middleware))
    
}
```

##In Login Controller
---------------------
```go
    
    err = user.Authenticate()
    if err != nil {
        http.Error(w, err.Error(), 401)
        return
    }
    claims := make(map[string]interface{})
    claims["Username"] = user.Username

    // generate JWT token with encrypted claims
    token, err := negroniJWT.GenerateToken(claims, time.Now().Add(30*time.Minute))
    err = utils.WriteJson(struct {
        Token string
    }{token}, w)
```

##Retrieve Token claims from request
---------------------
```go
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := negroniJWT.Get(r); if !ok {
        http.Error(w, "Error: auth failure", 401)
        return
    }
    ...
}
```
