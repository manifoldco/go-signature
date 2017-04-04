# go-signature

Verify signed HTTP requests from Manifold

[Code of Conduct](./.github/CONDUCT.md) |
[Contribution Guidelines](./.github/CONTRIBUTING.md)

[![GitHub release](https://img.shields.io/github/tag/manifoldco/go-signature.svg?label=latest)](https://github.com/manifoldco/go-signature/releases)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/manifoldco/go-signature)
[![Travis](https://img.shields.io/travis/manifoldco/go-signature/master.svg)](https://travis-ci.org/manifoldco/go-signature)
[![Go Report Card](https://goreportcard.com/badge/github.com/manifoldco/go-signature)](https://goreportcard.com/report/github.com/manifoldco/go-signature)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](./LICENSE.md)

## Usage

```go
import "github.com/manifoldco/go-signature"
```

signature includes middleware that conforms to the http.Handler interface,
wrapping another http.Handler. If the request is invalid, the middleware will
respond directly, instead of calling your handler.

Using the included middleware:

```go
verifier := signature.NewVerifier(signature.ManifoldKey)
http.Handle("/v1", verifier.WrapFunc(func (rw http.ResponseWriter, r *http.Request) {
	// your code goes here.
}))
```

Verifying a request manually:

```go
body, err := ioutil.ReadAll(req.Body)
buf := bytes.NewBuffer(body)

verifiier := signature.NewVerifier(signature.ManifoldKey)
if err := verifiier.Verify(req, buf); err != nil {
	// return an error...
}

// continue using the request and body
```

Manual verification may be useful if you are not using a standard net/http
setup.
