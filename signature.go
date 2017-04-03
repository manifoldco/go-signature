/*
Package signature provides validation of signed HTTP requests from Manifold.

signature includes middleware that conforms to the http.Handler interface,
wrapping another http.Handler. If the request is invalid, the middleware will
respond directly, instead of calling your handler.

Using the included middleware:

	verifier := signature.NewVerifier(signature.ManifoldKey)
	http.Handle("/v1", verifier.WrapFunc(func (rw http.ResponseWriter, r *http.Request) {
		// your code goes here.
	}))

Verifying a request manually:

	body, err := ioutil.ReadAll(req.Body)
	buf := bytes.NewBuffer(body)

	verifiier := signature.NewVerifier(signature.ManifoldKey)
	if err := verifiier.Verify(req, buf); err != nil {
		// return an error...
	}

	// continue using the request and body

Manual verification may be useful if you are not using a standard net/http
setup.
*/
package signature

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/manifoldco/go-base64"
)

// ManifoldKey is Manifold's public master signing key, base64 encoded.
const ManifoldKey = "PtISNzqQmQPBxNlUw3CdxsWczXbIwyExxlkRqZ7E690"

// PermittedTimeSkew is the time skew allowed on requests, on either side.
const PermittedTimeSkew = 5 * time.Minute

// ErrInvalidPublicKey is returned from NewVerifier when the provided public key
// is not valid
var ErrInvalidPublicKey = errors.New("The provided base64 public key is not valid")

// Error represents an unsuccessful HTTP error response.
type Error struct {
	Code    int    `json:"-"` // The HTTP status code.
	Message string `json:"message"`
}

// Error implements the standard error interface for signature Errors.
func (e *Error) Error() string {
	return e.Message
}

// Respond writes the Error to the provided ResponseWriter as JSON, in the
// format expected by Manifold for errors.
func (e *Error) Respond(rw http.ResponseWriter) {
	b, err := json.Marshal(e)
	if err != nil {
		panic("Error while marshaling error response!")
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Content-Length", strconv.Itoa(len(b)))
	rw.WriteHeader(e.Code)

	rw.Write(b)
}

// Signature represents a Signature of an HTTP request
type Signature struct {
	Value       *base64.Value
	PublicKey   *base64.Value
	Endorsement *base64.Value
}

// String returns the string representatino of a Signature
func (s *Signature) String() string {
	return fmt.Sprintf("%s %s %s", s.Value, s.PublicKey, s.Endorsement)
}

// Validate returns an error if the given byte slice does not match this
// signature
func (s *Signature) Validate(masterPubKey ed25519.PublicKey, b []byte) error {
	if !ed25519.Verify(masterPubKey, []byte(*s.PublicKey), []byte(*s.Endorsement)) {
		return &Error{Code: 401, Message: "Request Public Key was not endorsed by Manifold"}
	}

	livePubKey := ed25519.PublicKey([]byte(*s.PublicKey))
	if !ed25519.Verify(livePubKey, b, []byte(*s.Value)) {
		return &Error{Code: 401, Message: "Request was not signed by included Public Key"}
	}

	return nil
}

// ParseSignature parses the given string and returns a Signature struct
func ParseSignature(value string) (*Signature, error) {
	sigerr := &Error{Code: 400, Message: "Could not parse Signature chain"}
	parts := strings.Split(value, " ")
	if len(parts) != 3 {
		return nil, sigerr
	}

	v, err := base64.NewFromString(parts[0])
	if err != nil {
		return nil, err
	}

	k, err := base64.NewFromString(parts[1])
	if err != nil {
		return nil, err
	}

	e, err := base64.NewFromString(parts[2])
	if err != nil {
		return nil, err
	}

	return &Signature{
		Value:       v,
		PublicKey:   k,
		Endorsement: e,
	}, nil
}

// Canonize builds the canonical representation of the given request, for use in
// verifying the Manifold request signature applied to it.
// The request body is not read directly, instead, body is read, allowing
// buffering or duplication of the body to be handled outside of this func.
func Canonize(req *http.Request, body io.Reader) ([]byte, error) {
	var msg bytes.Buffer
	// Begin writing the target of the signature.
	// start with the request target:
	//     lower(METHOD) <space > PATH <'?'> canonical(QUERY) <newline>
	// where canonical(QUERY) is the query params, lexicographically sorted
	// in ascending order (including param name, = sign, and value),
	// and delimited by an '&'.
	// If no query params are set, the '?' is omitted.
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	msg.WriteString(strings.ToLower(method))
	msg.WriteRune(' ')
	msg.WriteString(req.URL.EscapedPath())

	if len(req.URL.RawQuery) > 0 {
		msg.WriteRune('?')

		parts := strings.Split(req.URL.RawQuery, "&")
		sort.Strings(parts)
		msg.WriteString(strings.Join(parts, "&"))
	}

	msg.WriteRune('\n')

	// Next, add all headers. These are the headers listed in the
	// X-Signed-Headers  header, in the order they are listed, followed by
	// the X-Signed-Headers header itself.
	//
	// Headers are written in the form:
	//     lower(NAME) <colon> <space> VALUES <newline>
	// Values have all optional whitespace removed.
	// If the header occurs multiple times on the request, the values are
	// included delimited by `, `, in the order they appear on the request.
	//
	// The X-Signed-Headers header includes the list of all signed headers,
	// lowercased, and delimited by a space. Only one occurrence of
	// X-Signed-Headers should exist on a request. If more than one exists,
	// The first is used.
	headers := strings.Split(req.Header.Get("x-signed-headers"), " ")
	headers = append(headers, "x-signed-headers")
	for _, h := range headers {
		ch := http.CanonicalHeaderKey(h)

		rhvs := req.Header[ch]
		if ch == "Host" {
			host := req.Host
			if host == "" {
				host = req.URL.Host
			}

			rhvs = []string{host}
		}

		msg.WriteString(strings.ToLower(h))
		msg.WriteString(": ")

		var hvs []string
		for _, hv := range rhvs {
			hvs = append(hvs, strings.TrimSpace(hv))
		}
		msg.WriteString(strings.Join(hvs, ", "))
		msg.WriteRune('\n')
	}

	// Finally, include the contents of the request body, if it is non-zero in
	// length.
	_, err := io.Copy(&msg, body)
	return msg.Bytes(), err
}

// Verifier verifies that HTTP requests are signed by Manifold
type Verifier struct {
	pk ed25519.PublicKey
}

// NewVerifier returns a new Verifier, configured with the provided raw base64
// URL encoded public key.
//
// It returns an error if the given public key is not a valid base64 URL encoded
// value, or if it is not a valid Ed25519 public key.
func NewVerifier(publicKey string) (*Verifier, error) {
	// be lenient of different base64 formats
	spk := strings.Replace(publicKey, "+", "-", -1)
	spk = strings.Replace(spk, "/", "_", -1)
	spk = strings.TrimRight(spk, "=")

	pkv, err := base64.NewFromString(spk)
	if err != nil || len(*pkv) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}

	return &Verifier{pk: ed25519.PublicKey((*pkv)[:ed25519.PublicKeySize])}, nil
}

// timeSince is replaced during testing
var timeSince = func(rt time.Time) time.Duration {
	return time.Since(rt)
}

// Verify verifies that the given request is signed by Manifold. It returns an
// error if the signature is invalid.
// The request body is not read directly, instead, body is read, allowing
// buffering or duplication of the body to be handled outside of this method.
func (v *Verifier) Verify(req *http.Request, body io.Reader) error {
	sigHeader := req.Header.Get("X-Signature")
	if sigHeader == "" {
		return &Error{Code: 400, Message: "Missing X-Signature header"}
	}

	sig, err := ParseSignature(sigHeader)
	if err != nil {
		return &Error{Code: 400, Message: "Could not parse X-Signature header"}
	}

	headerList := req.Header.Get("X-Signed-Headers")
	if headerList == "" {
		return &Error{Code: 400, Message: "Missing X-Signed-Headers header"}
	}

	rt, err := time.Parse(time.RFC3339, req.Header.Get("Date"))
	if err != nil {
		return &Error{Code: 400, Message: "Unable to read request date"}
	}

	delta := timeSince(rt)
	if delta < 0 {
		delta = -delta
	}

	if delta > PermittedTimeSkew {
		return &Error{Code: 400, Message: "Request time skew is too great"}
	}

	b, err := Canonize(req, body)
	if err != nil {
		return &Error{Code: 400, Message: "Unable to read request body"}
	}

	return sig.Validate(v.pk, b)
}

// Wrap wraps the provided Handler, returning a new Handler that will verify
// the request before passing it through to the Handler. If the request is
// invalid,  Wrap will respond appropriately through the RequestWriter
func (v *Verifier) Wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		v.Negroni().ServeHTTP(rw, req, handler.ServeHTTP)
	})
}

// WrapFunc is the HandlerFunc version of Wrap.
func (v *Verifier) WrapFunc(handler http.HandlerFunc) http.Handler {
	return v.Wrap(http.HandlerFunc(handler))
}

// Middleware implements the Negroni middleware interface for funcs
type Middleware func(http.ResponseWriter, *http.Request, http.HandlerFunc)

func (m Middleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	m(rw, r, next)
}

// Negroni returns a Negroni compatible middleware for verifying requests.
// This middleware behaves like Wrap; it will not pass through to the next
// Handler in the chain if the request does not have a valid signature.
func (v *Verifier) Negroni() Middleware {
	return Middleware(func(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		b := &bytes.Buffer{}
		_, err := b.ReadFrom(req.Body)
		if err != nil {
			e := &Error{400, "Could not ready body from request"}
			e.Respond(rw)
			return
		}

		defer req.Body.Close()

		req.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
		err = v.Verify(req, b)
		if e, ok := err.(*Error); ok {
			e.Respond(rw)
			return
		}

		if err != nil {
			e := &Error{401, "Could not validate authenticity of the request"}
			e.Respond(rw)
			return
		}

		next(rw, req)
	})
}
