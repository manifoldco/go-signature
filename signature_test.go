package signature

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func init() {
	timeSince = func(rt time.Time) time.Duration {
		return time.Second
	}
}

func ExampleCanonize() {
	body := bytes.NewBufferString("Test body data")
	req, _ := http.NewRequest("PUT", "/v1/resources?foo=bar", body)
	req.Header.Set("X-Signed-Headers", "date")
	req.Header.Set("Date", "2017-03-05T23:53:08Z")
	b, _ := Canonize(req, body)

	fmt.Println()
	fmt.Println(string(b))

	// Output:
	// put /v1/resources?foo=bar
	// date: 2017-03-05T23:53:08Z
	// x-signed-headers: date
	// Test body data
}

func ExampleVerifier_Verify() {
	body := bytes.NewBufferString("{\"id\":\"2686c96868emyj61cgt2ma7vdntg4\",\"plan\":\"low\",\"product\":\"generators\",\"region\":\"aws::us-east-1\",\"user_id\":\"200e7aeg2kf2d6nud8jran3zxnz5j\"}\n")
	req, _ := http.NewRequest("PUT", "https://127.0.0.1:4567/v1/resources/2686c96868emyj61cgt2ma7vdntg4", body)

	req.Host = "127.0.0.1:4567"
	req.Header.Set("Date", "2017-03-05T23:53:08Z")
	req.Header.Set("Content-Length", "143")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signed-Headers", "host date content-type content-length")
	req.Header.Set("X-Signature", "Nb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg")

	// For production usage, use verifier.ManifoldKey
	dummyKey := "PY7wu3q3-adYr9-0ES6CMRixup9OjO5iL7EFDFpolhk"
	verifier, _ := NewVerifier(dummyKey)

	err := verifier.Verify(req, body)
	if err != nil {
		fmt.Println("Signature is not valid:", err)
	} else {
		fmt.Println("Signature is ok!")
	}

	// Output: Signature is ok!
}

func newReq() *http.Request {
	body := bytes.NewBufferString("{\"id\":\"2686c96868emyj61cgt2ma7vdntg4\",\"plan\":\"low\",\"product\":\"generators\",\"region\":\"aws::us-east-1\",\"user_id\":\"200e7aeg2kf2d6nud8jran3zxnz5j\"}\n")
	req, _ := http.NewRequest("PUT", "https://127.0.0.1:4567/v1/resources/2686c96868emyj61cgt2ma7vdntg4", body)

	req.Host = "127.0.0.1:4567"
	req.Header.Set("Date", "2017-03-05T23:53:08Z")
	req.Header.Set("Content-Length", "143")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signed-Headers", "host date content-type content-length")
	req.Header.Set("X-Signature", "Nb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg")

	return req
}

func TestWrap(t *testing.T) {
	dummyKey := "PY7wu3q3-adYr9-0ES6CMRixup9OjO5iL7EFDFpolhk"
	verifier, _ := NewVerifier(dummyKey)

	t.Run("Good signature", func(t *testing.T) {
		req := newReq()

		var called bool

		w := verifier.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called = true
		}))

		rw := httptest.NewRecorder()
		w.ServeHTTP(rw, req)
		if !called {
			t.Error("Body was not called")
		}
	})

	t.Run("Bad signature", func(t *testing.T) {
		req := newReq()
		// signature changed to start with bb instead of Nb
		req.Header.Set("X-Signature", "bb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg")

		var called bool

		w := verifier.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called = true
		}))

		rw := httptest.NewRecorder()
		w.ServeHTTP(rw, req)
		if called {
			t.Error("Body was called")
		}

		if rw.Code != 401 {
			t.Error("Wrong status code returned")
		}

		if rw.Body.String() != `{"message":"Request was not signed by included Public Key"}` {
			t.Error("Bad error message returned")
		}
	})

	t.Run("old request", func(t *testing.T) {
		ots := timeSince
		defer func() { timeSince = ots }()
		timeSince = func(time.Time) time.Duration {
			return 30 * time.Minute
		}

		req := newReq()

		var called bool

		w := verifier.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called = true
		}))

		rw := httptest.NewRecorder()
		w.ServeHTTP(rw, req)
		if called {
			t.Error("Body was called")
		}

		if rw.Code != 400 {
			t.Error("Wrong status code returned")
		}

		if rw.Body.String() != `{"message":"Request time skew is too great"}` {
			t.Error("Bad error message returned")
		}
	})

}
