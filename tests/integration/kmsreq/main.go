// kmsreq sends HTTPS requests for tests/integration/kes_diff_cases.py, with Go's
// TLS (as MinIO and KES clients do): one JSON request per input line,
// {"url","method","body" (base64, or null),"cert","key","follow"}, one JSON
// response per output line, {"code","headers","body" (base64),"error"}.
//
//	go build -o /tmp/kmsreq ./tests/integration/kmsreq
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type request struct {
	URL    string  `json:"url"`
	Method string  `json:"method"`
	Body   *[]byte `json:"body"`
	Cert   string  `json:"cert"`
	Key    string  `json:"key"`
	Follow bool    `json:"follow"`
}

type response struct {
	Code    int               `json:"code"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
	Error   string            `json:"error,omitempty"`
}

func do(r request) response {
	conf := &tls.Config{InsecureSkipVerify: true}
	if r.Cert != "" {
		c, err := tls.LoadX509KeyPair(r.Cert, r.Key)
		if err != nil {
			return response{Error: err.Error()}
		}
		conf.Certificates = []tls.Certificate{c}
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: conf}}
	if !r.Follow {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	var body io.Reader
	if r.Body != nil {
		body = bytes.NewReader(*r.Body)
	}
	req, err := http.NewRequest(r.Method, r.URL, body)
	if err != nil {
		return response{Error: err.Error()}
	}
	if r.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) {
			err = ue.Unwrap()
		}
		return response{Error: err.Error()}
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	h := map[string]string{}
	for k, v := range resp.Header {
		h[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return response{Code: resp.StatusCode, Headers: h, Body: out}
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 16<<20), 16<<20)
	enc := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var r request
		if err := json.Unmarshal(in.Bytes(), &r); err != nil {
			enc.Encode(response{Error: err.Error()})
			continue
		}
		enc.Encode(do(r))
	}
}
