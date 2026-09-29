// inspectdec opens MinIO's inspect-data answers with the libraries mc uses,
// for tests/integration/adminops.sh. Build it inside a MinIO checkout:
//
//	cp -r tests/integration/inspectdec ~/minio/internal/ && (cd ~/minio && go build -o /tmp/inspectdec ./internal/inspectdec)
//
//	inspectdec genkey KEYFILE     writes a private key, prints the public key (base64 PKCS #1)
//	inspectdec [KEYFILE] < answer  prints the streams and the zip's entries as JSON
package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/minio/madmin-go/v3/estream"
	"github.com/secure-io/sio-go"
)

type entry struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"`
	Method  uint16 `json:"method"`
	Size    uint64 `json:"size"`
	Content string `json:"content"`
}

type result struct {
	Format  string   `json:"format"`
	Streams []string `json:"streams,omitempty"`
	Error   string   `json:"error,omitempty"`
	Entries []entry  `json:"entries"`
	ZipErr  string   `json:"zipError,omitempty"`
}

func entries(data []byte) ([]entry, error) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var out []entry
	for _, f := range z.File {
		rc, err := f.Open()
		if err != nil {
			return out, err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return out, err
		}
		c := string(b)
		if !utf8.Valid(b) {
			c = fmt.Sprintf("binary:%d", len(b))
		}
		out = append(out, entry{f.Name, fmt.Sprintf("%v", f.Mode()), f.Method, f.UncompressedSize64, c})
	}
	return out, nil
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "genkey" {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		os.WriteFile(os.Args[2], pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
		fmt.Print(base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&k.PublicKey)))
		return
	}
	in, _ := io.ReadAll(os.Stdin)
	var res result
	var zipData []byte
	if len(in) > 33 && in[0] == 1 {
		res.Format = "legacy"
		stream, _ := sio.AES_256_GCM.Stream(in[1:33])
		nonce := make([]byte, stream.NonceSize())
		var out bytes.Buffer
		w := stream.DecryptWriter(&out, nonce, nil)
		if _, err := w.Write(in[33:]); err != nil {
			res.Error = err.Error()
		}
		if err := w.Close(); err != nil && res.Error == "" {
			res.Error = err.Error()
		}
		zipData = out.Bytes()
	} else {
		res.Format = "estream"
		kb, _ := os.ReadFile(os.Args[1])
		blk, _ := pem.Decode(kb)
		key, _ := x509.ParsePKCS1PrivateKey(blk.Bytes)
		r, err := estream.NewReader(bytes.NewReader(in))
		if err != nil {
			res.Error = err.Error()
		} else {
			r.PrivateKeyProvider(func(pub *rsa.PublicKey) *rsa.PrivateKey {
				if pub.Equal(&key.PublicKey) {
					return key
				}
				return nil // the cluster key (SUBNET's)
			})
			r.SkipEncrypted(true)
			for {
				st, err := r.NextStream()
				if err == io.EOF {
					break
				}
				if err != nil {
					res.Error = err.Error()
					break
				}
				res.Streams = append(res.Streams, st.Name)
				b, err := io.ReadAll(st)
				if err != nil {
					res.Error = err.Error()
					break
				}
				if st.Name == "inspect.zip" {
					zipData = b
				}
			}
		}
	}
	if zipData != nil {
		e, err := entries(zipData)
		res.Entries = e
		if err != nil {
			res.ZipErr = err.Error()
		}
	}
	json.NewEncoder(os.Stdout).Encode(res)
}
