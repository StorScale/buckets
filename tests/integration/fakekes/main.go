// fakekes is a small KES server for tests/integration/kes.sh: the API
// kms-go's client (and so MinIO) uses -- /version, /v1/status, /v1/api and
// the key create/generate/decrypt/list/describe calls -- with in-memory
// AES-256-GCM keys, KES's error messages, and mutual TLS (any client
// certificate is accepted; -deny makes key operations answer 403).
//
//	go build -o /tmp/fakekes ./tests/integration/fakekes
//	fakekes -addr 127.0.0.1:7373 -cert server.crt -key server.key [-deny]
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
)

var (
	mu   sync.Mutex
	keys = map[string][]byte{}
	deny = flag.Bool("deny", false, "answer key operations with 403")
)

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func key(name string) ([]byte, bool) {
	mu.Lock()
	defer mu.Unlock()
	k, ok := keys[name]
	return k, ok
}

func main() {
	addr := flag.String("addr", "127.0.0.1:7373", "listen address")
	cert := flag.String("cert", "", "server certificate")
	priv := flag.String("key", "", "server private key")
	initial := flag.String("keys", "", "keys to create at start, comma separated")
	flag.Parse()
	for _, n := range strings.Split(*initial, ",") {
		if n != "" {
			k := make([]byte, 32)
			rand.Read(k)
			keys[n] = k
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]string{"version": "2025-03-12T09-35-18Z"})
	})
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"version": "2025-03-12T09-35-18Z", "os": "darwin", "arch": "arm64", "uptime": 1})
	})
	mux.HandleFunc("/v1/api", func(w http.ResponseWriter, r *http.Request) {
		reply(w, []map[string]any{
			{"method": "GET", "path": "/v1/status", "max_body": 0, "timeout": 15},
			{"method": "POST", "path": "/v1/key/generate/", "max_body": 1048576, "timeout": 15},
		})
	})
	mux.HandleFunc("/v1/key/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/v1/key/"), "/", 2)
		op, name := parts[0], ""
		if len(parts) == 2 {
			name = parts[1]
		}
		if *deny {
			fail(w, http.StatusForbidden, "not authorized: insufficient permissions")
			return
		}
		switch op {
		case "create":
			mu.Lock()
			_, exists := keys[name]
			if !exists {
				k := make([]byte, 32)
				rand.Read(k)
				keys[name] = k
			}
			mu.Unlock()
			if exists {
				fail(w, http.StatusBadRequest, "key already exists")
				return
			}
			w.WriteHeader(http.StatusOK)
		case "delete":
			mu.Lock()
			_, exists := keys[name]
			delete(keys, name)
			mu.Unlock()
			if !exists {
				fail(w, http.StatusNotFound, "key does not exist")
				return
			}
			w.WriteHeader(http.StatusOK)
		case "describe":
			if _, ok := key(name); !ok {
				fail(w, http.StatusNotFound, "key does not exist")
				return
			}
			reply(w, map[string]any{"name": name, "algorithm": "AES256-GCM_SHA256"})
		case "list":
			mu.Lock()
			var names []string
			for n := range keys {
				if strings.HasPrefix(n, strings.TrimSuffix(name, "*")) {
					names = append(names, n)
				}
			}
			mu.Unlock()
			sort.Strings(names)
			reply(w, map[string]any{"names": names, "continue_at": ""})
		case "generate", "decrypt":
			k, ok := key(name)
			if !ok {
				fail(w, http.StatusNotFound, "key does not exist")
				return
			}
			var req struct {
				Context    []byte `json:"context"`
				Ciphertext []byte `json:"ciphertext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				fail(w, http.StatusBadRequest, "invalid request body")
				return
			}
			block, _ := aes.NewCipher(k)
			gcm, _ := cipher.NewGCM(block)
			if op == "generate" {
				pt := make([]byte, 32)
				rand.Read(pt)
				nonce := make([]byte, gcm.NonceSize())
				rand.Read(nonce)
				ct := append(nonce, gcm.Seal(nil, nonce, pt, req.Context)...)
				reply(w, map[string][]byte{"plaintext": pt, "ciphertext": ct})
				return
			}
			ns := gcm.NonceSize()
			if len(req.Ciphertext) < ns {
				fail(w, http.StatusBadRequest, "decryption failed: ciphertext is not authentic")
				return
			}
			pt, err := gcm.Open(nil, req.Ciphertext[:ns], req.Ciphertext[ns:], req.Context)
			if err != nil {
				fail(w, http.StatusBadRequest, "decryption failed: ciphertext is not authentic")
				return
			}
			reply(w, map[string][]byte{"plaintext": pt})
		default:
			fail(w, http.StatusNotFound, "not found")
		}
	})
	srv := &http.Server{Addr: *addr, Handler: mux, TLSConfig: &tls.Config{ClientAuth: tls.RequireAnyClientCert}}
	log.Fatal(srv.ListenAndServeTLS(*cert, *priv))
}
