// sftpclient runs SFTP commands with the client libraries MinIO's own tests
// use (x/crypto/ssh, pkg/sftp) and prints one JSON result per command, for
// tests/integration/sftp.sh. Build it inside a MinIO checkout, which has
// these modules:
//
//	cp -r tests/integration/sftpclient ~/minio/internal/ && (cd ~/minio && go build -o /tmp/sftpclient ./internal/sftpclient)
//
// usage: sftpclient ADDR USER (password=PW | key=FILE [cert=FILE]) < commands
//
// Commands, one per line: mkdir|rmdir|remove|stat|lstat|readlink|realpath|
// ls|get|chmod|statvfs PATH; rename|posixrename|symlink|link OLD NEW;
// put PATH SIZE; getat PATH OFF LEN; writeoff PATH SIZE (second half first);
// openflags PATH FLAGS (r, w, rw, c: create only).
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type result struct {
	Cmd string `json:"cmd"`
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
	Out any    `json:"out,omitempty"`
}

type info struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	Dir   bool   `json:"dir"`
	Mtime int64  `json:"mtime"`
}

func fi(f os.FileInfo) info {
	return info{f.Name(), f.Size(), f.Mode().String(), f.IsDir(), f.ModTime().Unix()}
}

func data(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func main() {
	addr, user := os.Args[1], os.Args[2]
	cfg := &ssh.ClientConfig{User: user, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	for _, a := range os.Args[3:] {
		k, v, _ := strings.Cut(a, "=")
		switch k {
		case "password":
			cfg.Auth = append(cfg.Auth, ssh.Password(v))
		case "key":
			pem, err := os.ReadFile(v)
			if err != nil {
				panic(err)
			}
			signer, err := ssh.ParsePrivateKey(pem)
			if err != nil {
				panic(err)
			}
			if certFile := certArg(); certFile != "" {
				cb, _ := os.ReadFile(certFile)
				pub, _, _, _, err := ssh.ParseAuthorizedKey(cb)
				if err != nil {
					panic(err)
				}
				signer, err = ssh.NewCertSigner(pub.(*ssh.Certificate), signer)
				if err != nil {
					panic(err)
				}
			}
			cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
		}
	}
	enc := json.NewEncoder(os.Stdout)
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		enc.Encode(result{Cmd: "login", Err: err.Error()})
		return
	}
	defer conn.Close()
	c, err := sftp.NewClient(conn)
	if err != nil {
		enc.Encode(result{Cmd: "sftp", Err: err.Error()})
		return
	}
	defer c.Close()
	enc.Encode(result{Cmd: "login", OK: true})
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		r := result{Cmd: sc.Text()}
		var out any
		switch f[0] {
		case "mkdir":
			err = c.Mkdir(f[1])
		case "rmdir":
			err = c.RemoveDirectory(f[1])
		case "remove":
			err = c.Remove(f[1])
		case "rename":
			err = c.Rename(f[1], f[2])
		case "posixrename":
			err = c.PosixRename(f[1], f[2])
		case "symlink":
			err = c.Symlink(f[1], f[2])
		case "link":
			err = c.Link(f[1], f[2])
		case "chmod":
			err = c.Chmod(f[1], 0o644)
		case "stat", "lstat":
			var s os.FileInfo
			if f[0] == "stat" {
				s, err = c.Stat(f[1])
			} else {
				s, err = c.Lstat(f[1])
			}
			if err == nil {
				out = fi(s)
			}
		case "readlink":
			out, err = c.ReadLink(f[1])
		case "realpath":
			out, err = c.RealPath(f[1])
		case "statvfs":
			out, err = c.StatVFS(f[1])
		case "ls":
			var l []os.FileInfo
			l, err = c.ReadDir(f[1])
			if err == nil {
				var v []info
				for _, e := range l {
					v = append(v, fi(e))
				}
				out = v
			}
		case "put":
			n, _ := strconv.Atoi(f[2])
			var w *sftp.File
			w, err = c.Create(f[1])
			if err == nil {
				_, err = w.Write(data(n))
				if cerr := w.Close(); err == nil {
					err = cerr
				}
			}
		case "writeoff":
			n, _ := strconv.Atoi(f[2])
			var w *sftp.File
			w, err = c.OpenFile(f[1], os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
			if err == nil {
				d := data(n)
				_, err = w.WriteAt(d[n/2:], int64(n/2))
				if err == nil {
					_, err = w.WriteAt(d[:n/2], 0)
				}
				if cerr := w.Close(); err == nil {
					err = cerr
				}
			}
		case "get", "getat":
			var rd *sftp.File
			rd, err = c.Open(f[1])
			if err == nil {
				var b []byte
				if f[0] == "get" {
					b, err = io.ReadAll(rd)
				} else {
					off, _ := strconv.ParseInt(f[2], 10, 64)
					n, _ := strconv.Atoi(f[3])
					b = make([]byte, n)
					var k int
					k, err = rd.ReadAt(b, off)
					b = b[:k]
					if err == io.EOF {
						err = nil
						out = "eof"
					}
				}
				rd.Close()
				sum := sha256.Sum256(b)
				out = map[string]any{"len": len(b), "sha256": hex.EncodeToString(sum[:]), "note": out}
			}
		case "openflags":
			fl := 0
			switch f[2] {
			case "r":
				fl = os.O_RDONLY
			case "w":
				fl = os.O_WRONLY
			case "rw":
				fl = os.O_RDWR
			case "c":
				fl = os.O_CREATE
			}
			var h *sftp.File
			h, err = c.OpenFile(f[1], fl)
			if err == nil {
				err = h.Close()
			}
		default:
			err = fmt.Errorf("unknown command %q", f[0])
		}
		r.OK = err == nil
		if err != nil {
			r.Err = err.Error()
		}
		r.Out = out
		enc.Encode(r)
	}
}

func certArg() string {
	for _, a := range os.Args[3:] {
		if v, ok := strings.CutPrefix(a, "cert="); ok {
			return v
		}
	}
	return ""
}
