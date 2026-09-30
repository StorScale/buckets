// s3bench is a warp-style load generator for tests/bench/warp.sh: N clients
// PUT objects of one size for a while, then GET them back for a while, and
// the throughput of each phase is printed as JSON. It uses minio-go, as warp
// does. Build it inside a MinIO checkout, which has the module:
//
//	cp -r tests/bench/s3bench ~/minio/internal/ && (cd ~/minio && go build -o /tmp/s3bench ./internal/s3bench)
//
// usage: s3bench -endpoint host:port -access A -secret S [-concurrent 16] [-size 10MiB-in-bytes] [-duration 20s]
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type phase struct {
	Op        string  `json:"op"`
	Ops       int64   `json:"ops"`
	Errors    int64   `json:"errors"`
	MiBps     float64 `json:"mib_per_s"`
	OpsPerSec float64 `json:"ops_per_s"`
	P50ms     float64 `json:"p50_ms"`
	P99ms     float64 `json:"p99_ms"`
	FirstErr  string  `json:"first_error,omitempty"`
}

func main() {
	ep := flag.String("endpoint", "127.0.0.1:9000", "")
	ak := flag.String("access", "", "")
	sk := flag.String("secret", "", "")
	conc := flag.Int("concurrent", 16, "")
	size := flag.Int64("size", 10<<20, "object size in bytes")
	dur := flag.Duration("duration", 20*time.Second, "per phase")
	bucket := flag.String("bucket", "s3bench", "")
	objects := flag.Int("objects", 64, "objects the GET phase reads, uploaded beforehand (as warp get prepares them)")
	flag.Parse()
	c, err := minio.New(*ep, &minio.Options{Creds: credentials.NewStaticV4(*ak, *sk, ""),
		Transport: &customTransport})
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	c.MakeBucket(ctx, *bucket, minio.MakeBucketOptions{})
	payload := make([]byte, *size)
	rand.New(rand.NewSource(1)).Read(payload)

	var mu sync.Mutex
	var names []string
	run := func(op string, work func(worker int, i int64) (int64, error)) phase {
		var ops, errs, bytesDone atomic.Int64
		var lat []time.Duration
		var firstErr atomic.Value
		deadline := time.Now().Add(*dur)
		start := time.Now()
		var wg sync.WaitGroup
		for w := 0; w < *conc; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				var local []time.Duration
				for i := int64(0); time.Now().Before(deadline); i++ {
					t := time.Now()
					n, err := work(w, i)
					if err != nil {
						errs.Add(1)
						firstErr.CompareAndSwap(nil, err.Error())
						continue
					}
					local = append(local, time.Since(t))
					ops.Add(1)
					bytesDone.Add(n)
				}
				mu.Lock()
				lat = append(lat, local...)
				mu.Unlock()
			}(w)
		}
		wg.Wait()
		el := time.Since(start).Seconds()
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		pct := func(p float64) float64 {
			if len(lat) == 0 {
				return 0
			}
			return float64(lat[int(p*float64(len(lat)-1))].Microseconds()) / 1000
		}
		p := phase{Op: op, Ops: ops.Load(), Errors: errs.Load(), MiBps: float64(bytesDone.Load()) / el / (1 << 20),
			OpsPerSec: float64(ops.Load()) / el, P50ms: pct(0.5), P99ms: pct(0.99)}
		if v := firstErr.Load(); v != nil {
			p.FirstErr = v.(string)
		}
		return p
	}
	put := run("PUT", func(w int, i int64) (int64, error) {
		name := fmt.Sprintf("obj-%d-%d", w, i)
		_, err := c.PutObject(ctx, *bucket, name, bytes.NewReader(payload), *size,
			minio.PutObjectOptions{DisableMultipart: true})
		if err == nil {
			mu.Lock()
			names = append(names, name)
			mu.Unlock()
		}
		return *size, err
	})
	// the GET phase's objects: a fixed set, so every server reads the same amount
	names = names[:0]
	var pw sync.WaitGroup
	sem := make(chan struct{}, *conc)
	for i := 0; i < *objects; i++ {
		pw.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer pw.Done()
			defer func() { <-sem }()
			name := fmt.Sprintf("get-%d", i)
			if _, err := c.PutObject(ctx, *bucket, name, bytes.NewReader(payload), *size,
				minio.PutObjectOptions{DisableMultipart: true}); err == nil {
				mu.Lock()
				names = append(names, name)
				mu.Unlock()
			}
		}(i)
	}
	pw.Wait()
	if len(names) == 0 {
		json.NewEncoder(os.Stdout).Encode([]phase{put})
		return
	}
	get := run("GET", func(w int, i int64) (int64, error) {
		name := names[(int(i)*(*conc)+w)%len(names)]
		o, err := c.GetObject(ctx, *bucket, name, minio.GetObjectOptions{})
		if err != nil {
			return 0, err
		}
		defer o.Close()
		n, err := io.Copy(io.Discard, o)
		return n, err
	})
	json.NewEncoder(os.Stdout).Encode([]phase{put, get})
}
