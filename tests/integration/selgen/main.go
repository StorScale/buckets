// selgen writes S3 Select test fixtures with the libraries MinIO itself uses:
// stdin compressed (selgen zstd|lz4|s2|snappy), or a generated Parquet file
// (selgen parquet none|snappy|gzip|zstd v1|v2 ROWS). Build it inside a MinIO
// checkout, which has these modules:
//
//	cp -r tests/integration/selgen ~/minio/internal/ && (cd ~/minio && go build -o /tmp/selgen ./internal/selgen)
package main

import (
	"bytes"
	"io"
	"os"

	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

func main() {
	in, _ := io.ReadAll(os.Stdin)
	var b bytes.Buffer
	switch os.Args[1] {
	case "zstd":
		w, _ := zstd.NewWriter(&b)
		w.Write(in)
		w.Close()
	case "lz4":
		w := lz4.NewWriter(&b)
		w.Write(in)
		w.Close()
	case "s2":
		w := s2.NewWriter(&b)
		w.Write(in)
		w.Close()
	case "snappy":
		w := s2.NewWriter(&b, s2.WriterSnappyCompat())
		w.Write(in)
		w.Close()
	}
	os.Stdout.Write(b.Bytes())
}
