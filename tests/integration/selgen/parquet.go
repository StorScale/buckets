package main

import (
	"bytes"
	"fmt"
	"os"

	goparquet "github.com/fraugster/parquet-go"
	"github.com/fraugster/parquet-go/parquet"
	"github.com/fraugster/parquet-go/parquetschema"
)

const schemaText = `message test {
  required int64 id;
  optional binary name (STRING);
  optional int32 day (DATE);
  optional int64 ts_ms (TIMESTAMP(MILLIS, true));
  optional int64 ts_us (TIMESTAMP(MICROS, true));
  optional int64 ts_ns (TIMESTAMP(NANOS, true));
  optional int64 ts_local (TIMESTAMP(MILLIS, false));
  optional double score;
  optional float ratio;
  required boolean flag;
  optional int32 small;
  optional fixed_len_byte_array(4) code;
  optional int96 legacy;
  repeated int64 tags;
  optional group nested {
    optional int32 inner;
    optional binary label (STRING);
  }
}`

// parquetFile writes rows rows with the codec and page version.
func parquetFile(codec string, v2 bool, rows int) []byte {
	sd, err := parquetschema.ParseSchemaDefinition(schemaText)
	if err != nil {
		panic(err)
	}
	codecs := map[string]parquet.CompressionCodec{
		"none": parquet.CompressionCodec_UNCOMPRESSED, "snappy": parquet.CompressionCodec_SNAPPY,
		"gzip": parquet.CompressionCodec_GZIP, "zstd": parquet.CompressionCodec_ZSTD,
	}
	var b bytes.Buffer
	opts := []goparquet.FileWriterOption{
		goparquet.WithSchemaDefinition(sd), goparquet.WithCompressionCodec(codecs[codec]),
		goparquet.WithMaxRowGroupSize(4096),
	}
	if v2 {
		opts = append(opts, goparquet.WithDataPageV2())
	}
	w := goparquet.NewFileWriter(&b, opts...)
	for i := 0; i < rows; i++ {
		row := map[string]interface{}{
			"id":   int64(i),
			"flag": i%3 == 0,
		}
		if i%5 != 0 {
			row["name"] = []byte(fmt.Sprintf("name-%d", i%17))
			row["day"] = int32(18000 + i)
			row["ts_ms"] = int64(1600000000000 + int64(i)*1234)
			row["ts_us"] = int64(1600000000000000 + int64(i)*999)
			row["ts_ns"] = int64(1600000000000000000 + int64(i)*123456789)
			row["ts_local"] = int64(1600000000000 + int64(i))
			row["score"] = float64(i) / 7
			row["ratio"] = float32(i) / 3
			row["small"] = int32(i % 100)
			row["code"] = []byte(fmt.Sprintf("c%03d", i%1000))
			var legacy [12]byte
			legacy[0] = byte(i)
			row["legacy"] = legacy
			row["tags"] = []int64{int64(i), int64(i * 2)}
			row["nested"] = map[string]interface{}{"inner": int32(i), "label": []byte("x")}
		}
		if err := w.AddData(row); err != nil {
			panic(err)
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func init() {
	if len(os.Args) > 3 && os.Args[1] == "parquet" {
		var rows int
		fmt.Sscan(os.Args[4], &rows)
		os.Stdout.Write(parquetFile(os.Args[2], os.Args[3] == "v2", rows))
		os.Exit(0)
	}
}
