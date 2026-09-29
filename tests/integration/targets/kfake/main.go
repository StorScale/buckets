// SPDX-License-Identifier: AGPL-3.0-or-later

// A Kafka broker stand-in for target tests (franz-go's kfake): one broker
// with the given topics (one partition each), optionally requiring SASL,
// that logs every request -- key, version, client ID and, for Metadata and
// Produce, what was asked and the records sent -- one JSON array per line.
//
//	kfake -port 19951 -out log -topics events,stored [-sasl plain|scram-sha-256|scram-sha-512 -user u -pass p]
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kmsg"
)

func main() {
	port := flag.Int("port", 9092, "listen port")
	out := flag.String("out", "kfake.log", "log file")
	topics := flag.String("topics", "events", "comma-separated topics")
	sasl := flag.String("sasl", "", "plain, scram-sha-256 or scram-sha-512")
	user := flag.String("user", "", "SASL user")
	pass := flag.String("pass", "", "SASL password")
	flag.Parse()

	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	logRec := func(rec ...any) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := json.Marshal(rec)
		f.Write(append(b, '\n'))
	}

	opts := []kfake.Opt{kfake.Ports(*port), kfake.NumBrokers(1), kfake.SeedTopics(1, strings.Split(*topics, ",")...)}
	if *sasl != "" {
		opts = append(opts, kfake.EnableSASL(), kfake.Superuser(strings.ToUpper(*sasl), *user, *pass))
	}
	c, err := kfake.NewCluster(opts...)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	for key := int16(0); key <= 70; key++ {
		key := key
		c.ControlKey(key, func(req kmsg.Request) (kmsg.Response, error, bool) {
			c.KeepControl()
			rec := []any{kmsg.NameForKey(key), req.GetVersion()}
			switch r := req.(type) {
			case *kmsg.MetadataRequest:
				var ts []string
				for _, t := range r.Topics {
					if t.Topic != nil {
						ts = append(ts, *t.Topic)
					}
				}
				rec = append(rec, r.Topics == nil, ts, r.AllowAutoTopicCreation)
			case *kmsg.ProduceRequest:
				rec = append(rec, r.Acks, r.TimeoutMillis)
				for _, t := range r.Topics {
					for _, p := range t.Partitions {
						var batch kmsg.RecordBatch
						if err := batch.ReadFrom(p.Records); err != nil {
							rec = append(rec, "bad batch: "+err.Error())
							continue
						}
						recs := []any{t.Topic, p.Partition, batch.Magic, batch.Attributes, batch.LastOffsetDelta,
							batch.ProducerID, batch.ProducerEpoch, batch.FirstSequence, batch.PartitionLeaderEpoch, batch.NumRecords}
						if batch.Attributes&7 == 0 {
							raw := batch.Records
							for i := int32(0); i < batch.NumRecords; i++ {
								var r kmsg.Record
								if err := r.ReadFrom(raw); err != nil {
									break
								}
								recs = append(recs, []any{r.OffsetDelta, string(r.Key), string(r.Value), len(r.Headers)})
								raw = raw[r.Length+int32(varintLen(int64(r.Length))):]
							}
						}
						rec = append(rec, recs)
					}
				}
			case *kmsg.SASLHandshakeRequest:
				rec = append(rec, r.Mechanism)
			case *kmsg.ApiVersionsRequest:
				rec = append(rec, r.ClientSoftwareName, r.ClientSoftwareVersion)
			}
			logRec(rec...)
			return nil, nil, false
		})
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
}

func varintLen(v int64) int {
	u := uint64(v<<1) ^ uint64(v>>63)
	n := 1
	for u >= 0x80 {
		u >>= 7
		n++
	}
	return n
}
