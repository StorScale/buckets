package main

// -metrics: the servers' internode call counts (buckets_node_internode_*),
// read before and after each phase, so a phase reports how many calls between
// servers its requests made, by operation, and how long they took.

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type rpcOp struct {
	Calls    float64 `json:"calls"`
	WaitS    float64 `json:"wait_s"`
	Served   float64 `json:"served"`
	ServedS  float64 `json:"served_s"`
	PerReq   float64 `json:"calls_per_request"`
	WaitMs   float64 `json:"wait_ms_per_call"`
	ServedMs float64 `json:"served_ms_per_call"`
}

var rpcFields = map[string]func(o *rpcOp) *float64{
	"buckets_node_internode_calls_total":          func(o *rpcOp) *float64 { return &o.Calls },
	"buckets_node_internode_call_seconds_total":   func(o *rpcOp) *float64 { return &o.WaitS },
	"buckets_node_internode_served_total":         func(o *rpcOp) *float64 { return &o.Served },
	"buckets_node_internode_served_seconds_total": func(o *rpcOp) *float64 { return &o.ServedS },
}

// A token for the metrics endpoints, as `mc admin prometheus generate` makes one.
func promToken(ak, sk string) string {
	enc := base64.RawURLEncoding.EncodeToString
	h := enc([]byte(`{"alg":"HS512","typ":"JWT"}`))
	c := enc([]byte(fmt.Sprintf(`{"exp":%d,"sub":%q,"iss":"prometheus"}`, time.Now().Add(24*time.Hour).Unix(), ak)))
	m := hmac.New(sha512.New, []byte(sk))
	m.Write([]byte(h + "." + c))
	return h + "." + c + "." + enc(m.Sum(nil))
}

// The servers' internode counters, summed.
func scrapeRPC(hosts []string, token string) (map[string]*rpcOp, error) {
	out := map[string]*rpcOp{}
	for _, host := range hosts {
		req, _ := http.NewRequest("GET", "http://"+host+"/minio/v2/metrics/node", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("%s: metrics: %s", host, resp.Status)
		}
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			brace := strings.IndexByte(line, '{')
			if brace < 0 || !strings.HasPrefix(line, "buckets_node_internode_") {
				continue
			}
			field := rpcFields[line[:brace]]
			_, rest, ok := strings.Cut(line[brace:], `op="`)
			if field == nil || !ok {
				continue
			}
			name, rest, _ := strings.Cut(rest, `"`)
			sp := strings.LastIndexByte(rest, ' ')
			v, err := strconv.ParseFloat(rest[sp+1:], 64)
			if err != nil {
				continue
			}
			if out[name] == nil {
				out[name] = &rpcOp{}
			}
			*field(out[name]) += v
		}
		resp.Body.Close()
	}
	return out, nil
}

// after - before, per request of the phase.
func diffRPC(before, after map[string]*rpcOp, requests int64) map[string]*rpcOp {
	d := map[string]*rpcOp{}
	for name, a := range after {
		b := before[name]
		if b == nil {
			b = &rpcOp{}
		}
		o := &rpcOp{Calls: a.Calls - b.Calls, WaitS: a.WaitS - b.WaitS, Served: a.Served - b.Served, ServedS: a.ServedS - b.ServedS}
		if o.Calls == 0 && o.Served == 0 {
			continue
		}
		if requests > 0 {
			o.PerReq = o.Calls / float64(requests)
		}
		if o.Calls > 0 {
			o.WaitMs = o.WaitS / o.Calls * 1000
		}
		if o.Served > 0 {
			o.ServedMs = o.ServedS / o.Served * 1000
		}
		d[name] = o
	}
	return d
}
