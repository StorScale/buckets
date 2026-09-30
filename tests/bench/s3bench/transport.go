package main

import (
	"net"
	"net/http"
	"time"
)

// warp's transport: many idle connections per host, no compression.
var customTransport = http.Transport{
	Proxy:               http.ProxyFromEnvironment,
	DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	MaxIdleConns:        1024,
	MaxIdleConnsPerHost: 1024,
	IdleConnTimeout:     90 * time.Second,
	DisableCompression:  true,
}
