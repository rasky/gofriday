package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

var port = flag.Int("port", 0, "HTTP port to listen to (default to $PORT)")
var ca = flag.String("ca", "", "CA bundle to validate remote server (PEM file)")

// Implements http.Handle
type ReverseProxy struct {

	// The remote that we need to connect to
	Remote *url.URL

	// The client to which requests must be proxied
	Transport *http.Transport
}

func (rp *ReverseProxy) ServeHTTP(out http.ResponseWriter, req *http.Request) {

	c := http.Client{
		Transport: rp.Transport,
	}

	// Only change Path component of the remote URL
	proxyurl := *rp.Remote
	proxyurl.Path = req.URL.Path

	// Prepare a request which is identical to the original one
	proxyreq := &http.Request{
		Method:           req.Method,
		URL:              &proxyurl,
		Header:           req.Header,
		Body:             req.Body,
		ContentLength:    req.ContentLength,
		TransferEncoding: req.TransferEncoding,
		Close:            false,
	}

	resp, err := c.Do(proxyreq)
	if err != nil {
		log.Println("error proxying request", err)
		log.Println("request", req)
		log.Println("response", resp)
		out.WriteHeader(http.StatusBadGateway)
		return
	}

	// Send response header back to client
	for k, v := range resp.Header {
		out.Header()[k] = v
	}

	out.WriteHeader(resp.StatusCode)

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Println("error sending response body", err)
	}

	resp.Body.Close()
}

func main() {
	flag.Parse()

	if *port == 0 {
		xport, err := strconv.Atoi(os.Getenv("PORT"))
		if err != nil {
			fmt.Println("Please specify the HTTP port (either flag or environment)")
			os.Exit(1)
		}
		*port = xport
	}

	if flag.NArg() < 1 {
		fmt.Println("Specify remote URL on the command line")
		os.Exit(1)
	}

	remote, err := url.Parse(flag.Arg(0))
	if err != nil {
		fmt.Println("error parsing remote URL", err)
		os.Exit(1)
	}

	transport := new(http.Transport)

	switch remote.Scheme {
	case "http":
		if *ca != "" {
			log.Println("ignoring ca flag for non-https remote")
		}

	case "https":
		if *ca != "" {
			pool := x509.NewCertPool()
			data, err := ioutil.ReadFile(*ca)
			if err != nil {
				log.Fatal(err)
				os.Exit(1)
			}
			pool.AppendCertsFromPEM(data)
			tlsconfig := new(tls.Config)
			tlsconfig.RootCAs = pool
			transport.TLSClientConfig = tlsconfig
		}

	default:
		fmt.Println("unsupported remote scheme:", remote.Scheme)
		os.Exit(1)
	}

	rp := &ReverseProxy{
		remote,
		transport,
	}

	log.Fatal(http.ListenAndServe(
		fmt.Sprintf(":%v", *port), rp))
}
