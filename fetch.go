package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// fetchResult is what one download or request produced, success or not.
// Every fetch reports its own health, so a CRL that stopped being reachable
// is visible while its last good copy is still being served.
type fetchResult struct {
	ok       bool
	status   int // HTTP status; 0 for a file or a transport error
	duration time.Duration
	size     int
	err      string
}

// fetchBytes reads a URL (http/https) or a file path, capped at max bytes.
func fetchBytes(ctx context.Context, client *http.Client, loc string, max int64) ([]byte, fetchResult) {
	start := time.Now()
	var res fetchResult
	var body []byte
	var err error
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		body, res.status, err = httpGet(ctx, client, loc, max)
	} else {
		body, err = readFileCapped(loc, max)
	}
	res.duration = time.Since(start)
	res.size = len(body)
	if err != nil {
		res.err = err.Error()
		return nil, res
	}
	res.ok = true
	return body, res
}

func httpGet(ctx context.Context, client *http.Client, url string, max int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "revocation-exporter")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := readCapped(resp.Body, max)
	return b, resp.StatusCode, err
}

func readFileCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f, max)
}

// readCapped refuses a body larger than max instead of truncating it: a
// truncated CRL fails to parse and would read as "corrupt", which is the
// wrong diagnosis.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than max_crl_bytes (%d)", max)
	}
	return b, nil
}

// parseCRL accepts DER (what a CRL Distribution Point serves) or PEM
// ("X509 CRL" blocks; the first one is used).
func parseCRL(b []byte) (*x509.RevocationList, error) {
	if blk, _ := pem.Decode(b); blk != nil {
		if blk.Type != "X509 CRL" {
			return nil, fmt.Errorf("PEM block is %q, not X509 CRL", blk.Type)
		}
		b = blk.Bytes
	}
	return x509.ParseRevocationList(b)
}

// parseCerts reads every CERTIFICATE block of a PEM file (or one DER cert).
func parseCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, errors.New("no certificate found (neither PEM CERTIFICATE blocks nor DER)")
		}
		out = append(out, c)
	}
	return out, nil
}

func loadCertFile(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCerts(b)
}
