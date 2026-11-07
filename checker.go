package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// crlState is one CRL: the last copy that parsed, and the health of the
// latest fetch. A failed fetch keeps the last good copy, so the CRL's own
// nextUpdate keeps counting down while the fetch failure is reported beside it.
type crlState struct {
	source   string // URL or file path
	kind     string // "url", "file" or "distribution_point"
	issuer   *x509.Certificate
	fetch    fetchResult
	lastOK   time.Time
	crl      *x509.RevocationList
	sigValid *bool // nil: no issuer certificate known, so not checked
}

// certState is one certificate (the leaf of a configured source).
type certState struct {
	source   string
	cert     *x509.Certificate
	issuer   *x509.Certificate
	loadErr  string
	crlURLs  []string
	ocspURLs []string
	stapled  *stapleState // TLS sources only
}

type stapleState struct {
	present  bool
	resp     *ocsp.Response
	sigValid bool
}

// ocspState is one (certificate, responder) pair.
type ocspState struct {
	source    string
	responder string
	fetch     fetchResult
	lastOK    time.Time
	resp      *ocsp.Response
	sigValid  bool
	respError string // an OCSP error response (unauthorized, tryLater …)
}

// Snapshot is what one check cycle produced; the collector renders it.
type Snapshot struct {
	at       time.Time
	duration time.Duration
	crls     []*crlState
	certs    []*certState
	ocsp     []*ocspState
}

// Checker runs check cycles and keeps state between them.
type Checker struct {
	cfg    *Config
	client *http.Client
	log    *slog.Logger

	mu   sync.Mutex
	crls map[string]*crlState
	ocsp map[string]*ocspState
	snap *Snapshot
}

func NewChecker(cfg *Config, log *slog.Logger) *Checker {
	return &Checker{
		cfg: cfg,
		log: log,
		// Redirects are followed (a CDP commonly redirects http -> a CDN),
		// at most 5, as net/http does by default.
		client: &http.Client{Timeout: time.Duration(cfg.Timeout)},
		crls:   map[string]*crlState{},
		ocsp:   map[string]*ocspState{},
	}
}

// Snapshot returns the latest completed cycle (nil before the first).
func (c *Checker) Snapshot() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snap
}

// Run checks once immediately, then every interval, until ctx ends.
func (c *Checker) Run(ctx context.Context) {
	t := time.NewTicker(time.Duration(c.cfg.Interval))
	defer t.Stop()
	for {
		c.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Check runs one cycle.
func (c *Checker) Check(ctx context.Context) {
	start := time.Now()
	certs := c.loadCertificates(ctx)

	// Which CRLs to fetch this cycle: the configured ones, then every
	// distribution point a certificate names (deduplicated by URL).
	type want struct {
		loc, kind string
		issuer    *x509.Certificate
	}
	var wants []want
	seen := map[string]bool{}
	for _, s := range c.cfg.CRLs {
		loc, kind := s.URL, "url"
		if loc == "" {
			loc, kind = s.File, "file"
		}
		var iss *x509.Certificate
		if s.Issuer != "" {
			if cs, err := loadCertFile(s.Issuer); err == nil {
				iss = cs[0]
			} else {
				c.log.Warn("cannot read CRL issuer", "file", s.Issuer, "err", err)
			}
		}
		if !seen[loc] {
			seen[loc] = true
			wants = append(wants, want{loc, kind, iss})
		}
	}
	if c.cfg.followCRLDP() {
		for _, cs := range certs {
			for _, u := range cs.crlURLs {
				if !seen[u] {
					seen[u] = true
					wants = append(wants, want{u, "distribution_point", cs.issuer})
				}
			}
		}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	results := make([]*crlState, len(wants))
	for i, w := range wants {
		wg.Add(1)
		go func(i int, w want) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = c.checkCRL(ctx, w.loc, w.kind, w.issuer)
		}(i, w)
	}

	var ocspResults []*ocspState
	var omu sync.Mutex
	if c.cfg.checkOCSP() {
		for _, cs := range certs {
			if cs.cert == nil {
				continue
			}
			for _, u := range cs.ocspURLs {
				wg.Add(1)
				go func(cs *certState, u string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					st := c.checkOCSP(ctx, cs, u)
					omu.Lock()
					ocspResults = append(ocspResults, st)
					omu.Unlock()
				}(cs, u)
			}
		}
	}
	wg.Wait()

	sort.Slice(ocspResults, func(i, j int) bool {
		return ocspResults[i].source+ocspResults[i].responder < ocspResults[j].source+ocspResults[j].responder
	})
	snap := &Snapshot{at: time.Now(), duration: time.Since(start), crls: results,
		certs: certs, ocsp: ocspResults}
	c.mu.Lock()
	c.snap = snap
	c.mu.Unlock()
	c.log.Info("check done", "crls", len(results), "certificates", len(certs),
		"ocsp", len(ocspResults), "took", snap.duration.Round(time.Millisecond))
}

func (c *Checker) checkCRL(ctx context.Context, loc, kind string, issuer *x509.Certificate) *crlState {
	c.mu.Lock()
	st := c.crls[loc]
	if st == nil {
		st = &crlState{source: loc, kind: kind}
		c.crls[loc] = st
	}
	c.mu.Unlock()
	if issuer != nil {
		st.issuer = issuer
	}
	fctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.Timeout))
	defer cancel()
	b, res := fetchBytes(fctx, c.client, loc, c.cfg.MaxCRLBytes)
	if res.ok {
		crl, err := parseCRL(b)
		if err != nil {
			res.ok = false
			res.err = "parse: " + err.Error()
		} else {
			st.crl = crl
			st.lastOK = time.Now()
		}
	}
	st.fetch = res
	if !res.ok {
		c.log.Warn("CRL fetch failed", "source", loc, "status", res.status, "err", res.err)
	}
	st.sigValid = nil
	if st.crl != nil && st.issuer != nil {
		ok := st.crl.CheckSignatureFrom(st.issuer) == nil
		st.sigValid = &ok
	}
	// A copy: the collector renders this snapshot while the next cycle
	// updates the stored state.
	cp := *st
	return &cp
}

// loadCertificates reads every configured certificate source; a TLS source
// also yields the stapled OCSP response, if the server sent one.
func (c *Checker) loadCertificates(ctx context.Context) []*certState {
	var out []*certState
	for _, s := range c.cfg.Certificates {
		cs := &certState{source: s.File}
		var chain []*x509.Certificate
		var err error
		if s.TLS != "" {
			cs.source = s.TLS
			var staple []byte
			chain, staple, err = c.dialTLS(ctx, s.TLS, s.ServerName)
			if err == nil {
				cs.stapled = &stapleState{present: len(staple) > 0}
				if len(chain) > 1 && len(staple) > 0 {
					if r, e := ocsp.ParseResponseForCert(staple, chain[0], nil); e == nil {
						cs.stapled.resp = r
						_, e2 := ocsp.ParseResponseForCert(staple, chain[0], chain[1])
						cs.stapled.sigValid = e2 == nil
					}
				}
			}
		} else {
			chain, err = loadCertFile(s.File)
		}
		if err != nil {
			cs.loadErr = err.Error()
			c.log.Warn("certificate source failed", "source", cs.source, "err", err)
			out = append(out, cs)
			continue
		}
		cs.cert = chain[0]
		if len(chain) > 1 {
			cs.issuer = chain[1]
		}
		if s.Issuer != "" {
			if is, e := loadCertFile(s.Issuer); e == nil {
				cs.issuer = is[0]
			}
		}
		cs.crlURLs = httpOnly(cs.cert.CRLDistributionPoints)
		cs.ocspURLs = httpOnly(cs.cert.OCSPServer)
		out = append(out, cs)
	}
	return out
}

// httpOnly drops ldap:// and other schemes this exporter does not fetch.
func httpOnly(urls []string) []string {
	var out []string
	for _, u := range urls {
		if len(u) > 7 && (u[:7] == "http://" || (len(u) > 8 && u[:8] == "https://")) {
			out = append(out, u)
		}
	}
	return out
}

func (c *Checker) dialTLS(ctx context.Context, addr, serverName string) ([]*x509.Certificate, []byte, error) {
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, nil, err
		}
		serverName = host
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: time.Duration(c.cfg.Timeout)},
		Config: &tls.Config{
			ServerName: serverName,
			// This exporter INSPECTS the chain a server presents (to follow
			// its CRL and OCSP pointers); it does not trust it with anything.
			// An expired or untrusted chain must still be read.
			InsecureSkipVerify: true, //nolint:gosec
		},
	}
	dctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.Timeout))
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	cst := conn.(*tls.Conn).ConnectionState()
	if len(cst.PeerCertificates) == 0 {
		return nil, nil, fmt.Errorf("%s presented no certificate", addr)
	}
	return cst.PeerCertificates, cst.OCSPResponse, nil
}

func (c *Checker) checkOCSP(ctx context.Context, cs *certState, responder string) *ocspState {
	st := c.ocspOnce(ctx, cs, responder)
	cp := *st // see checkCRL
	return &cp
}

func (c *Checker) ocspOnce(ctx context.Context, cs *certState, responder string) *ocspState {
	key := cs.source + "|" + responder
	c.mu.Lock()
	st := c.ocsp[key]
	if st == nil {
		st = &ocspState{source: cs.source, responder: responder}
		c.ocsp[key] = st
	}
	c.mu.Unlock()
	start := time.Now()
	res := fetchResult{}
	defer func() { res.duration = time.Since(start); st.fetch = res }()
	if cs.issuer == nil {
		res.err = "issuer certificate unknown (add it to the chain or set issuer:)"
		return st
	}
	req, err := ocsp.CreateRequest(cs.cert, cs.issuer, nil)
	if err != nil {
		res.err = err.Error()
		return st
	}
	fctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.Timeout))
	defer cancel()
	hreq, err := http.NewRequestWithContext(fctx, http.MethodPost, responder, bytes.NewReader(req))
	if err != nil {
		res.err = err.Error()
		return st
	}
	hreq.Header.Set("Content-Type", "application/ocsp-request")
	hreq.Header.Set("Accept", "application/ocsp-response")
	resp, err := c.client.Do(hreq)
	if err != nil {
		res.err = err.Error()
		return st
	}
	defer resp.Body.Close()
	res.status = resp.StatusCode
	body, err := readCapped(resp.Body, 1<<20)
	res.size = len(body)
	if err != nil || resp.StatusCode != http.StatusOK {
		if err == nil {
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		res.err = err.Error()
		_, _ = io.Copy(io.Discard, resp.Body)
		return st
	}
	parsed, err := ocsp.ParseResponseForCert(body, cs.cert, nil)
	if err != nil {
		if re, ok := err.(ocsp.ResponseError); ok {
			st.respError = re.Status.String()
		}
		res.err = "parse: " + err.Error()
		return st
	}
	_, verr := ocsp.ParseResponseForCert(body, cs.cert, cs.issuer)
	st.resp, st.sigValid, st.respError, st.lastOK = parsed, verr == nil, "", time.Now()
	res.ok = true
	return st
}
