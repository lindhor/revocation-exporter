package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/crypto/ocsp"
)

// pki is a throwaway CA, one leaf, and a server that publishes the CA's CRL
// and answers OCSP for it — the whole of what the exporter reads.
type pki struct {
	caKey, leafKey *ecdsa.PrivateKey
	ca, leaf       *x509.Certificate
	srv            *httptest.Server
	revoked        atomic.Bool
	crlFails       atomic.Bool
	ocspWrongKey   atomic.Bool
	nextUpdate     time.Time
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{nextUpdate: time.Now().Add(48 * time.Hour)}
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	p.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA", Organization: []string{"Basalt"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour * 365),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &p.caKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.ca, _ = x509.ParseCertificate(der)
	p.leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234abcd), Subject: pkix.Name{CommonName: "vpn.example.test"},
		DNSNames:  []string{"127.0.0.1", "vpn.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour * 90),
		CRLDistributionPoints: []string{p.srv.URL + "/ca.crl", "ldap://ignored.example/cn=crl"},
		OCSPServer:            []string{p.srv.URL + "/ocsp"},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, leafTmpl, p.ca, &p.leafKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.leaf, _ = x509.ParseCertificate(der)
	return p
}

func (p *pki) crlDER() []byte {
	this := time.Now().Add(-time.Hour)
	if !this.Before(p.nextUpdate) {
		this = p.nextUpdate.Add(-24 * time.Hour)
	}
	tmpl := &x509.RevocationList{Number: big.NewInt(42), ThisUpdate: this, NextUpdate: p.nextUpdate}
	if p.revoked.Load() {
		tmpl.RevokedCertificateEntries = []x509.RevocationListEntry{
			{SerialNumber: p.leaf.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)}}
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, p.ca, p.caKey)
	if err != nil {
		panic(err)
	}
	return der
}

func (p *pki) ocspDER(req *ocsp.Request) []byte {
	status := ocsp.Good
	tmpl := ocsp.Response{SerialNumber: req.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(6 * time.Hour)}
	if p.revoked.Load() {
		status = ocsp.Revoked
		tmpl.RevokedAt = time.Now().Add(-time.Minute)
	}
	tmpl.Status = status
	var signer crypto.Signer = p.caKey
	if p.ocspWrongKey.Load() {
		signer, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	der, err := ocsp.CreateResponse(p.ca, p.ca, tmpl, signer)
	if err != nil {
		panic(err)
	}
	return der
}

func (p *pki) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ca.crl":
		if p.crlFails.Load() {
			http.Error(w, "gone", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(p.crlDER())
	case "/ocsp":
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(p.ocspDER(req))
	default:
		http.NotFound(w, r)
	}
}

func writePEM(t *testing.T, dir, name string, blocks ...*pem.Block) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var b []byte
	for _, blk := range blocks {
		b = append(b, pem.EncodeToMemory(blk)...)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func certBlock(c *x509.Certificate) *pem.Block { return &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw} }

// metrics runs one cycle and returns "name{l1=v1,...}" -> value.
func metrics(t *testing.T, chk *Checker) map[string]float64 {
	t.Helper()
	chk.Check(context.Background())
	reg := prometheus.NewRegistry()
	reg.MustRegister(&Collector{c: chk, now: time.Now})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			out[key(mf.GetName(), m)] = m.GetGauge().GetValue()
		}
	}
	return out
}

func key(name string, m *dto.Metric) string {
	var parts []string
	for _, l := range m.GetLabel() {
		if l.GetValue() != "" {
			parts = append(parts, l.GetName()+"="+l.GetValue())
		}
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

// find returns the value of the one series of name whose key contains every needle.
func find(t *testing.T, ms map[string]float64, name string, needles ...string) (float64, bool) {
	t.Helper()
	var hit []string
	for k := range ms {
		if !strings.HasPrefix(k, name+"{") {
			continue
		}
		ok := true
		for _, n := range needles {
			ok = ok && strings.Contains(k, n)
		}
		if ok {
			hit = append(hit, k)
		}
	}
	if len(hit) > 1 {
		t.Fatalf("%s %v matches %d series: %v", name, needles, len(hit), hit)
	}
	if len(hit) == 0 {
		return 0, false
	}
	return ms[hit[0]], true
}

func must(t *testing.T, ms map[string]float64, name string, needles ...string) float64 {
	t.Helper()
	v, ok := find(t, ms, name, needles...)
	if !ok {
		t.Fatalf("no %s series with %v", name, needles)
	}
	return v
}

func checker(cfg *Config) *Checker {
	if cfg.Timeout == 0 {
		cfg.Timeout = Duration(5 * time.Second)
	}
	if cfg.MaxCRLBytes == 0 {
		cfg.MaxCRLBytes = 64 << 20
	}
	return NewChecker(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestACertificateFileLeadsToItsCRLAndOCSP(t *testing.T) {
	p := newPKI(t)
	chain := writePEM(t, t.TempDir(), "chain.pem", certBlock(p.leaf), certBlock(p.ca))
	chk := checker(&Config{Certificates: []CertSource{{File: chain}}})
	ms := metrics(t, chk)
	crl := p.srv.URL + "/ca.crl"

	// The enix-compatible family, read from the distribution point.
	next := must(t, ms, "x509_crl_next_update", "source="+crl, "source_kind=distribution_point",
		"issuer_CN=Test CA", "issuer_O=Basalt", "crl_number=42")
	if int64(next) != p.nextUpdate.Unix() {
		t.Fatalf("next_update %v, want %v", next, p.nextUpdate.Unix())
	}
	if v := must(t, ms, "x509_crl_stale", "source="+crl); v != 0 {
		t.Fatalf("stale = %v", v)
	}
	if v := must(t, ms, "x509_crl_number", "source="+crl); v != 42 {
		t.Fatalf("number = %v", v)
	}
	if v := must(t, ms, "revocation_crl_signature_valid", "source="+crl); v != 1 {
		t.Fatalf("CRL signature = %v (issuer comes from the chain)", v)
	}
	if v := must(t, ms, "revocation_crl_certificate_revoked", "serial_number=1234abcd"); v != 0 {
		t.Fatalf("revoked per CRL = %v", v)
	}
	if v := must(t, ms, "revocation_fetch_success", "kind=crl", "source="+crl); v != 1 {
		t.Fatalf("fetch_success = %v", v)
	}
	if _, ok := find(t, ms, "revocation_fetch_success", "ldap://"); ok {
		t.Fatal("an ldap:// distribution point must be skipped, not reported as failing")
	}
	if v := must(t, ms, "revocation_ocsp_status", "status=good", "subject_CN=vpn.example.test"); v != 1 {
		t.Fatalf("OCSP good = %v", v)
	}
	if v := must(t, ms, "revocation_ocsp_signature_valid", "subject_CN=vpn.example.test"); v != 1 {
		t.Fatalf("OCSP signature = %v", v)
	}
}

func TestARevokedCertificateIsReportedByBothMechanisms(t *testing.T) {
	p := newPKI(t)
	p.revoked.Store(true)
	chain := writePEM(t, t.TempDir(), "chain.pem", certBlock(p.leaf), certBlock(p.ca))
	ms := metrics(t, checker(&Config{Certificates: []CertSource{{File: chain}}}))
	if v := must(t, ms, "revocation_crl_certificate_revoked", "serial_number=1234abcd"); v != 1 {
		t.Fatalf("revoked per CRL = %v", v)
	}
	if v := must(t, ms, "revocation_ocsp_status", "status=revoked"); v != 1 {
		t.Fatalf("OCSP revoked = %v", v)
	}
	if v := must(t, ms, "revocation_ocsp_status", "status=good"); v != 0 {
		t.Fatalf("OCSP good = %v", v)
	}
	if _, ok := find(t, ms, "revocation_ocsp_revoked_at"); !ok {
		t.Fatal("revoked_at missing")
	}
	if v := must(t, ms, "revocation_crl_revoked_certificates"); v != 1 {
		t.Fatalf("revoked entries = %v", v)
	}
}

func TestAFailedFetchKeepsTheLastGoodCRLAndSaysItFailed(t *testing.T) {
	p := newPKI(t)
	chk := checker(&Config{CRLs: []CRLSource{{URL: p.srv.URL + "/ca.crl"}}})
	metrics(t, chk)
	p.crlFails.Store(true)
	ms := metrics(t, chk)
	if v := must(t, ms, "revocation_fetch_success", "kind=crl"); v != 0 {
		t.Fatalf("fetch_success = %v", v)
	}
	if v := must(t, ms, "revocation_fetch_http_status", "kind=crl"); v != 503 {
		t.Fatalf("http_status = %v", v)
	}
	// Still counting down: the last good copy is what relying parties hold too.
	if _, ok := find(t, ms, "x509_crl_next_update", "source_kind=url"); !ok {
		t.Fatal("the last good CRL must still be reported")
	}
	if _, ok := find(t, ms, "revocation_fetch_last_success_timestamp_seconds", "kind=crl"); !ok {
		t.Fatal("last_success must survive a failed fetch")
	}
	// No issuer configured for a plain URL source: not checked, not "invalid".
	if _, ok := find(t, ms, "revocation_crl_signature_valid"); ok {
		t.Fatal("signature_valid must be absent when no issuer is known")
	}
}

func TestAStaleCRLReadsStale(t *testing.T) {
	p := newPKI(t)
	p.nextUpdate = time.Now().Add(-time.Hour)
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crl")
	if err := os.WriteFile(path, p.crlDER(), 0o600); err != nil { // DER on disk
		t.Fatal(err)
	}
	issuer := writePEM(t, dir, "ca.pem", certBlock(p.ca))
	ms := metrics(t, checker(&Config{CRLs: []CRLSource{{File: path, Issuer: issuer}}}))
	if v := must(t, ms, "x509_crl_stale", "source_kind=file"); v != 1 {
		t.Fatalf("stale = %v", v)
	}
	if v := must(t, ms, "x509_crl_stale_in_seconds"); v > -3000 {
		t.Fatalf("stale_in_seconds = %v, want about -3600", v)
	}
	if v := must(t, ms, "revocation_crl_signature_valid"); v != 1 {
		t.Fatalf("signature = %v", v)
	}
}

func TestAPEMCRLAndAWrongIssuerAreTold(t *testing.T) {
	p := newPKI(t)
	other := newPKI(t)
	dir := t.TempDir()
	path := writePEM(t, dir, "ca.crl.pem", &pem.Block{Type: "X509 CRL", Bytes: p.crlDER()})
	wrong := writePEM(t, dir, "other.pem", certBlock(other.ca))
	ms := metrics(t, checker(&Config{CRLs: []CRLSource{{File: path, Issuer: wrong}}}))
	if v := must(t, ms, "revocation_crl_signature_valid"); v != 0 {
		t.Fatalf("signature against the wrong CA = %v, want 0", v)
	}
}

func TestAnOCSPResponseSignedByTheWrongKeyIsInvalid(t *testing.T) {
	p := newPKI(t)
	p.ocspWrongKey.Store(true)
	chain := writePEM(t, t.TempDir(), "chain.pem", certBlock(p.leaf), certBlock(p.ca))
	ms := metrics(t, checker(&Config{Certificates: []CertSource{{File: chain}}}))
	if v := must(t, ms, "revocation_ocsp_signature_valid"); v != 0 {
		t.Fatalf("OCSP signature = %v, want 0", v)
	}
}

func TestOCSPWithoutAnIssuerSaysWhy(t *testing.T) {
	p := newPKI(t)
	leafOnly := writePEM(t, t.TempDir(), "leaf.pem", certBlock(p.leaf))
	chk := checker(&Config{Certificates: []CertSource{{File: leafOnly}}})
	ms := metrics(t, chk)
	if v := must(t, ms, "revocation_fetch_success", "kind=ocsp"); v != 0 {
		t.Fatalf("OCSP without an issuer = %v, want a failed fetch", v)
	}
	if got := chk.Snapshot().ocsp[0].fetch.err; !strings.Contains(got, "issuer") {
		t.Fatalf("error %q does not say the issuer is missing", got)
	}
}

func TestAnOversizeCRLIsRefusedNotTruncated(t *testing.T) {
	p := newPKI(t)
	chk := checker(&Config{MaxCRLBytes: 64, CRLs: []CRLSource{{URL: p.srv.URL + "/ca.crl"}}})
	ms := metrics(t, chk)
	if v := must(t, ms, "revocation_fetch_success"); v != 0 {
		t.Fatal("an oversize CRL must fail the fetch")
	}
	if got := chk.Snapshot().crls[0].fetch.err; !strings.Contains(got, "max_crl_bytes") {
		t.Fatalf("error %q does not name the limit", got)
	}
}

func TestATLSEndpointReportsItsStaple(t *testing.T) {
	p := newPKI(t)
	staple := p.ocspDER(&ocsp.Request{SerialNumber: p.leaf.SerialNumber})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{p.leaf.Raw, p.ca.Raw}, PrivateKey: p.leafKey, OCSPStaple: staple}}}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	ms := metrics(t, checker(&Config{Certificates: []CertSource{{TLS: addr, ServerName: "vpn.example.test"}}}))
	if v := must(t, ms, "revocation_ocsp_stapled", "source="+addr); v != 1 {
		t.Fatalf("stapled = %v", v)
	}
	if v := must(t, ms, "revocation_ocsp_stapled_status", "status=good"); v != 1 {
		t.Fatalf("stapled good = %v", v)
	}
	if v := must(t, ms, "revocation_ocsp_stapled_signature_valid"); v != 1 {
		t.Fatalf("stapled signature = %v", v)
	}
	// The chain the server presented leads to the CRL and the responder too.
	if _, ok := find(t, ms, "x509_crl_next_update", "source_kind=distribution_point"); !ok {
		t.Fatal("the TLS chain's CRL distribution point was not followed")
	}
}

func TestATLSEndpointWithoutAStapleSaysSo(t *testing.T) {
	p := newPKI(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{p.leaf.Raw, p.ca.Raw}, PrivateKey: p.leafKey}}}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	ms := metrics(t, checker(&Config{Certificates: []CertSource{{TLS: addr}}}))
	if v := must(t, ms, "revocation_ocsp_stapled"); v != 0 {
		t.Fatalf("stapled = %v, want 0", v)
	}
}

func TestAnUnreachableTLSEndpointIsNotLoaded(t *testing.T) {
	ms := metrics(t, checker(&Config{Certificates: []CertSource{{TLS: "127.0.0.1:1"}}}))
	if v := must(t, ms, "revocation_certificate_loaded"); v != 0 {
		t.Fatalf("loaded = %v", v)
	}
}

func TestTheConfigRefusesWhatItCannotDo(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"empty":    "interval: 1m\n",
		"both":     "crls: [{url: http://x/a.crl, file: /a}]\n",
		"neither":  "certificates: [{server_name: x}]\n",
		"typo":     "crls: [{url: http://x/a.crl}]\nintervall: 1m\n",
		"tooshort": "interval: 1s\ncrls: [{url: http://x/a.crl}]\n",
	} {
		path := filepath.Join(dir, name+".yaml")
		_ = os.WriteFile(path, []byte(body), 0o600)
		if _, err := loadConfig(path); err == nil {
			t.Errorf("%s: accepted %q", name, body)
		}
	}
	path := filepath.Join(dir, "ok.yaml")
	_ = os.WriteFile(path, []byte("crls: [{url: http://x/a.crl}]\n"), 0o600)
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(c.Interval) != 5*time.Minute || !c.followCRLDP() || !c.checkOCSP() {
		t.Fatalf("defaults: %+v", c)
	}
}
