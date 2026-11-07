package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

// Label sets. The x509_crl_* family deliberately uses enix
// x509-certificate-exporter's names and its issuer_* / crl_number labels, so a
// dashboard or alert written for enix's file-based CRL metrics also reads
// these. The location label differs: enix has filename/filepath, this
// exporter has source (a URL or a path) and source_kind.
var (
	issuerFields = []string{"C", "ST", "L", "O", "OU", "CN"}
	crlLabels    = append([]string{"source", "source_kind", "crl_number"}, prefixed("issuer_", issuerFields)...)
	fetchLabels  = []string{"kind", "source"}
	certLabels   = []string{"source", "subject_CN", "serial_number", "issuer_CN"}
)

func prefixed(p string, fs []string) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = p + f
	}
	return out
}

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labels, nil)
}

var (
	// enix-compatible CRL family
	dCRLNext  = desc("x509_crl_next_update", "Unix time of the CRL's nextUpdate (RFC 5280 5.1.2.5).", crlLabels...)
	dCRLThis  = desc("x509_crl_this_update", "Unix time of the CRL's thisUpdate (RFC 5280 5.1.2.4).", crlLabels...)
	dCRLNum   = desc("x509_crl_number", "The CRL's cRLNumber extension; an issuer increments it on every publish.", crlLabels...)
	dCRLStale = desc("x509_crl_stale", "1 when now is past the CRL's nextUpdate: relying parties must stop trusting it.", crlLabels...)
	dCRLIn    = desc("x509_crl_stale_in_seconds", "Seconds until nextUpdate (negative once stale).", crlLabels...)
	dCRLSince = desc("x509_crl_fresh_since_seconds", "Seconds since thisUpdate.", crlLabels...)

	dCRLRevoked = desc("revocation_crl_revoked_certificates", "Entries in the CRL.", crlLabels...)
	dCRLSig     = desc("revocation_crl_signature_valid", "1 when the CRL's signature verifies against its issuer certificate; absent when no issuer is known.", crlLabels...)

	dFetchOK     = desc("revocation_fetch_success", "1 when the latest fetch of this source succeeded and parsed.", fetchLabels...)
	dFetchDur    = desc("revocation_fetch_duration_seconds", "Duration of the latest fetch.", fetchLabels...)
	dFetchStatus = desc("revocation_fetch_http_status", "HTTP status of the latest fetch; 0 for a file or a transport error.", fetchLabels...)
	dFetchSize   = desc("revocation_fetch_size_bytes", "Size of the latest successful download.", fetchLabels...)
	dFetchLast   = desc("revocation_fetch_last_success_timestamp_seconds", "Unix time of the last fetch that succeeded and parsed.", fetchLabels...)

	dCertLoaded  = desc("revocation_certificate_loaded", "1 when the certificate source was read (file parsed or TLS handshake completed).", "source")
	dCertCRLRev  = desc("revocation_crl_certificate_revoked", "1 when the certificate's serial is listed in a CRL its distribution points name.", append(certLabels, "crl")...)
	dOCSPStatus  = desc("revocation_ocsp_status", "OCSP status of the certificate, one series per status, 1 for the current one.", append(certLabels, "responder", "status")...)
	dOCSPThis    = desc("revocation_ocsp_this_update", "Unix time of the OCSP response's thisUpdate.", append(certLabels, "responder")...)
	dOCSPNext    = desc("revocation_ocsp_next_update", "Unix time of the OCSP response's nextUpdate (absent when the responder sets none).", append(certLabels, "responder")...)
	dOCSPRevAt   = desc("revocation_ocsp_revoked_at", "Unix time the certificate was revoked, per OCSP.", append(certLabels, "responder")...)
	dOCSPSig     = desc("revocation_ocsp_signature_valid", "1 when the OCSP response's signature verifies against the certificate's issuer.", append(certLabels, "responder")...)
	dOCSPRespErr = desc("revocation_ocsp_error_response", "1 when the responder answered with an OCSP error status (unauthorized, tryLater, ...).", append(certLabels, "responder", "error")...)
	dStapled     = desc("revocation_ocsp_stapled", "1 when the TLS server stapled an OCSP response.", "source")
	dStapleStat  = desc("revocation_ocsp_stapled_status", "Status in the stapled OCSP response, one series per status.", "source", "status")
	dStapleNext  = desc("revocation_ocsp_stapled_next_update", "Unix time of the stapled response's nextUpdate.", "source")
	dStapleSig   = desc("revocation_ocsp_stapled_signature_valid", "1 when the stapled response's signature verifies.", "source")

	dCheckDur  = desc("revocation_check_duration_seconds", "Duration of the latest check cycle.")
	dCheckLast = desc("revocation_check_last_timestamp_seconds", "Unix time the latest check cycle finished.")
)

// Collector renders the checker's latest snapshot. It never fetches anything.
type Collector struct {
	c   *Checker
	now func() time.Time
}

func (col *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{dCRLNext, dCRLThis, dCRLNum, dCRLStale, dCRLIn, dCRLSince,
		dCRLRevoked, dCRLSig, dFetchOK, dFetchDur, dFetchStatus, dFetchSize, dFetchLast, dCertLoaded,
		dCertCRLRev, dOCSPStatus, dOCSPThis, dOCSPNext, dOCSPRevAt, dOCSPSig, dOCSPRespErr, dStapled,
		dStapleStat, dStapleNext, dStapleSig, dCheckDur, dCheckLast} {
		ch <- d
	}
}

func gauge(ch chan<- prometheus.Metric, d *prometheus.Desc, v float64, lv ...string) {
	ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, lv...)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func unix(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func nameValues(n pkix.Name) []string {
	pick := func(xs []string) string { return strings.Join(xs, ",") }
	return []string{pick(n.Country), pick(n.Province), pick(n.Locality), pick(n.Organization),
		pick(n.OrganizationalUnit), n.CommonName}
}

func serialHex(c *x509.Certificate) string { return hex.EncodeToString(c.SerialNumber.Bytes()) }

func certValues(source string, c *x509.Certificate) []string {
	return []string{source, c.Subject.CommonName, serialHex(c), c.Issuer.CommonName}
}

var ocspStatuses = map[int]string{ocsp.Good: "good", ocsp.Revoked: "revoked", ocsp.Unknown: "unknown"}

func (col *Collector) Collect(ch chan<- prometheus.Metric) {
	s := col.c.Snapshot()
	if s == nil {
		return
	}
	now := col.now()
	gauge(ch, dCheckDur, s.duration.Seconds())
	gauge(ch, dCheckLast, unix(s.at))

	byURL := map[string]*crlState{}
	for _, st := range s.crls {
		byURL[st.source] = st
		col.fetch(ch, "crl", st.source, st.fetch, st.lastOK)
		if st.crl == nil {
			continue
		}
		crl := st.crl
		num := ""
		if crl.Number != nil {
			num = crl.Number.String()
		}
		lv := append([]string{st.source, st.kind, num}, nameValues(crl.Issuer)...)
		if !crl.NextUpdate.IsZero() {
			gauge(ch, dCRLNext, unix(crl.NextUpdate), lv...)
			gauge(ch, dCRLStale, b2f(now.After(crl.NextUpdate)), lv...)
			gauge(ch, dCRLIn, crl.NextUpdate.Sub(now).Seconds(), lv...)
		}
		gauge(ch, dCRLThis, unix(crl.ThisUpdate), lv...)
		gauge(ch, dCRLSince, now.Sub(crl.ThisUpdate).Seconds(), lv...)
		if crl.Number != nil {
			f, _ := new(big.Float).SetInt(crl.Number).Float64()
			gauge(ch, dCRLNum, f, lv...)
		}
		gauge(ch, dCRLRevoked, float64(len(crl.RevokedCertificateEntries)), lv...)
		if st.sigValid != nil {
			gauge(ch, dCRLSig, b2f(*st.sigValid), lv...)
		}
	}

	for _, cs := range s.certs {
		gauge(ch, dCertLoaded, b2f(cs.cert != nil), cs.source)
		if cs.cert == nil {
			continue
		}
		cv := certValues(cs.source, cs.cert)
		for _, u := range cs.crlURLs {
			st := byURL[u]
			if st == nil || st.crl == nil {
				continue
			}
			// Only a CRL issued by the certificate's own issuer can revoke it.
			if !bytes.Equal(st.crl.RawIssuer, cs.cert.RawIssuer) {
				continue
			}
			revoked := false
			for _, e := range st.crl.RevokedCertificateEntries {
				if e.SerialNumber.Cmp(cs.cert.SerialNumber) == 0 {
					revoked = true
					break
				}
			}
			gauge(ch, dCertCRLRev, b2f(revoked), append(cv, u)...)
		}
		if sp := cs.stapled; sp != nil {
			gauge(ch, dStapled, b2f(sp.present), cs.source)
			if sp.resp != nil {
				for code, name := range ocspStatuses {
					gauge(ch, dStapleStat, b2f(sp.resp.Status == code), cs.source, name)
				}
				if !sp.resp.NextUpdate.IsZero() {
					gauge(ch, dStapleNext, unix(sp.resp.NextUpdate), cs.source)
				}
				gauge(ch, dStapleSig, b2f(sp.sigValid), cs.source)
			}
		}
	}

	certBySource := map[string]*certState{}
	for _, cs := range s.certs {
		certBySource[cs.source] = cs
	}
	for _, st := range s.ocsp {
		col.fetch(ch, "ocsp", st.source+" "+st.responder, st.fetch, st.lastOK)
		cs := certBySource[st.source]
		if cs == nil || cs.cert == nil {
			continue
		}
		lv := append(certValues(st.source, cs.cert), st.responder)
		if st.respError != "" {
			gauge(ch, dOCSPRespErr, 1, append(lv, st.respError)...)
		}
		if st.resp == nil {
			continue
		}
		for code, name := range ocspStatuses {
			gauge(ch, dOCSPStatus, b2f(st.resp.Status == code), append(lv, name)...)
		}
		gauge(ch, dOCSPThis, unix(st.resp.ThisUpdate), lv...)
		if !st.resp.NextUpdate.IsZero() {
			gauge(ch, dOCSPNext, unix(st.resp.NextUpdate), lv...)
		}
		if st.resp.Status == ocsp.Revoked {
			gauge(ch, dOCSPRevAt, unix(st.resp.RevokedAt), lv...)
		}
		gauge(ch, dOCSPSig, b2f(st.sigValid), lv...)
	}
}

func (col *Collector) fetch(ch chan<- prometheus.Metric, kind, source string, r fetchResult, lastOK time.Time) {
	gauge(ch, dFetchOK, b2f(r.ok), kind, source)
	gauge(ch, dFetchDur, r.duration.Seconds(), kind, source)
	gauge(ch, dFetchStatus, float64(r.status), kind, source)
	if r.ok {
		gauge(ch, dFetchSize, float64(r.size), kind, source)
	}
	if !lastOK.IsZero() {
		gauge(ch, dFetchLast, unix(lastOK), kind, source)
	}
}
