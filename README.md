# revocation-exporter

A Prometheus exporter for certificate **revocation infrastructure**: CRLs and OCSP.

Expiring *certificates* are well covered (blackbox_exporter, enix
x509-certificate-exporter). What goes unwatched is the machinery that says
whether a certificate is still good. A CRL that has passed its `nextUpdate`
makes relying parties refuse every certificate its issuer signed. Examples are
IPsec gateways, RADIUS/802.1X, smart-card logon and mutual-TLS clients. An
OCSP responder that stopped answering, or a TLS server that stopped stapling,
fails the same way. This exporter watches both.

- **CRLs** from http(s) URLs or files (PEM or DER), and every CRL named by the
  CRL Distribution Points of the certificates you give it.
- **OCSP**: asks the responders named in each certificate's Authority
  Information Access. It reports good/revoked/unknown, `thisUpdate`/`nextUpdate`,
  revocation time and signature validity, including delegated OCSP signers.
- **Stapling**: for a `host:port` source it reads the chain the server presents
  and the OCSP response it staples, if any.
- **Fetch health** beside every answer: success, HTTP status, duration, size and
  the last success. A failed download keeps the last good CRL, so its
  `nextUpdate` keeps counting down while the failure is reported. That is also
  what a relying party holding a cached copy experiences.

Checks run on an interval and are cached. A scrape never triggers a download.

## Metrics

The `x509_crl_*` family uses **enix x509-certificate-exporter's names** and its
`issuer_*` / `crl_number` labels, so alerts written for one read the other.
The location label differs: enix has `filename`/`filepath`, this exporter has
`source` (a URL or path) and `source_kind` (`url`, `file`,
`distribution_point`).

| metric | meaning |
| --- | --- |
| `x509_crl_next_update`, `x509_crl_this_update` | Unix time of the CRL's nextUpdate / thisUpdate |
| `x509_crl_number` | the cRLNumber extension (an issuer increments it on every publish) |
| `x509_crl_stale` | 1 once now is past nextUpdate |
| `x509_crl_stale_in_seconds` | seconds until nextUpdate (negative once stale) |
| `x509_crl_fresh_since_seconds` | seconds since thisUpdate |
| `revocation_crl_revoked_certificates` | entries in the CRL |
| `revocation_crl_signature_valid` | the CRL's signature verifies against its issuer (absent when no issuer certificate is known) |
| `revocation_crl_certificate_revoked` | a watched certificate's serial is on a CRL its distribution points name |
| `revocation_ocsp_status{status}` | one series per good/revoked/unknown, 1 for the current answer |
| `revocation_ocsp_this_update`, `revocation_ocsp_next_update`, `revocation_ocsp_revoked_at` | from the OCSP response |
| `revocation_ocsp_signature_valid` | the response verifies against the certificate's issuer |
| `revocation_ocsp_error_response{error}` | the responder answered unauthorized, tryLater, … |
| `revocation_ocsp_stapled`, `revocation_ocsp_stapled_status`, `revocation_ocsp_stapled_next_update`, `revocation_ocsp_stapled_signature_valid` | the TLS server's staple |
| `revocation_fetch_success`, `revocation_fetch_http_status`, `revocation_fetch_duration_seconds`, `revocation_fetch_size_bytes`, `revocation_fetch_last_success_timestamp_seconds` | per source, `kind="crl"` or `"ocsp"` |
| `revocation_certificate_loaded` | the certificate file parsed / the TLS handshake completed |
| `revocation_check_duration_seconds`, `revocation_check_last_timestamp_seconds` | the check cycle itself |

Example alerts:

```promql
# CRL goes stale within 3 days
x509_crl_stale_in_seconds < 3 * 86400
# The issuer stopped publishing (thisUpdate older than its usual cadence)
x509_crl_fresh_since_seconds > 2 * 86400
# A CRL or responder is unreachable while the last good copy is still in use
revocation_fetch_success == 0
# A watched certificate is revoked
revocation_ocsp_status{status="revoked"} == 1 or revocation_crl_certificate_revoked == 1
# A TLS server stopped stapling
revocation_ocsp_stapled == 0
```

## Configuration

See [revocation-exporter.example.yaml](revocation-exporter.example.yaml).
Unknown keys are refused, so a misspelt setting is an error rather than
silently ignored.

```sh
revocation-exporter -config revocation-exporter.yaml          # serve :10062/metrics
revocation-exporter -config revocation-exporter.yaml -once    # one check, print metrics
```

`/healthz` answers 200 once the first check has finished.

The default port, 10062, is outside the range already taken on Prometheus's
[default port allocations](https://github.com/prometheus/prometheus/wiki/Default-port-allocations)
page (every port from 9790 to 9999 is listed there, 9793 by enix); it is not
registered yet. Register one before publishing.

## Running it

```sh
podman build -t revocation-exporter .
podman run -d -p 10062:10062 -v ./conf:/etc/revocation-exporter:ro revocation-exporter
```

The image is distroless and static, and runs as nonroot.

## Verification

`go test -race ./...` builds a CA in memory, serves its CRL and an OCSP
responder from `httptest`, and runs a TLS server with a stapled response.

`verify/podman-verify.sh` checks the **container image** against a real
OpenSSL PKI on the host:

- `openssl ca` issues a good and a revoked leaf;
- the CRL is served over HTTP;
- `openssl ocsp` answers with a delegated signer;
- `openssl s_server` staples.

Every expectation is a value OpenSSL produced: the serial numbers, the
cRLNumber and the nextUpdate.

## Limitations

- `ldap://` distribution points are skipped, not fetched.
- A delegated OCSP signer's certificate is checked against the issuer's
  signature, but not for the `id-kp-OCSPSigning` EKU or `nocheck`. This is the
  same as Go's `x/crypto/ocsp`.
- Delta CRLs and indirect CRLs (issuer ≠ CA) are not interpreted. A CRL from a
  different issuer than the certificate's is never used to call it revoked.
- A TLS source's chain is read without trusting it. The exporter inspects
  chains; it does not validate them for use.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
