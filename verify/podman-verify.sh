#!/usr/bin/env bash
# End-to-end check of the container image against a REAL OpenSSL PKI.
#
# On the host: an OpenSSL CA with a delegated OCSP signer, two leaves (one
# revoked), its CRL served over HTTP, `openssl ocsp` answering for the CA and
# `openssl s_server` presenting the good leaf with a stapled OCSP response.
# In podman: the exporter image, run once (-once) against all of it. Every
# expectation below is a value OpenSSL produced, not one this code wrote.
#
# Needs: podman, openssl (3.x), python3. Usage: verify/podman-verify.sh [image]
set -euo pipefail

IMAGE="${1:-localhost/revocation-exporter:verify}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
HOSTNAME_IN_POD=host.containers.internal
P_HTTP=18080 P_OCSP=18888 P_TLS=18443
pids=()
cleanup() {
  for p in "${pids[@]+"${pids[@]}"}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true   # reap them, so bash does not print "Terminated"
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ "${1:-}" == "" ]]; then
  echo "== building $IMAGE"
  podman build -q -t "$IMAGE" "$HERE" >/dev/null
fi

cd "$WORK"
mkdir -p ca/newcerts www
: > ca/index.txt
echo 1000 > ca/serial
echo 1000 > ca/crlnumber
cat > ca.cnf <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = $WORK/ca
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $WORK/ca.pem
private_key = $WORK/ca.key
default_md = sha256
default_days = 90
default_crl_days = 7
policy = policy_any
copy_extensions = none
[ policy_any ]
commonName = supplied
[ leaf ]
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:vpn.verify.test, IP:127.0.0.1
crlDistributionPoints = URI:http://$HOSTNAME_IN_POD:$P_HTTP/ca.crl
authorityInfoAccess = OCSP;URI:http://$HOSTNAME_IN_POD:$P_OCSP/
[ ocsp_signer ]
basicConstraints = CA:false
keyUsage = digitalSignature
extendedKeyUsage = OCSPSigning
EOF

q() { "$@" >/dev/null 2>&1; }
q openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj "/O=Verify/CN=Verify Root CA" -keyout ca.key -out ca.pem \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
for n in good revoked ocsp; do
  q openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=$n.verify.test" -keyout "$n.key" -out "$n.csr"
done
q openssl ca -batch -config ca.cnf -extensions leaf -in good.csr -out good.pem
q openssl ca -batch -config ca.cnf -extensions leaf -in revoked.csr -out revoked.pem
q openssl ca -batch -config ca.cnf -extensions ocsp_signer -in ocsp.csr -out ocsp.pem
q openssl ca -batch -config ca.cnf -revoke revoked.pem -crl_reason keyCompromise
q openssl ca -batch -config ca.cnf -gencrl -out ca.crl.pem
openssl crl -in ca.crl.pem -outform DER -out www/ca.crl
cat good.pem ca.pem > good-chain.pem
cat revoked.pem ca.pem > revoked-chain.pem
crl_next=$(openssl crl -in ca.crl.pem -noout -nextupdate | cut -d= -f2)
crl_num=$(( $(openssl crl -in ca.crl.pem -noout -crlnumber | cut -d= -f2) ))

python3 -I -m http.server "$P_HTTP" --bind 0.0.0.0 --directory www >/dev/null 2>&1 & pids+=($!)
openssl ocsp -index ca/index.txt -port "$P_OCSP" -rsigner ocsp.pem -rkey ocsp.key \
  -CA ca.pem -nmin 60 -ignore_err >/dev/null 2>&1 & pids+=($!)
sleep 1
# The response the TLS server will staple, fetched from the responder above.
openssl ocsp -issuer ca.pem -cert good.pem -url "http://127.0.0.1:$P_OCSP/" \
  -respout staple.der -noverify >/dev/null 2>&1
openssl s_server -accept "$P_TLS" -cert good.pem -key good.key -cert_chain ca.pem \
  -status_file staple.der -quiet >/dev/null 2>&1 & pids+=($!)
sleep 1

mkdir -p conf
cp good-chain.pem revoked-chain.pem ca.pem conf/
cp ca.crl.pem conf/
cat > conf/config.yaml <<EOF
interval: 1m
timeout: 10s
crls:
  - file: /etc/revocation-exporter/ca.crl.pem
    issuer: /etc/revocation-exporter/ca.pem
certificates:
  - file: /etc/revocation-exporter/good-chain.pem
  - file: /etc/revocation-exporter/revoked-chain.pem
  - tls: $HOSTNAME_IN_POD:$P_TLS
    server_name: vpn.verify.test
EOF
chmod -R a+rX conf

echo "== running $IMAGE -once"
podman run --rm -v "$WORK/conf:/etc/revocation-exporter:ro,Z" "$IMAGE" \
  -config /etc/revocation-exporter/config.yaml -once > metrics.txt

fail=0
expect() {  # expect <description> <grep -E pattern on the metrics>
  if grep -Eq "$2" metrics.txt; then echo "  ok    $1"; else echo "  FAIL  $1   ($2)"; fail=1; fi
}
gs=$(openssl x509 -in good.pem -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f' | sed 's/^0*//')
rs=$(openssl x509 -in revoked.pem -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f' | sed 's/^0*//')
next_epoch=$(python3 -I -c 'import sys,calendar,time;print(calendar.timegm(time.strptime(sys.argv[1],"%b %d %H:%M:%S %Y GMT")))' "$crl_next")

echo "== expectations (OpenSSL's answers)"
expect "CRL from the distribution point parsed"  "^x509_crl_number\\{.*source_kind=\"distribution_point\".*\\} $crl_num$"
expect "CRL issuer labels"                       '^x509_crl_this_update\{.*issuer_CN="Verify Root CA".*issuer_O="Verify"'
expect "CRL not stale"                           '^x509_crl_stale\{.*source_kind="file".*\} 0$'
expect "CRL signature verified (file + issuer)"  '^revocation_crl_signature_valid\{.*source_kind="file".*\} 1$'
expect "CRL signature verified (chain issuer)"   '^revocation_crl_signature_valid\{.*source_kind="distribution_point".*\} 1$'
expect "one revoked entry"                       '^revocation_crl_revoked_certificates\{.*source_kind="file".*\} 1$'
expect "good leaf not on the CRL"                "^revocation_crl_certificate_revoked\\{.*serial_number=\"0*$gs\".*\\} 0$"
expect "revoked leaf on the CRL"                 "^revocation_crl_certificate_revoked\\{.*serial_number=\"0*$rs\".*\\} 1$"
expect "OCSP: good leaf is good"                 "^revocation_ocsp_status\\{.*serial_number=\"0*$gs\".*status=\"good\".*\\} 1$"
expect "OCSP: revoked leaf is revoked"           "^revocation_ocsp_status\\{.*serial_number=\"0*$rs\".*status=\"revoked\".*\\} 1$"
expect "OCSP delegated-signer signature valid"   '^revocation_ocsp_signature_valid\{.*\} 1$'
expect "TLS server stapled"                      "^revocation_ocsp_stapled\\{source=\"$HOSTNAME_IN_POD:$P_TLS\"\\} 1$"
expect "stapled status good"                     '^revocation_ocsp_stapled_status\{.*status="good"\} 1$'
expect "stapled signature valid"                 '^revocation_ocsp_stapled_signature_valid\{.*\} 1$'
expect "every fetch succeeded"                   '^revocation_fetch_success\{'
if grep -E '^revocation_fetch_success\{.*\} 0$' metrics.txt; then echo "  FAIL  a fetch failed (above)"; fail=1; fi
got_next=$(sed -n 's/^x509_crl_next_update{.*source_kind="file".*} //p' metrics.txt | head -1)
if python3 -I -c 'import sys; sys.exit(0 if abs(float(sys.argv[1]) - float(sys.argv[2])) < 1 else 1)' "${got_next:-nan}" "$next_epoch"; then
  echo "  ok    nextUpdate equals openssl's ($crl_next)"
else
  echo "  FAIL  nextUpdate $got_next, openssl says $next_epoch ($crl_next)"; fail=1
fi

if (( fail )); then
  echo "== FAILED; metrics follow"; grep -E '^(x509_crl|revocation_)' metrics.txt; exit 1
fi
echo "== PASSED"
