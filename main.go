// revocation-exporter watches certificate revocation infrastructure: CRLs
// (fetched over HTTP or read from files, plus every CRL a certificate's
// distribution points name) and OCSP (the responders a certificate's
// Authority Information Access names, and responses stapled by TLS servers).
//
// The x509_crl_* metrics use enix x509-certificate-exporter's names, so
// alerts written for one read the other. Fetch health is reported beside
// every CRL and OCSP answer: a CRL that stopped being reachable is visible
// while its last good copy keeps counting down to nextUpdate.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "revocation-exporter.yaml", "configuration file")
	listen := flag.String("listen", ":9793", "address to serve /metrics on")
	once := flag.Bool("once", false, "run one check, print the metrics to stdout and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Error("configuration", "err", err)
		os.Exit(2)
	}

	chk := NewChecker(cfg, log)
	reg := prometheus.NewRegistry()
	reg.MustRegister(&Collector{c: chk, now: time.Now},
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "revocation_exporter_build_info", Help: "Always 1; the version is a label.",
		ConstLabels: prometheus.Labels{"version": version},
	}, func() float64 { return 1 }))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		chk.Check(ctx)
		mfs, err := reg.Gather()
		if err != nil {
			log.Error("gather", "err", err)
			os.Exit(1)
		}
		writeText(os.Stdout, mfs)
		return
	}

	go chk.Run(ctx)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		// Healthy once the first cycle has finished: before that /metrics
		// has no revocation data and a readiness probe should say so.
		if chk.Snapshot() == nil {
			http.Error(w, "first check not finished", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("listening", "addr", *listen, "version", version)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
