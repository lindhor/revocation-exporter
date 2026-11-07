package main

import (
	"io"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// writeText prints gathered metrics in the Prometheus text format (-once).
func writeText(w io.Writer, mfs []*dto.MetricFamily) {
	enc := expfmt.NewEncoder(w, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		_ = enc.Encode(mf)
	}
}
