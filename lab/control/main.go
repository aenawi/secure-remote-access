// Command control is the lab's control surface: a small HTTP server with the
// UI embedded in the binary, and a Docker socket. Every button on the page is
// one or more real commands run inside a real container, and every result comes
// back in the same shape the sandbox page on chapter 14 uses — the rung that
// decided it, the rule that did the deciding, and the numbers.
//
// It binds inside its own container and is published to loopback only. If the
// compose file has been changed to publish it anywhere else, it refuses to run.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed ui
var uiFS embed.FS

var (
	flagAddr     = flag.String("addr", envOr("LAB_ADDR", "0.0.0.0:8099"), "listen address inside the container")
	flagStateDir = flag.String("state", envOr("LAB_STATE_DIR", "/lab/state"), "shared state directory")
	flagApply    = flag.String("apply", "", "apply a named configuration and exit (day-one|typical|weak|hardened)")
	flagHealth   = flag.Bool("health", false, "exit 0 once the CA is written and the server answers")
	flagInsecure = flag.Bool("i-have-read-the-readme", false,
		"allow a non-loopback publish. Do not.")
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("[control] ")

	// The health check the coordination server waits on: it cannot start until
	// the certificate this server generates exists, because DERP needs TLS.
	if *flagHealth {
		if _, err := os.Stat(filepath.Join(*flagStateDir, "ca", "headscale.crt")); err != nil {
			os.Exit(1)
		}
		cl := &http.Client{Timeout: 2 * time.Second}
		resp, err := cl.Get("http://127.0.0.1:8099/api/meta")
		if err != nil {
			os.Exit(1)
		}
		resp.Body.Close()
		return
	}

	lab, err := NewLab()
	if err != nil {
		log.Fatalf("cannot reach Docker: %v", err)
	}
	defer lab.Close()

	ctl := NewController(lab, *flagStateDir)
	ctl.log = func(f string, a ...any) { log.Printf(f, a...) }

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ---- one-shot mode: `control -apply weak` ---------------------------
	// This is what `docker compose --profile weak up` runs. Same code path as
	// the button, so the two cannot drift.
	if *flagApply != "" {
		if err := ctl.waitForLab(ctx); err != nil {
			log.Fatalf("%v", err)
		}
		res := ctl.ApplyPreset(ctx, *flagApply)
		fmt.Println(mustJSON(res))
		if !res.OK {
			os.Exit(1)
		}
		return
	}

	// ---- the loopback guard ---------------------------------------------
	if err := guardBind(ctx, lab, *flagAddr, *flagInsecure); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}

	// ---- the lab's own CA ------------------------------------------------
	// Written before the coordination server starts, because DERP requires TLS
	// and a lab that needs you to have openssl is a lab with a prerequisite.
	if err := ensureCA(*flagStateDir); err != nil {
		log.Fatalf("cannot create the lab CA: %v", err)
	}
	log.Printf("lab CA ready in %s", filepath.Join(*flagStateDir, "ca"))

	// Read the lab before waiting on anything. The control server can be
	// restarted while the lab keeps running, and it should come back knowing
	// what is already there rather than pretending the lab is empty.
	go ctl.Observe(ctx)

	go func() {
		if err := ctl.Bootstrap(ctx); err != nil {
			log.Printf("bootstrap: %v", err)
			return
		}
		if ok := WaitFor(ctx, 4*time.Minute, 3*time.Second, func() bool {
			ns, err := ctl.nodes(ctx)
			return err == nil && len(ns) >= 3
		}); ok {
			ctl.EnsureTags(ctx)
			_ = ctl.applyPolicy(ctx)
			log.Printf("all three machines are registered and tagged")
		} else {
			log.Printf("not every machine registered — check `docker compose logs lab-ubuntu`")
		}
		ctl.Observe(ctx)
	}()

	srv := &http.Server{
		Addr:              *flagAddr,
		Handler:           routes(ctl),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		sh, cancel := ctxWithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()

	log.Printf("listening on %s — open http://localhost:8099", *flagAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("%v", err)
	}
	log.Printf("stopped")
}

// waitForLab is the small patience the one-shot mode needs: compose starts the
// configuration container as soon as the machines exist, not when they have
// finished joining.
func (c *Controller) waitForLab(ctx context.Context) error {
	var why string
	ok := WaitFor(ctx, 4*time.Minute, 3*time.Second, func() bool {
		if up, err := c.lab.RunningErr(ctx, "lab-vps"); !up {
			why = "lab-vps is not running"
			if err != nil {
				why += ": " + err.Error()
			}
			return false
		}
		if !c.lab.Running(ctx, "headscale") {
			why = "the coordination server is not running"
			return false
		}
		ns, err := c.nodes(ctx)
		if err != nil {
			why = "asking the coordination server for its nodes: " + err.Error()
			return false
		}
		if len(ns) < 3 {
			why = fmt.Sprintf("only %d of the three machines have registered", len(ns))
			return false
		}
		return true
	})
	if !ok {
		return fmt.Errorf("the lab did not come up in time — %s", why)
	}
	if key, err := readFileTrimmed(c.StateFile("authkey")); err == nil {
		c.untrustedKey = key
	}
	c.Observe(ctx)
	return nil
}

// ---------------------------------------------------------------------------
// The loopback guard
//
// The lab has no authentication, because nothing in it is reachable from off
// this machine. That is only true while it is published to loopback, so the
// server checks its own port bindings and refuses to run if somebody has
// changed them. An unauthenticated Docker-socket-holding control plane on
// 0.0.0.0 is a remote root shell with a nice UI.
// ---------------------------------------------------------------------------

func guardBind(ctx context.Context, lab *Lab, addr string, override bool) error {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
			return fmt.Errorf("-addr %s is neither loopback nor the container's own 0.0.0.0", addr)
		}
	}

	self := os.Getenv("HOSTNAME")
	if self == "" {
		log.Printf("cannot identify my own container, so I cannot check the publish; " +
			"make sure compose publishes 127.0.0.1:8099 only")
		return nil
	}
	binds, err := lab.PublishedBindings(ctx, self)
	if err != nil {
		log.Printf("cannot read my own port bindings (%v) — check the publish by hand", err)
		return nil
	}
	var bad []string
	for _, b := range binds {
		hostIP := ""
		if i := strings.LastIndex(b, " "); i >= 0 {
			hostIP, _, _ = net.SplitHostPort(b[i+1:])
		}
		if hostIP == "" || hostIP == "0.0.0.0" || hostIP == "::" {
			bad = append(bad, b)
			continue
		}
		if ip := net.ParseIP(hostIP); ip != nil && !ip.IsLoopback() {
			bad = append(bad, b)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	msg := fmt.Errorf(
		"this lab is published off loopback (%s). It has no authentication and it holds "+
			"the Docker socket, so anyone who can reach that address can run commands as "+
			"root on this machine. Change the ports: line in docker-compose.yml back to "+
			"\"127.0.0.1:8099:8099\"", strings.Join(bad, ", "))
	if override {
		log.Printf("WARNING: %v", msg)
		log.Printf("continuing because -i-have-read-the-readme was passed. You are on your own.")
		return nil
	}
	return msg
}

// ---------------------------------------------------------------------------
// The lab CA
// ---------------------------------------------------------------------------

func ensureCA(dir string) error {
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		return err
	}
	crt := filepath.Join(caDir, "headscale.crt")
	if _, err := os.Stat(crt); err == nil {
		return nil // already generated; `make reset` throws the volume away
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "secure-remote-access lab CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	srvTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "headscale"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"headscale", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("203.0.113.2"), net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	write := func(name string, blocks ...*pem.Block) error {
		f, err := os.OpenFile(filepath.Join(caDir, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		for _, b := range blocks {
			if err := pem.Encode(f, b); err != nil {
				return err
			}
		}
		return nil
	}
	if err := write("lab-ca.crt", &pem.Block{Type: "CERTIFICATE", Bytes: caDER}); err != nil {
		return err
	}
	// The chain, so a client that only has the leaf can still build a path.
	if err := write("headscale.crt",
		&pem.Block{Type: "CERTIFICATE", Bytes: srvDER},
		&pem.Block{Type: "CERTIFICATE", Bytes: caDER}); err != nil {
		return err
	}
	return write("headscale.key",
		&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

var (
	journalMu sync.Mutex
	journal   []string
)

func record(cmds []string) {
	if len(cmds) == 0 {
		return
	}
	journalMu.Lock()
	defer journalMu.Unlock()
	journal = append(journal, cmds...)
	if len(journal) > 400 {
		journal = journal[len(journal)-400:]
	}
}

func scriptText() string {
	journalMu.Lock()
	defer journalMu.Unlock()
	if len(journal) == 0 {
		return "# Nothing yet. Every switch you flip and every attack you run appends the\n" +
			"# real command here, in the order it happened.\n"
	}
	return "#!/usr/bin/env bash\n" +
		"# Everything this lab has done, in order. These are the same commands\n" +
		"# chapter 13 has you type by hand against three Lima VMs. Read before running.\n" +
		"set -euo pipefail\n\n" + strings.Join(journal, "\n") + "\n"
}

func routes(c *Controller) http.Handler {
	mux := http.NewServeMux()

	ui, err := fs.Sub(uiFS, "ui")
	if err != nil {
		log.Fatalf("embedded UI: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(ui)))

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	writeText := func(w http.ResponseWriter, s string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(s))
	}
	body := func(r *http.Request) map[string]any {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	str := func(m map[string]any, k, def string) string {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
		return def
	}

	mux.HandleFunc("/api/meta", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"catalog": Catalog,
			"presets": Presets,
			"grants":  Grants,
			"attacks": AttackList,
			// Everything /api/action will dispatch, which is a longer list than
			// AttackList: the board reports which of these has no set-piece, and
			// handing it the nine attacks was how `rotate-key` stayed invisible
			// to the tool built to notice exactly that.
			"actions":    ActionIDs(),
			"panels":     Panels,
			"groups":     AuditGroups,
			"lossSteps":  []int{0, 5, 20, 40},
			"delaySteps": []int{0, 40, 180},
		})
	})

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		c.Observe(r.Context())
		writeJSON(w, c.Snapshot())
	})

	mux.HandleFunc("/api/set", func(w http.ResponseWriter, r *http.Request) {
		m := body(r)
		res := c.Set(r.Context(), str(m, "path", ""), m["value"])
		record(res.Cmds)
		writeJSON(w, res)
	})

	mux.HandleFunc("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		m := body(r)
		res := c.Probe(r.Context(),
			str(m, "from", "lab-ubuntu"), str(m, "to", "lab-vps"), str(m, "port", "22"))
		record(res.Cmds)
		writeJSON(w, res)
	})

	mux.HandleFunc("/api/action", func(w http.ResponseWriter, r *http.Request) {
		m := body(r)
		id := str(m, "id", "")
		var res Result
		switch id {
		case "reset":
			res = c.Reset(r.Context())
		default:
			res = c.RunAttack(r.Context(), id)
		}
		record(res.Cmds)
		writeJSON(w, res)
	})

	mux.HandleFunc("/api/preset", func(w http.ResponseWriter, r *http.Request) {
		m := body(r)
		res := c.ApplyPreset(r.Context(), str(m, "id", ""))
		record(res.Cmds)
		writeJSON(w, res)
	})

	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, c.Audit(r.Context()))
	})

	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		writeText(w, c.RulesText(r.Context()))
	})
	mux.HandleFunc("/api/policy", func(w http.ResponseWriter, r *http.Request) {
		writeText(w, c.PolicyText())
	})
	mux.HandleFunc("/api/script", func(w http.ResponseWriter, r *http.Request) {
		writeText(w, scriptText())
	})

	mux.HandleFunc("/api/stream/status", c.StreamStatus)
	mux.HandleFunc("/api/stream/tcpdump", c.StreamTcpdump)
	mux.HandleFunc("/api/stream/logs", c.StreamLogs)
	mux.HandleFunc("/api/stream/stats", c.StreamStats)

	return mux
}

func readFileTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
