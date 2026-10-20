// Command openclash-mitm is the HTTP(S) rewrite sidecar for OpenClash. It
// decrypts the hostnames listed in Stash overrides, applies their url, header
// and body rewrites, and hands the traffic back to mihomo for routing.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/ca"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/clashpatch"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/proxy"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/rewrite"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/script"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/stash"
)

var version = "dev"

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		*l = append(*l, s)
	}
	return nil
}

type overrideFlags struct {
	files listFlag
	dirs  listFlag
	hosts listFlag
}

func (o *overrideFlags) register(fs *flag.FlagSet) {
	fs.Var(&o.files, "override", "Stash override file (repeatable)")
	fs.Var(&o.dirs, "override-dir", "directory of *.stoverride / *.yaml overrides (repeatable)")
	fs.Var(&o.hosts, "hosts", "extra MITM hostnames, comma separated (repeatable)")
}

func (o *overrideFlags) paths() []string {
	paths := append([]string(nil), o.files...)
	for _, d := range o.dirs {
		var found []string
		for _, pat := range []string{"*.stoverride", "*.yaml", "*.yml"} {
			m, _ := filepath.Glob(filepath.Join(d, pat))
			found = append(found, m...)
		}
		sort.Strings(found)
		paths = append(paths, found...)
	}
	return paths
}

func (o *overrideFlags) load(log *slog.Logger) []*stash.Override {
	overrides, errs := stash.LoadAll(o.paths())
	for _, err := range errs {
		log.Error("override skipped", "err", err)
	}
	return overrides
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "clash-patch":
		err = cmdClashPatch(os.Args[2:])
	case "gen-ca":
		err = cmdGenCA(os.Args[2:])
	case "ca-info":
		err = cmdCAInfo(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "openclash-mitm:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: openclash-mitm <command> [flags]

commands:
  run          start the MITM proxy
  clash-patch  inject the MITM proxy and routing rules into a mihomo config
  gen-ca       generate the root certificate
  ca-info      print root certificate details
  check        validate overrides and print a summary
  version      print the version
`)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var ov overrideFlags
	ov.register(fs)
	listen := fs.String("listen", "127.0.0.1:7899", "proxy listen address used by mihomo")
	upstream := fs.String("upstream", "127.0.0.1:7898", "mihomo mitm-out HTTP proxy, empty to dial directly")
	certListen := fs.String("cert-listen", "", "address serving the CA download page, empty to disable")
	caCert := fs.String("ca-cert", "/etc/openclash/mitm/ca.crt", "CA certificate (PEM)")
	caKey := fs.String("ca-key", "/etc/openclash/mitm/ca.key", "CA private key (PEM)")
	maxBody := fs.Int64("max-body-size", 4<<20, "largest body buffered for body-rewrite, bytes")
	skipVerify := fs.Bool("skip-server-cert-verify", false, "do not verify origin server certificates")
	bypassTTL := fs.Duration("bypass-ttl", 10*time.Minute, "tunnel a host without decryption after the client rejects the certificate, 0 disables")
	scriptDir := fs.String("script-dir", "/etc/openclash/mitm/scripts", "directory caching script-providers downloads")
	storeDir := fs.String("store-dir", "/etc/openclash/mitm/store", "directory for $persistentStore")
	logFile := fs.String("log-file", "", "log file, empty for stderr")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	_ = fs.Parse(args)

	log, closeLog, err := newLogger(*logFile, *logLevel)
	if err != nil {
		return err
	}
	defer closeLog()

	authority, generated, err := ca.LoadOrGenerate(*caCert, *caKey)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	if generated {
		log.Info("generated new root certificate", "cert", *caCert)
	}
	log.Info("root certificate loaded", "name", authority.Cert.Subject.CommonName, "sha1", authority.Fingerprint())

	runner, err := script.NewRunner(*storeDir, *upstream, version, *skipVerify, log)
	if err != nil {
		return fmt.Errorf("script store: %w", err)
	}
	loader, err := script.NewLoader(*scriptDir, runner.HTTP.Client)
	if err != nil {
		return fmt.Errorf("script dir: %w", err)
	}
	compileOpts := &stash.CompileOptions{Loader: loader}

	compile := func() *rewrite.Engine {
		overrides := ov.load(log)
		engine, warns := stash.Compile(overrides, ov.hosts, compileOpts)
		for _, w := range warns {
			log.Warn("override", "warning", w.String())
		}
		log.Info("rules loaded", "overrides", len(overrides), "url-rewrite", len(engine.URL),
			"header-rewrite", len(engine.Header), "body-rewrite", len(engine.Body), "script", len(engine.Scripts))
		return engine
	}
	srv := proxy.New(proxy.Config{
		Listen:               *listen,
		Upstream:             *upstream,
		SkipServerCertVerify: *skipVerify,
		MaxBodySize:          *maxBody,
		BypassTTL:            *bypassTTL,
	}, authority, compile(), runner, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Info("reloading overrides")
			srv.SetEngine(compile())
		}
	}()

	var wg sync.WaitGroup
	if *certListen != "" {
		cs := &http.Server{Addr: *certListen, Handler: proxy.CertHandler(authority), ReadHeaderTimeout: 10 * time.Second}
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("certificate page listening", "addr", *certListen)
			if err := cs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("certificate page stopped", "err", err)
			}
		}()
		go func() { <-ctx.Done(); _ = cs.Close() }()
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	log.Info("openclash-mitm started", "version", version, "listen", *listen, "upstream", *upstream)
	err = srv.Serve(ctx, ln)
	stop()
	wg.Wait()
	log.Info("openclash-mitm stopped")
	return err
}

func cmdClashPatch(args []string) error {
	fs := flag.NewFlagSet("clash-patch", flag.ExitOnError)
	var ov overrideFlags
	ov.register(fs)
	config := fs.String("config", "", "mihomo config file to patch in place")
	enginePort := fs.Int("engine-port", 7899, "MITM proxy port")
	outPort := fs.Int("out-port", 7898, "mitm-out listener port")
	blockQUIC := fs.Bool("block-quic", true, "reject UDP/443 to decrypted hosts")
	var src listFlag
	fs.Var(&src, "src", "LAN client IP/CIDR to decrypt, comma separated (repeatable); empty for all")
	_ = fs.Parse(args)
	if *config == "" {
		return errors.New("--config is required")
	}
	log, closeLog, _ := newLogger("", "info")
	defer closeLog()
	overrides := ov.load(log)
	res, err := clashpatch.PatchFile(*config, overrides, clashpatch.Options{
		EnginePort:  *enginePort,
		OutPort:     *outPort,
		SourceCIDRs: src,
		ExtraHosts:  ov.hosts,
		BlockQUIC:   *blockQUIC,
	})
	if err != nil {
		return err
	}
	_, compileWarns := stash.Compile(overrides, ov.hosts, nil)
	for _, w := range compileWarns {
		fmt.Println("WARN", w.String())
	}
	for _, w := range res.Warnings {
		fmt.Println("WARN", w)
	}
	fmt.Printf("OK hosts=%d rules=%d rule-providers=%d\n", res.Hosts, res.Rules, res.RuleProviders)
	return nil
}

func cmdGenCA(args []string) error {
	fs := flag.NewFlagSet("gen-ca", flag.ExitOnError)
	certPath := fs.String("cert", "/etc/openclash/mitm/ca.crt", "CA certificate output")
	keyPath := fs.String("key", "/etc/openclash/mitm/ca.key", "CA private key output")
	cn := fs.String("cn", "", "certificate common name")
	force := fs.Bool("force", false, "overwrite an existing CA")
	_ = fs.Parse(args)
	if !*force {
		if _, err := os.Stat(*certPath); err == nil {
			return fmt.Errorf("%s exists, use --force to replace it", *certPath)
		}
	}
	if err := ca.Generate(*certPath, *keyPath, *cn); err != nil {
		return err
	}
	return printCAInfo(os.Stdout, *certPath, *keyPath)
}

func cmdCAInfo(args []string) error {
	fs := flag.NewFlagSet("ca-info", flag.ExitOnError)
	certPath := fs.String("cert", "/etc/openclash/mitm/ca.crt", "CA certificate")
	keyPath := fs.String("key", "/etc/openclash/mitm/ca.key", "CA private key")
	_ = fs.Parse(args)
	return printCAInfo(os.Stdout, *certPath, *keyPath)
}

func printCAInfo(w io.Writer, certPath, keyPath string) error {
	a, err := ca.Load(certPath, keyPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "name=%s\nsha1=%s\nnot_after=%s\n", a.Cert.Subject.CommonName, a.Fingerprint(), a.Cert.NotAfter.Format(time.DateOnly))
	return nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var ov overrideFlags
	ov.register(fs)
	_ = fs.Parse(args)
	overrides, errs := stash.LoadAll(ov.paths())
	for _, err := range errs {
		fmt.Println("ERROR", err)
	}
	loader, _ := script.NewLoader(os.TempDir(), nil)
	engine, warns := stash.Compile(overrides, ov.hosts, &stash.CompileOptions{Loader: loader})
	for _, w := range warns {
		fmt.Println("WARN", w.String())
	}
	fmt.Printf("overrides=%d mitm-hosts=%d url-rewrite=%d header-rewrite=%d body-rewrite=%d script=%d\n",
		len(overrides), len(stash.MITMHosts(overrides, ov.hosts)), len(engine.URL), len(engine.Header), len(engine.Body), len(engine.Scripts))
	if len(errs) > 0 {
		return errors.New("some overrides failed to load")
	}
	return nil
}
