package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxLogSize bounds the log file, which normally lives in tmpfs.
const maxLogSize = 2 << 20

type cappedFile struct {
	mu   sync.Mutex
	f    *os.File
	size int64
}

func (c *cappedFile) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.size+int64(len(p)) > maxLogSize {
		if err := c.f.Truncate(0); err == nil {
			_, _ = c.f.Seek(0, io.SeekStart)
			c.size = 0
		}
	}
	n, err := c.f.Write(p)
	c.size += int64(n)
	return n, err
}

func newLogger(path, level string) (*slog.Logger, func(), error) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	var (
		w       io.Writer = os.Stderr
		closeFn           = func() {}
	)
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log: %w", err)
		}
		st, _ := f.Stat()
		cf := &cappedFile{f: f}
		if st != nil {
			cf.size = st.Size()
		}
		w = cf
		closeFn = func() { _ = f.Close() }
	}
	loc := systemLocation()
	h := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: lv,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.String("time", a.Value.Time().In(loc).Format("2006-01-02 15:04:05"))
			}
			return a
		},
	})
	return slog.New(h), closeFn, nil
}

// systemLocation prefers TZ / OpenWrt /etc/TZ so logs match `date` when
// /etc/localtime is missing and the Go runtime falls back to UTC.
func systemLocation() *time.Location {
	for _, src := range []string{os.Getenv("TZ"), readTZFile("/etc/TZ")} {
		if loc := parseOpenWRTTZ(src); loc != nil {
			return loc
		}
	}
	return time.Local
}

func readTZFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// POSIX/OpenWrt: name then signed offset added to local time to get UTC.
// "CST-8" => UTC = local-8h => local = UTC+8; "EST5" => local = UTC-5.
var openWRTTZRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9/_]*)(-?\d+)(?::(\d{2})(?::(\d{2}))?)?$`)

func parseOpenWRTTZ(s string) *time.Location {
	s = strings.TrimSpace(s)
	if s == "" || s == "UTC" || s == "GMT" {
		return nil
	}
	m := openWRTTZRe.FindStringSubmatch(s)
	if m == nil {
		if loc, err := time.LoadLocation(s); err == nil {
			return loc
		}
		return nil
	}
	hours, _ := strconv.Atoi(m[2])
	mins, _ := strconv.Atoi(m[3])
	secs, _ := strconv.Atoi(m[4])
	if hours < 0 {
		mins, secs = -mins, -secs
	}
	posix := hours*3600 + mins*60 + secs
	return time.FixedZone(m[1], -posix)
}
