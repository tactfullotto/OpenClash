package script_test

import (
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/rewrite"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/script"
)

func TestURLPolyfill(t *testing.T) {
	dir := t.TempDir()
	r, err := script.NewRunner(filepath.Join(dir, "store"), "", "test", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	code := `
const u = new URL("https://weatherkit.apple.com/api/v2/weather/zh-Hans/1/2?dataSets=airQuality");
if (u.hostname !== "weatherkit.apple.com") throw new Error("host "+u.hostname);
if (u.pathname.indexOf("/api/v2/weather") !== 0) throw new Error("path "+u.pathname);
u.searchParams.set("token", "abc");
if (u.searchParams.get("token") !== "abc") throw new Error("sp");
if (String(u).indexOf("token=abc") < 0) throw new Error("href "+u);
$done({response:{status:200,body:"ok"}});
`
	rule, err := rewrite.NewScriptRule("^https://x", "url-poly", "request", "", false, false, 5, 0, nil, code)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(rule, script.Input{URL: "https://x/", Method: "GET", Headers: http.Header{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Response == nil || string(res.Response.Body) != "ok" {
		t.Fatalf("res=%+v", res)
	}
}
