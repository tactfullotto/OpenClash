package script

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/rewrite"
)

func testRunner(t *testing.T) *Runner {
	t.Helper()
	r, err := NewRunner(t.TempDir(), "", "test", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rule(t *testing.T, match, name, typ, code string, requireBody bool) *rewrite.ScriptRule {
	t.Helper()
	r, err := rewrite.NewScriptRule(match, name, typ, "t", requireBody, false, 5, 0, nil, code)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDoneNoopAndAbort(t *testing.T) {
	r := testRunner(t)
	res, err := r.Run(rule(t, "^https://a", "n", "request", `$done({})`, false), Input{URL: "https://a/", Method: "GET", Headers: http.Header{}})
	if err != nil || res.Kind != ResultNoop {
		t.Fatalf("noop: %+v %v", res, err)
	}
	res, err = r.Run(rule(t, "^https://a", "n", "request", `$done()`, false), Input{URL: "https://a/", Method: "GET", Headers: http.Header{}})
	if err != nil || res.Kind != ResultAbort {
		t.Fatalf("abort: %+v %v", res, err)
	}
}

func TestRequestMutateAndShortCircuit(t *testing.T) {
	r := testRunner(t)
	code := `
$done({
  url: "https://b.example/new",
  headers: {"X-Script": "1"},
  body: "changed"
});
`
	res, err := r.Run(rule(t, "^https://a", "n", "request", code, true), Input{
		URL: "https://a/", Method: "POST", Headers: http.Header{"A": []string{"1"}}, Body: []byte("old"),
	})
	if err != nil || res.Kind != ResultMutate {
		t.Fatalf("%+v %v", res, err)
	}
	if res.URL != "https://b.example/new" || res.Headers.Get("X-Script") != "1" || string(res.Body) != "changed" {
		t.Fatalf("mutate = %+v", res)
	}

	code = `$done({response: {status: 200, headers: {"Content-Type": "text/plain"}, body: "local"}});`
	res, err = r.Run(rule(t, "^https://a", "n", "request", code, false), Input{URL: "https://a/", Method: "GET", Headers: http.Header{}})
	if err != nil || res.Response == nil || string(res.Response.Body) != "local" {
		t.Fatalf("short-circuit = %+v %v", res, err)
	}
}

func TestResponseBodyRewrite(t *testing.T) {
	r := testRunner(t)
	code := `
let body = JSON.parse($response.body);
body.vip = true;
$done({body: JSON.stringify(body), headers: {"X-Out": "1"}});
`
	res, err := r.Run(rule(t, "^https://a", "n", "response", code, true), Input{
		URL: "https://a/", Method: "GET", Headers: http.Header{},
		HasResponse: true, Status: 200, RespHeaders: http.Header{"Content-Type": []string{"application/json"}},
		RespBody: []byte(`{"vip":false}`),
	})
	if err != nil || res.Kind != ResultMutate || !strings.Contains(string(res.Body), `"vip":true`) {
		t.Fatalf("%+v %v body=%q", res, err, res.Body)
	}
	if res.Headers.Get("X-Out") != "1" {
		t.Errorf("headers = %v", res.Headers)
	}
}

func TestCaseInsensitiveHeaders(t *testing.T) {
	r := testRunner(t)
	code := `
let ua = $request.headers["user-agent"];
let ct = $response.headers["content-type"];
$response.headers["content-type"] = "text/plain";
$done({body: ua + "|" + ct, headers: $response.headers});
`
	res, err := r.Run(rule(t, "^https://a", "n", "response", code, true), Input{
		URL: "https://a/", Method: "GET",
		Headers:     http.Header{"User-Agent": []string{"TestAgent/1.0"}},
		HasResponse: true, Status: 200,
		RespHeaders: http.Header{"Content-Type": []string{"application/json"}},
		RespBody:    []byte(`{}`),
	})
	if err != nil || string(res.Body) != "TestAgent/1.0|application/json" {
		t.Fatalf("case-insensitive headers failed: %+v %v body=%q", res, err, res.Body)
	}
	if res.Headers.Get("Content-Type") != "text/plain" {
		t.Errorf("updated Content-Type = %q", res.Headers.Get("Content-Type"))
	}
}

func TestScriptInfiniteLoopTimeout(t *testing.T) {
	r := testRunner(t)
	rl, err := rewrite.NewScriptRule("^https://a", "loop", "request", "t", false, false, 1, 0, nil, `while (true) {}`)
	if err != nil {
		t.Fatal(err)
	}
	rl.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, err = r.Run(rl, Input{URL: "https://a/", Method: "GET", Headers: http.Header{}})
	if err == nil {
		t.Fatal("expected timeout error for infinite loop")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("infinite loop was not interrupted promptly: %v", elapsed)
	}
}

func TestPersistentStore(t *testing.T) {
	r := testRunner(t)
	code := `
$persistentStore.write("v1", "k1");
let v = $persistentStore.read("k1");
$done({body: v});
`
	res, err := r.Run(rule(t, "^https://a", "n", "response", code, true), Input{
		URL: "https://a/", Method: "GET", Headers: http.Header{},
		HasResponse: true, Status: 200, RespHeaders: http.Header{}, RespBody: []byte("{}"),
	})
	if err != nil || string(res.Body) != "v1" {
		t.Fatalf("%+v %v", res, err)
	}
	got, ok := r.Store.Read("k1")
	if !ok || got != "v1" {
		t.Errorf("store = %q %v", got, ok)
	}
	st1, err := os.Stat(r.Store.path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(15 * time.Millisecond)
	if !r.Store.Write("v1", "k1") {
		t.Fatal("unchanged write returned false")
	}
	st2, err := os.Stat(r.Store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Errorf("store file rewritten despite unchanged value")
	}
}

func TestHTTPClientAndNotification(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"from":"origin"}`))
	}))
	defer origin.Close()

	r := testRunner(t)
	code := `
$notification.post("t", "s", "b");
$httpClient.get({url: "` + origin.URL + `/redirect"}, (err, resp, data) => {
  if (err) { $done({body: err}); return; }
  $done({body: resp.status + ":" + data});
});
`
	res, err := r.Run(rule(t, "^https://a", "n", "response", code, true), Input{
		URL: "https://a/", Method: "GET", Headers: http.Header{},
		HasResponse: true, Status: 200, RespHeaders: http.Header{}, RespBody: []byte("{}"),
	})
	if err != nil || !strings.Contains(string(res.Body), `200:{"from":"origin"}`) {
		t.Fatalf("redirect follow failed: %+v %v body=%q", res, err, res.Body)
	}

	noRedirCode := `
$httpClient.get({url: "` + origin.URL + `/redirect", "auto-redirect": false}, (err, resp, data) => {
  if (err) { $done({body: err}); return; }
  $done({body: String(resp.status)});
});
`
	res, err = r.Run(rule(t, "^https://a", "n", "response", noRedirCode, true), Input{
		URL: "https://a/", Method: "GET", Headers: http.Header{},
		HasResponse: true, Status: 200, RespHeaders: http.Header{}, RespBody: []byte("{}"),
	})
	if err != nil || string(res.Body) != "302" {
		t.Fatalf("auto-redirect=false failed: %+v %v body=%q", res, err, res.Body)
	}
}

func TestLoaderPayload(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLoader(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	code, err := l.Load("demo", Provider{Payload: "console.log(1); $done({});"})
	if err != nil || !strings.Contains(code, "$done") {
		t.Fatalf("%q %v", code, err)
	}
	code2, err := l.Load("demo2", Provider{Path: filepath.Join(dir, "x.js"), Payload: "payload-only"})
	if err != nil || code2 != "payload-only" {
		t.Fatalf("%q %v", code2, err)
	}
}
