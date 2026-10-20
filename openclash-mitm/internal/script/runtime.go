package script

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/rewrite"
)

const maxConcurrentScripts = 16

var polyfillProg = goja.MustCompile("polyfills.js", polyfillJS, false)

// ResultKind is how a script finished.
type ResultKind int

const (
	// ResultNoop means $done({}) — leave the message unchanged.
	ResultNoop ResultKind = iota
	// ResultAbort means $done() with no argument — interrupt the exchange.
	ResultAbort
	// ResultMutate means $done({...}) with fields to apply.
	ResultMutate
)

// DoneResponse is a synthetic response from a request script.
type DoneResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// Result is the outcome of running one script.
type Result struct {
	Kind     ResultKind
	URL      string
	Headers  http.Header // nil = unchanged
	Body     []byte      // nil = unchanged; empty slice may be intentional
	BodySet  bool
	Status   int // response scripts; 0 = unchanged
	Response *DoneResponse
}

// Input is the HTTP message passed into the script.
type Input struct {
	URL     string
	Method  string
	Headers http.Header
	Body    []byte
	// Response fields (response scripts only).
	Status      int
	RespHeaders http.Header
	RespBody    []byte
	HasResponse bool
}

// Runner executes Stash-compatible JavaScript rewrite scripts.
type Runner struct {
	Store      *Store
	HTTP       *HTTPClient
	Log        *slog.Logger
	Version    string
	SkipVerify bool

	sem       chan struct{}
	progCache sync.Map // string (code) -> *goja.Program
}

// NewRunner builds a script runner. storeDir and upstream may be empty.
func NewRunner(storeDir, upstream, version string, skipVerify bool, log *slog.Logger) (*Runner, error) {
	if log == nil {
		log = slog.Default()
	}
	var store *Store
	if storeDir != "" {
		s, err := NewStore(storeDir)
		if err != nil {
			return nil, err
		}
		store = s
	} else {
		store = &Store{data: map[string]string{}}
	}
	if version == "" {
		version = "dev"
	}
	return &Runner{
		Store:      store,
		HTTP:       newHTTPClient(upstream, skipVerify),
		Log:        log,
		Version:    version,
		SkipVerify: skipVerify,
		sem:        make(chan struct{}, maxConcurrentScripts),
	}, nil
}

func (r *Runner) compileProgram(name, code string) (*goja.Program, error) {
	if v, ok := r.progCache.Load(code); ok {
		return v.(*goja.Program), nil
	}
	prog, err := goja.Compile(name, code, false)
	if err != nil {
		return nil, err
	}
	r.progCache.Store(code, prog)
	return prog, nil
}

// Run executes rule against in and returns the $done result.
func (r *Runner) Run(rule *rewrite.ScriptRule, in Input) (Result, error) {
	if rule == nil || rule.Code == "" {
		return Result{Kind: ResultNoop}, nil
	}
	prog, err := r.compileProgram(rule.Name, rule.Code)
	if err != nil {
		return Result{Kind: ResultNoop}, err
	}
	timeout := rule.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	if r.sem != nil {
		r.sem <- struct{}{}
		defer func() { <-r.sem }()
	}

	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	var (
		mu     sync.Mutex
		vmRef  *goja.Runtime
		done   Result
		doneOK bool
		runErr error
	)
	doneCh := make(chan struct{})
	finish := func(res Result) {
		mu.Lock()
		already := doneOK
		if !doneOK {
			done = res
			doneOK = true
		}
		mu.Unlock()
		if already {
			return
		}
		close(doneCh)
		loop.StopNoWait()
	}

	loop.Start()
	loop.RunOnLoop(func(vm *goja.Runtime) {
		mu.Lock()
		vmRef = vm
		mu.Unlock()
		defer func() {
			if rec := recover(); rec != nil {
				mu.Lock()
				if runErr == nil {
					runErr = fmt.Errorf("script panic: %v", rec)
				}
				mu.Unlock()
				finish(Result{Kind: ResultNoop})
			}
		}()
		if err := r.install(vm, loop, rule, in, finish); err != nil {
			mu.Lock()
			if runErr == nil {
				runErr = err
			}
			mu.Unlock()
			finish(Result{Kind: ResultNoop})
			return
		}
		if _, err := vm.RunProgram(prog); err != nil {
			mu.Lock()
			if runErr == nil {
				runErr = err
			}
			mu.Unlock()
			finish(Result{Kind: ResultNoop})
		}
	})

	timer := time.AfterFunc(timeout, func() {
		mu.Lock()
		already := doneOK
		v := vmRef
		if !already && runErr == nil {
			runErr = fmt.Errorf("script timed out after %v", timeout)
		}
		mu.Unlock()
		if !already {
			r.Log.Warn("script timed out", "name", rule.Name, "timeout", timeout)
			if v != nil {
				v.Interrupt("script timed out")
			}
			finish(Result{Kind: ResultNoop})
		}
	})
	<-doneCh
	timer.Stop()
	loop.Stop()

	mu.Lock()
	defer mu.Unlock()
	if runErr != nil {
		return Result{Kind: ResultNoop}, runErr
	}
	if !doneOK {
		return Result{Kind: ResultNoop}, errors.New("script did not call $done")
	}
	return done, nil
}

func (r *Runner) install(vm *goja.Runtime, loop *eventloop.EventLoop, rule *rewrite.ScriptRule, in Input, finish func(Result)) error {
	installPolyfills(vm)

	reqObj := vm.NewObject()
	_ = reqObj.Set("url", in.URL)
	_ = reqObj.Set("method", in.Method)
	_ = reqObj.Set("headers", headersToObject(vm, in.Headers))
	if rule.RequireBody {
		_ = reqObj.Set("body", bodyToJS(vm, in.Body, rule.BinaryMode))
	}
	if err := vm.Set("$request", reqObj); err != nil {
		return err
	}

	if in.HasResponse {
		respObj := vm.NewObject()
		_ = respObj.Set("status", in.Status)
		_ = respObj.Set("headers", headersToObject(vm, in.RespHeaders))
		if rule.RequireBody {
			_ = respObj.Set("body", bodyToJS(vm, in.RespBody, rule.BinaryMode))
		}
		if err := vm.Set("$response", respObj); err != nil {
			return err
		}
	}

	scriptObj := vm.NewObject()
	_ = scriptObj.Set("name", rule.Name)
	_ = scriptObj.Set("type", rule.Phase.String())
	_ = scriptObj.Set("startTime", time.Now().UnixMilli())
	_ = vm.Set("$script", scriptObj)
	_ = vm.Set("$argument", argumentToJS(vm, rule.Argument))

	env := vm.NewObject()
	_ = env.Set("stash-build", r.Version)
	_ = env.Set("stash-version", r.Version)
	_ = env.Set("language", "en")
	_ = env.Set("system", "OpenClash")
	_ = vm.Set("$environment", env)

	_ = vm.Set("$done", func(call goja.FunctionCall) goja.Value {
		finish(parseDone(vm, rule, call))
		return goja.Undefined()
	})

	storeObj := vm.NewObject()
	_ = storeObj.Set("read", func(call goja.FunctionCall) goja.Value {
		key := ""
		if len(call.Arguments) > 0 && !goja.IsUndefined(call.Arguments[0]) && !goja.IsNull(call.Arguments[0]) {
			key = call.Arguments[0].String()
		} else {
			key = rule.Name
		}
		v, ok := r.Store.Read(key)
		if !ok {
			return goja.Null()
		}
		return vm.ToValue(v)
	})
	_ = storeObj.Set("write", func(call goja.FunctionCall) goja.Value {
		var value string
		key := rule.Name
		if len(call.Arguments) == 0 {
			return vm.ToValue(false)
		}
		if goja.IsNull(call.Arguments[0]) || goja.IsUndefined(call.Arguments[0]) {
			if len(call.Arguments) > 1 {
				key = call.Arguments[1].String()
			}
			return vm.ToValue(r.Store.Delete(key))
		}
		value = call.Arguments[0].String()
		if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
			key = call.Arguments[1].String()
		}
		return vm.ToValue(r.Store.Write(value, key))
	})
	_ = vm.Set("$persistentStore", storeObj)

	notify := vm.NewObject()
	_ = notify.Set("post", func(call goja.FunctionCall) goja.Value {
		title, subtitle, body := "", "", ""
		if len(call.Arguments) > 0 {
			title = call.Arguments[0].String()
		}
		if len(call.Arguments) > 1 {
			subtitle = call.Arguments[1].String()
		}
		if len(call.Arguments) > 2 {
			body = call.Arguments[2].String()
		}
		r.Log.Info("notification", "title", title, "subtitle", subtitle, "body", body, "script", rule.Name)
		return goja.Undefined()
	})
	_ = vm.Set("$notification", notify)

	console := vm.NewObject()
	_ = console.Set("log", func(call goja.FunctionCall) goja.Value {
		parts := make([]string, 0, len(call.Arguments))
		for _, a := range call.Arguments {
			parts = append(parts, stringifyJS(a))
		}
		r.Log.Info("script", "name", rule.Name, "log", strings.Join(parts, " "))
		return goja.Undefined()
	})
	_ = vm.Set("console", console)

	httpObj := vm.NewObject()
	for _, method := range []string{"get", "post", "put", "delete", "head", "options", "patch"} {
		m := method
		_ = httpObj.Set(m, func(call goja.FunctionCall) goja.Value {
			return r.bindHTTP(vm, loop, m, call)
		})
	}
	_ = vm.Set("$httpClient", httpObj)

	return nil
}

func (r *Runner) bindHTTP(vm *goja.Runtime, loop *eventloop.EventLoop, method string, call goja.FunctionCall) goja.Value {
	if len(call.Arguments) < 1 {
		return goja.Undefined()
	}
	opts := call.Arguments[0].Export()
	var cb goja.Callable
	if len(call.Arguments) > 1 {
		if fn, ok := goja.AssertFunction(call.Arguments[1]); ok {
			cb = fn
		}
	}
	go func() {
		resp, errMsg := r.HTTP.do(method, opts)
		loop.RunOnLoop(func(runtime *goja.Runtime) {
			if cb == nil {
				return
			}
			if errMsg != "" {
				_, _ = cb(goja.Undefined(), runtime.ToValue(errMsg), goja.Null(), goja.Null())
				return
			}
			respObj := runtime.NewObject()
			_ = respObj.Set("status", resp.Status)
			hObj := runtime.NewObject()
			for k, v := range resp.Headers {
				_ = hObj.Set(k, v)
			}
			wrapCaseInsensitiveHeaders(runtime, hObj)
			_ = respObj.Set("headers", hObj)
			var data goja.Value
			switch b := resp.Body.(type) {
			case []byte:
				data = bytesToUint8Array(runtime, b)
			case string:
				data = runtime.ToValue(b)
			default:
				data = runtime.ToValue(fmt.Sprint(b))
			}
			_, _ = cb(goja.Undefined(), goja.Null(), respObj, data)
		})
	}()
	return goja.Undefined()
}

func parseDone(vm *goja.Runtime, rule *rewrite.ScriptRule, call goja.FunctionCall) Result {
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) {
		return Result{Kind: ResultAbort}
	}
	if goja.IsNull(call.Arguments[0]) {
		return Result{Kind: ResultNoop}
	}
	exp := call.Arguments[0].Export()
	m, ok := exp.(map[string]any)
	if !ok {
		// $done(non-object) treated as noop
		return Result{Kind: ResultNoop}
	}
	if len(m) == 0 {
		return Result{Kind: ResultNoop}
	}
	res := Result{Kind: ResultMutate}
	if u, ok := m["url"].(string); ok {
		res.URL = u
	}
	if st, ok := asInt(m["status"]); ok {
		res.Status = st
	}
	if h, ok := m["headers"]; ok {
		res.Headers = anyToHeader(h)
	}
	if b, ok := m["body"]; ok {
		res.Body = anyToBody(vm, b, rule.BinaryMode)
		res.BodySet = true
	}
	if raw, ok := m["response"]; ok {
		if rm, ok := raw.(map[string]any); ok {
			dr := &DoneResponse{Status: http.StatusOK, Headers: make(http.Header)}
			if st, ok := asInt(rm["status"]); ok {
				dr.Status = st
			}
			if h, ok := rm["headers"]; ok {
				dr.Headers = anyToHeader(h)
			}
			if b, ok := rm["body"]; ok {
				dr.Body = anyToBody(vm, b, rule.BinaryMode)
			}
			res.Response = dr
		}
	}
	return res
}

func headersToObject(vm *goja.Runtime, h http.Header) *goja.Object {
	obj := vm.NewObject()
	if h == nil {
		return obj
	}
	for k, vs := range h {
		if len(vs) == 1 {
			_ = obj.Set(k, vs[0])
		} else if len(vs) > 1 {
			_ = obj.Set(k, vs)
		}
	}
	wrapCaseInsensitiveHeaders(vm, obj)
	return obj
}

func wrapCaseInsensitiveHeaders(vm *goja.Runtime, obj *goja.Object) {
	if fn, ok := goja.AssertFunction(vm.Get("__ciHeaders")); ok {
		_, _ = fn(goja.Undefined(), obj)
	}
}

func bodyToJS(vm *goja.Runtime, body []byte, binary bool) goja.Value {
	if binary {
		return bytesToUint8Array(vm, body)
	}
	if body == nil {
		return goja.Null()
	}
	if utf8.Valid(body) {
		return vm.ToValue(string(body))
	}
	return bytesToUint8Array(vm, body)
}

func bytesToUint8Array(vm *goja.Runtime, b []byte) goja.Value {
	if b == nil {
		b = []byte{}
	}
	ctor, ok := goja.AssertConstructor(vm.Get("Uint8Array"))
	if !ok {
		return vm.ToValue(b)
	}
	arr, err := ctor(nil, vm.ToValue(len(b)))
	if err != nil || arr == nil {
		return vm.ToValue(b)
	}
	if bufVal := arr.Get("buffer"); bufVal != nil && !goja.IsUndefined(bufVal) {
		if ab, ok := bufVal.Export().(goja.ArrayBuffer); ok {
			copy(ab.Bytes(), b)
			return arr
		}
	}
	for i, v := range b {
		_ = arr.Set(fmt.Sprintf("%d", i), int(v))
	}
	return arr
}

func anyToHeader(v any) http.Header {
	h := make(http.Header)
	switch m := v.(type) {
	case map[string]any:
		for k, val := range m {
			switch vv := val.(type) {
			case string:
				h.Set(k, vv)
			case []any:
				for _, item := range vv {
					h.Add(k, fmt.Sprint(item))
				}
			default:
				h.Set(k, fmt.Sprint(vv))
			}
		}
	case map[string]string:
		for k, val := range m {
			h.Set(k, val)
		}
	}
	return h
}

func anyToBody(vm *goja.Runtime, v any, binaryPrefer bool) []byte {
	switch b := v.(type) {
	case string:
		return []byte(b)
	case []byte:
		return b
	case goja.ArrayBuffer:
		return b.Bytes()
	case []any:
		out := make([]byte, 0, len(b))
		for _, x := range b {
			if n, ok := asInt(x); ok {
				out = append(out, byte(n))
			}
		}
		return out
	default:
		// Uint8Array export is often map[string]any or a typed slice
		if o, ok := v.(map[string]any); ok {
			if buf, ok := o["buffer"]; ok {
				return anyToBody(vm, buf, true)
			}
		}
		// try JSON for objects/arrays (common in scripts)
		if binaryPrefer {
			if s, ok := v.(string); ok {
				return []byte(s)
			}
		}
		jb, err := json.Marshal(v)
		if err == nil {
			return jb
		}
		return []byte(fmt.Sprint(v))
	}
}

func argumentToJS(vm *goja.Runtime, arg any) goja.Value {
	if arg == nil {
		return goja.Undefined()
	}
	switch v := arg.(type) {
	case string:
		return vm.ToValue(v)
	default:
		return vm.ToValue(v)
	}
}

func stringifyJS(v goja.Value) string {
	if v == nil || goja.IsUndefined(v) {
		return "undefined"
	}
	if goja.IsNull(v) {
		return "null"
	}
	exp := v.Export()
	switch t := exp.(type) {
	case string:
		return t
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

func installPolyfills(vm *goja.Runtime) {
	_ = vm.Set("atob", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return vm.ToValue("")
		}
		b, err := base64.StdEncoding.DecodeString(call.Arguments[0].String())
		if err != nil {
			panic(vm.NewTypeError("atob: invalid base64"))
		}
		return vm.ToValue(string(b))
	})
	_ = vm.Set("btoa", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return vm.ToValue("")
		}
		return vm.ToValue(base64.StdEncoding.EncodeToString([]byte(call.Arguments[0].String())))
	})

	_, _ = vm.RunProgram(polyfillProg)
}

const polyfillJS = `
(function(g) {
  g.__ciHeaders = function(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    var proto = Object.create(Object.prototype);
    Object.keys(obj).forEach(function(k) {
      var lk = k.toLowerCase();
      if (lk !== k && !Object.prototype.hasOwnProperty.call(obj, lk)) {
        Object.defineProperty(proto, lk, {
          configurable: true,
          enumerable: false,
          get: function() { return this[k]; },
          set: function(v) { this[k] = v; }
        });
      }
    });
    if (Object.setPrototypeOf) Object.setPrototypeOf(obj, proto);
    return obj;
  };
  if (typeof g.TextEncoder === 'undefined') {
    g.TextEncoder = function TextEncoder() {};
    g.TextEncoder.prototype.encode = function(str) {
      str = String(str || '');
      var utf8 = unescape(encodeURIComponent(str));
      var arr = new Uint8Array(utf8.length);
      for (var i = 0; i < utf8.length; i++) arr[i] = utf8.charCodeAt(i);
      return arr;
    };
  }
  if (typeof g.TextDecoder === 'undefined') {
    g.TextDecoder = function TextDecoder(label, options) {
      this.label = label || 'utf-8';
      this.fatal = !!(options && options.fatal);
    };
    g.TextDecoder.prototype.decode = function(input) {
      if (input == null) return '';
      var bytes;
      if (input instanceof ArrayBuffer) bytes = new Uint8Array(input);
      else if (ArrayBuffer.isView && ArrayBuffer.isView(input)) bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
      else if (input instanceof Uint8Array) bytes = input;
      else bytes = new Uint8Array(input);
      var str = '';
      for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
      try { return decodeURIComponent(escape(str)); } catch (e) { return str; }
    };
  }
  if (typeof g.URLSearchParams === 'undefined') {
    g.URLSearchParams = function URLSearchParams(init) {
      this._map = {};
      var self = this;
      function appendPair(k, v) {
        k = String(k); v = String(v);
        if (!Object.prototype.hasOwnProperty.call(self._map, k)) self._map[k] = [];
        self._map[k].push(v);
      }
      if (typeof init === 'string') {
        var q = init.charAt(0) === '?' ? init.slice(1) : init;
        if (q) q.split('&').forEach(function(pair) {
          if (!pair) return;
          var i = pair.indexOf('=');
          var k = i < 0 ? pair : pair.slice(0, i);
          var v = i < 0 ? '' : pair.slice(i + 1);
          try { k = decodeURIComponent(k.replace(/\+/g, ' ')); } catch (e) {}
          try { v = decodeURIComponent(v.replace(/\+/g, ' ')); } catch (e) {}
          appendPair(k, v);
        });
      } else if (init && typeof init === 'object') {
        Object.keys(init).forEach(function(k) { appendPair(k, init[k]); });
      }
    };
    g.URLSearchParams.prototype.get = function(k) {
      var a = this._map[String(k)]; return a && a.length ? a[0] : null;
    };
    g.URLSearchParams.prototype.getAll = function(k) { return (this._map[String(k)] || []).slice(); };
    g.URLSearchParams.prototype.has = function(k) { return Object.prototype.hasOwnProperty.call(this._map, String(k)); };
    g.URLSearchParams.prototype.set = function(k, v) { this._map[String(k)] = [String(v)]; };
    g.URLSearchParams.prototype.append = function(k, v) {
      k = String(k); v = String(v);
      if (!Object.prototype.hasOwnProperty.call(this._map, k)) this._map[k] = [];
      this._map[k].push(v);
    };
    g.URLSearchParams.prototype.delete = function(k) { delete this._map[String(k)]; };
    g.URLSearchParams.prototype.toString = function() {
      var out = [];
      Object.keys(this._map).forEach(function(k) {
        this._map[k].forEach(function(v) {
          out.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
        });
      }, this);
      return out.join('&');
    };
  }
  if (typeof g.URL === 'undefined') {
    g.URL = function URL(url, base) {
      url = String(url || '');
      if (base) {
        var b = new g.URL(String(base));
        if (url.charAt(0) === '/') url = b.protocol + '//' + b.host + url;
        else if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
          var path = b.pathname.replace(/\/[^\/]*$/, '/');
          url = b.protocol + '//' + b.host + path + url;
        }
      }
      var m = String(url).match(/^([a-zA-Z][a-zA-Z0-9+.-]*:)(\/\/)?([^\/?#]*)(\/[^?#]*)?(\?[^#]*)?(#.*)?$/);
      if (!m) throw new TypeError('Invalid URL: ' + url);
      this.protocol = m[1];
      this.username = '';
      this.password = '';
      var authHost = m[3] || '';
      var at = authHost.lastIndexOf('@');
      if (at >= 0) {
        var auth = authHost.slice(0, at);
        authHost = authHost.slice(at + 1);
        var colon = auth.indexOf(':');
        if (colon >= 0) { this.username = auth.slice(0, colon); this.password = auth.slice(colon + 1); }
        else this.username = auth;
      }
      this.host = authHost;
      var h = authHost.match(/^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/);
      this.hostname = h ? h[1] : authHost;
      this.port = h && h[2] ? h[2] : '';
      this.pathname = m[4] || '/';
      this.search = m[5] || '';
      this.hash = m[6] || '';
      this.origin = this.protocol + '//' + this.host;
      var self = this;
      var params = new g.URLSearchParams(this.search);
      Object.defineProperty(this, 'searchParams', {
        get: function() { return params; }
      });
      var syncSearch = function() {
        var q = params.toString();
        self.search = q ? ('?' + q) : '';
      };
      var _set = params.set.bind(params);
      var _append = params.append.bind(params);
      var _del = params.delete.bind(params);
      params.set = function(k, v) { _set(k, v); syncSearch(); };
      params.append = function(k, v) { _append(k, v); syncSearch(); };
      params.delete = function(k) { _del(k); syncSearch(); };
    };
    g.URL.prototype.toString = function() {
      return this.protocol + '//' + this.host + this.pathname + this.search + this.hash;
    };
    g.URL.prototype.toJSON = function() { return this.toString(); };
    Object.defineProperty(g.URL.prototype, 'href', {
      get: function() { return this.toString(); },
      set: function(v) {
        var u = new g.URL(String(v));
        this.protocol = u.protocol; this.host = u.host; this.hostname = u.hostname;
        this.port = u.port; this.pathname = u.pathname; this.search = u.search;
        this.hash = u.hash; this.origin = u.origin; this.username = u.username; this.password = u.password;
      }
    });
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
`
