package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/ca"
)

var certPage = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenClash MITM 证书</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:640px;margin:0 auto;padding:24px;line-height:1.6;color:#222}
a.btn{display:block;text-align:center;padding:14px;margin:12px 0;border-radius:10px;background:#0a7cff;color:#fff;text-decoration:none;font-weight:600}
a.btn.alt{background:#34a853}
code{word-break:break-all;background:#f3f3f3;padding:2px 4px;border-radius:4px}
h2{margin-top:28px;font-size:18px}
</style></head><body>
<h1>OpenClash MITM 根证书</h1>
<p>名称：<code>{{.Name}}</code><br>SHA-1 指纹：<code>{{.Fingerprint}}</code><br>有效期至：{{.NotAfter}}</p>
<a class="btn" href="/ca.mobileconfig">iOS / iPadOS / macOS：下载描述文件</a>
<a class="btn alt" href="/ca.crt">Android / 其它系统：下载证书 (.crt)</a>
<h2>iOS</h2>
<ol><li>用 Safari 打开本页并下载描述文件。</li>
<li>设置 → 通用 → VPN 与设备管理 → 安装「OpenClash MITM」。</li>
<li>设置 → 通用 → 关于本机 → 证书信任设置 → 打开该证书的完全信任。</li></ol>
<h2>Android</h2>
<ol><li>下载 .crt 文件。</li>
<li>设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书，选择下载的文件。</li>
<li>Android 7 及以上的 App 默认不信任用户证书，只有浏览器和声明信任用户证书的 App 能被解密；全局生效需要 root 后安装为系统证书。</li></ol>
<p>证书私钥只保存在路由器上，请勿分享。重新生成证书后需要在设备上重新安装和信任。</p>
</body></html>`))

// CertHandler serves the CA certificate and installation instructions.
func CertHandler(authority *ca.Authority) http.Handler {
	mux := http.NewServeMux()
	sum := sha256.Sum256(authority.CertDER())
	name := authority.Cert.Subject.CommonName
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = certPage.Execute(w, map[string]string{
			"Name":        name,
			"Fingerprint": authority.Fingerprint(),
			"NotAfter":    authority.Cert.NotAfter.Format(time.DateOnly),
		})
	})
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="openclash-mitm-ca.crt"`)
		_, _ = w.Write(authority.CertDER())
	})
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="openclash-mitm-ca.pem"`)
		_, _ = w.Write(authority.CertPEM)
	})
	mux.HandleFunc("/ca.mobileconfig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="openclash-mitm.mobileconfig"`)
		_, _ = fmt.Fprintf(w, mobileconfig,
			base64.StdEncoding.EncodeToString(authority.CertDER()),
			template.HTMLEscapeString(name),
			uuidFrom(sum[:16]), uuidFrom(sum[:16]),
			uuidFrom(sum[16:]), uuidFrom(sum[16:]))
	})
	return mux
}

func uuidFrom(b []byte) string {
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

const mobileconfig = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>openclash-mitm-ca.cer</string>
			<key>PayloadContent</key>
			<data>%s</data>
			<key>PayloadDescription</key>
			<string>OpenClash MITM root certificate</string>
			<key>PayloadDisplayName</key>
			<string>%s</string>
			<key>PayloadIdentifier</key>
			<string>com.apple.security.root.%s</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>OpenClash MITM</string>
	<key>PayloadIdentifier</key>
	<string>com.openclash.mitm.%s</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`
