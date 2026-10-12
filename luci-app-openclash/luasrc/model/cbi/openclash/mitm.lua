
local SYS = require "luci.sys"
local HTTP = require "luci.http"
local DISP = require "luci.dispatcher"
local UTIL = require "luci.util"
local IP = require "luci.ip"
local fs = require "luci.openclash"

local MITM_SH = "/usr/share/openclash/openclash_mitm.sh"
local MITM_CUSTOM = "/etc/openclash/custom/openclash_custom_mitm.stoverride"
local MITM_LOG = "/tmp/openclash_mitm.log"

font_green = [[<b style=color:green>]]
font_red = [[<b style=color:red>]]
font_off = [[</b>]]
bold_on = [[<strong>]]
bold_off = [[</strong>]]

local status = {}
for line in (SYS.exec(MITM_SH .. " status 2>/dev/null") or ""):gmatch("[^\n]+") do
	local k, v = line:match("^([%w_]+)=(.*)$")
	if k then status[k] = v end
end

local lan_ip = fs.lanip()
local cert_port = fs.uci_get_config("config", "mitm_cert_port") or "7900"

m = Map("openclash", translate("HTTP(S) Rewrite"))
m.pageaction = false
m.description = translate("Decrypt the HTTPS traffic of selected hosts with a local root certificate and rewrite it with Stash override (.stoverride) rules, the rewritten traffic still follows the rules of the current config.")..
"<br/>"..font_red..bold_on..translate("JavaScript (http.script) is not supported yet, those rules are ignored.")..bold_off..font_off

s = m:section(TypedSection, "openclash")
s.anonymous = true

s:tab("settings", translate("General Settings"))
s:tab("cert", translate("Root Certificate"))
s:tab("custom", translate("Custom Override"))
s:tab("log", translate("Logs"))

---- General Settings
o = s:taboption("settings", Flag, "mitm_enable", font_red..bold_on..translate("Enable HTTP(S) Rewrite")..bold_off..font_off)
o.description = translate("Take Effect After Restart, Recommended With Fake-IP Mode Or Sniffer Enabled So The Hostname Is Known")
o.default = 0

o = s:taboption("settings", DummyValue, "_mitm_engine", translate("Engine Version"))
o.rawhtml = true
o.value = (status.version and status.version ~= "") and
	(font_green..bold_on..status.version..bold_off..font_off.." "..((status.running == "1") and translate("Running") or translate("Not Running"))) or
	(font_red..bold_on..translate("Not Installed")..bold_off..font_off)

o = s:taboption("settings", Value, "mitm_engine_url", translate("Engine Download URL"))
o.placeholder = "https://raw.githubusercontent.com/vernesong/OpenClash/core/master/mitm/openclash-mitm-{arch}.tar.gz"
o.description = translate("Leave Empty To Use The Official Core Branch, {arch} Is Replaced With The Core Compiled Version Of Plugin Settings")

o = s:taboption("settings", Button, "_mitm_core_download", translate("Download Engine"))
o.inputtitle = translate("Check And Update")
o.inputstyle = "reload"
o.description = translate("Download The Engine Matching The Core Compiled Version Of Plugin Settings, Or Upload It Manually To").." /etc/openclash/core/openclash_mitm"
o.write = function(self, section)
	local url = HTTP.formvalue("cbid.openclash."..section..".mitm_engine_url") or ""
	if url ~= "" and not url:match("^https?://") then
		url = ""
	end
	SYS.call(MITM_SH .. " core-download " .. UTIL.shellquote(url) .. " >/dev/null 2>&1 &")
	HTTP.redirect(DISP.build_url("admin", "services", "openclash"))
end

o = s:taboption("settings", DynamicList, "mitm_src", translate("Decrypted Devices"))
o.datatype = "ipmask"
o.description = translate("Only Decrypt And Rewrite The Traffic Of These LAN Devices (IP Or CIDR), Leave Empty For All Devices")
IP.neighbors({ family = 4 }, function(n)
	if n.mac and n.dest then
		o:value(n.dest:string(), "%s%s" %{ n.dest:string(), n.hostname and " [".. n.hostname .."]" or "" })
	end
end)

o = s:taboption("settings", DynamicList, "mitm_hosts", translate("Extra MITM Hostnames"))
o.description = translate("Appended To The http.mitm Lists Of The Overrides, Supports * And ? Wildcards, - Prefix Excludes")
o.placeholder = "api.example.com"

o = s:taboption("settings", Flag, "mitm_block_quic", translate("Block QUIC Of Decrypted Hosts"))
o.description = translate("Reject UDP/443 To Decrypted Hosts So Clients Fall Back To TCP, Otherwise HTTP/3 Traffic Bypasses The Rewrite")
o.default = 1

o = s:taboption("settings", Flag, "mitm_skip_cert_verify", translate("Skip Server Certificate Verify"))
o.description = font_red..bold_on..translate("Not Recommended, Do Not Verify The Certificates Of The Real Servers")..bold_off..font_off
o.default = 0

o = s:taboption("settings", Value, "mitm_max_body_size", translate("Max Body Size For Body Rewrite (MB)"))
o.datatype = "range(1,64)"
o.default = "4"

o = s:taboption("settings", Value, "mitm_port", translate("Engine Port"))
o.datatype = "port"
o.default = "7899"
o.description = translate("Please Make Sure Ports Available")

o = s:taboption("settings", Value, "mitm_out_port", translate("Engine Outbound Listener Port"))
o.datatype = "port"
o.default = "7898"
o.description = translate("Decrypted Traffic Re-enters The Core From This Local Listener To Follow The Config Rules")

o = s:taboption("settings", ListValue, "mitm_log_level", translate("Log Level"))
o:value("info", translate("Info Mode"))
o:value("warn", translate("Warning Mode"))
o:value("error", translate("Error Mode"))
o:value("debug", translate("Debug Mode"))
o.default = "info"

---- Root Certificate
o = s:taboption("cert", DummyValue, "_mitm_ca", translate("Certificate Info"))
o.rawhtml = true
if status.sha1 then
	o.value = translate("Name")..": "..bold_on..UTIL.pcdata(status.name or "")..bold_off.."<br/>"..
		"SHA-1: <code>"..UTIL.pcdata(status.sha1).."</code><br/>"..
		translate("Expire Time")..": "..UTIL.pcdata(status.not_after or "")
else
	o.value = font_red..bold_on..translate("Not Generated, It Will Be Generated Automatically On Start")..bold_off..font_off
end

o = s:taboption("cert", Value, "mitm_cert_port", translate("Certificate Page Port"))
o.datatype = "port"
o.default = "7900"
o.description = translate("Open This Page With The Phone To Install The Certificate, 0 Disables The Page")..": "..
	"<a href='http://"..lan_ip..":"..cert_port.."/' target='_blank'>http://"..lan_ip..":"..cert_port.."/</a>"..
	"<br/>"..translate("iOS: Install The Profile, Then Enable Full Trust In Settings - General - About - Certificate Trust Settings")..
	"<br/>"..translate("Android 7+: Apps Do Not Trust User Certificates By Default, Only Browsers And Apps That Opt In Can Be Decrypted, Global Effect Requires Root")

o = s:taboption("cert", DummyValue, "_mitm_ca_download", translate("Download Certificate"))
o.rawhtml = true
o.value = "<a class='btn cbi-button cbi-button-apply' href='"..DISP.build_url("admin", "services", "openclash", "mitm_ca").."'>"..translate("Download").."</a>"

o = s:taboption("cert", Button, "_mitm_regen_ca", translate("Regenerate Certificate"))
o.inputtitle = translate("Regenerate")
o.inputstyle = "reset"
o.description = font_red..bold_on..translate("All Devices Need To Reinstall And Trust The New Certificate")..bold_off..font_off
o.write = function()
	SYS.call(MITM_SH .. " regen-ca >/dev/null 2>&1")
	HTTP.redirect(DISP.build_url("admin", "services", "openclash", "mitm"))
end

---- Custom Override
custom = s:taboption("custom", Value, "_mitm_custom")
custom.template = "cbi/tvalue"
custom.rows = 30
custom.wrap = "off"
custom.description = translate("Stash Override Syntax, Takes Precedence Over The Subscribed Overrides")
function custom.cfgvalue(self, section)
	return fs.readfile(MITM_CUSTOM) or ""
end
function custom.write(self, section, value)
	if value then
		value = value:gsub("\r\n?", "\n")
		if value ~= fs.readfile(MITM_CUSTOM) then
			fs.writefile(MITM_CUSTOM, value)
		end
	end
	return true
end

---- Logs
o = s:taboption("log", TextValue, "_mitm_log")
o.rows = 30
o.wrap = "off"
o.readonly = true
function o.cfgvalue(self, section)
	return SYS.exec("tail -n 300 " .. MITM_LOG .. " 2>/dev/null") or ""
end
function o.write() return true end

-- [[ Override Subscriptions ]] --
ov = m:section(TypedSection, "mitm_override", translate("Override Subscriptions"),
	translate("Stash Override (.stoverride) URLs, Downloaded On Start If Missing, Use The Update Button To Refresh"))
ov.anonymous = true
ov.addremove = true
ov.sortable = true
ov.template = "cbi/tblsection"
ov.rmempty = false

o = ov:option(Flag, "enabled", translate("Enable"))
o.rmempty = false
o.default = o.enabled
o.cfgvalue = function(...)
	return Flag.cfgvalue(...) or "1"
end

o = ov:option(Value, "name", translate("Override Name"))
o.rmempty = false
o.placeholder = "iRingo.WeatherKit"
function o.validate(self, value, section)
	if not value or value == "" then
		return nil, translate("Override Name")..": "..translate("Not Null")
	end
	return value
end

o = ov:option(Value, "url", translate("Override URL"))
o.rmempty = false
o.placeholder = "https://github.com/NSRingo/WeatherKit/releases/latest/download/iRingo.WeatherKit.stoverride"
function o.validate(self, value, section)
	if value and value:match("^https?://") then
		return value
	end
	return nil, translate("Override URL")..": "..translate("Please Enter A Valid URL")
end

local t = {
	{Commit, Update, Apply}
}

a = m:section(Table, t)

o = a:option(Button, "Commit", " ")
o.inputtitle = translate("Commit Settings")
o.inputstyle = "apply"
o.write = function()
	m.uci:commit("openclash")
	SYS.call(MITM_SH .. " clean >/dev/null 2>&1")
end

o = a:option(Button, "Update", " ")
o.inputtitle = translate("Update Overrides")
o.inputstyle = "reload"
o.write = function()
	m.uci:commit("openclash")
	SYS.call("(" .. MITM_SH .. " clean; " .. MITM_SH .. " update; /etc/init.d/openclash restart) >/dev/null 2>&1 &")
	HTTP.redirect(DISP.build_url("admin", "services", "openclash"))
end

o = a:option(Button, "Apply", " ")
o.inputtitle = translate("Apply Settings")
o.inputstyle = "apply"
o.write = function()
	m.uci:set("openclash", "config", "enable", 1)
	m.uci:commit("openclash")
	SYS.call(MITM_SH .. " clean >/dev/null 2>&1")
	SYS.call("/etc/init.d/openclash restart >/dev/null 2>&1 &")
	HTTP.redirect(DISP.build_url("admin", "services", "openclash"))
end

m:append(Template("openclash/toolbar_show"))

return m
