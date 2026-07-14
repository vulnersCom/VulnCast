#include "web_ui.h"

namespace {

// <head> up to (and excluding) the page <title> text.
const char kHead1[] PROGMEM =
    R"WEB(<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>)WEB";

// After the title: shared CSS (styled to match vulners.com), then <body>, the
// VULNCAST brand (coral cube + wordmark), and the status-bar container.
const char kHead2[] PROGMEM = R"WEB(</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 3 27.3 9.5 16 16 4.7 9.5Z' fill='%233d302b'/%3E%3Cpath d='M4.7 9.5 16 16 16 29 4.7 22.5Z' fill='%23e85a34'/%3E%3Cpath d='M27.3 9.5 27.3 22.5 16 29 16 16Z' fill='%23241d19'/%3E%3C/svg%3E"><style>
:root{--bg:#0c0a09;--panel:#161210;--bd:#2a231e;--tx:#f4f0ee;--mut:#a99f98;--coral:#ff7a4d;--coral2:#e85a34}
*{box-sizing:border-box}
body{margin:0;color:var(--tx);font-family:-apple-system,system-ui,"Segoe UI",Roboto,Arial,sans-serif;min-height:100vh;
background:radial-gradient(900px 520px at 80% -10%,rgba(232,90,52,.30),transparent 60%),radial-gradient(700px 500px at 5% 0%,rgba(232,90,52,.10),transparent 55%),var(--bg)}
.wrap{max-width:820px;margin:0 auto;padding:18px 16px 40px}
.brand{display:flex;align-items:center;gap:11px}
.wm{font-weight:800;font-size:23px;letter-spacing:.5px}
.wm b{background:linear-gradient(92deg,#fff 30%,var(--coral));-webkit-background-clip:text;background-clip:text;color:transparent}
a{color:var(--coral);text-decoration:none}
.back{display:inline-block;margin:0 0 14px;color:var(--mut);font-size:14px}
.back:hover{color:var(--tx)}
.card{background:var(--panel);border:1px solid var(--bd);border-radius:16px;padding:14px 15px;margin:12px 0}
h2{font-size:14px;margin:0 0 6px;font-weight:700}b{font-weight:700}
label{display:block;font-size:12px;color:var(--mut);margin-top:9px}
input,textarea,select{padding:10px 11px;margin-top:5px;border-radius:10px;border:1px solid #33291f;background:#100d0b;color:var(--tx);font-size:14px;font-family:inherit}
input,textarea,.full{width:100%}
select{width:auto;padding:8px 10px}
input[type=checkbox]{width:auto;margin:0;accent-color:var(--coral)}
button{padding:9px 14px;border:0;border-radius:999px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;margin-right:6px;color:#fff;background:linear-gradient(135deg,#ff8a5c,var(--coral2));box-shadow:0 5px 18px rgba(232,90,52,.32)}
button.wide{width:100%;padding:12px;margin:12px 0 0;border-radius:12px;font-size:15px}
.pri{background:linear-gradient(135deg,#ff8a5c,var(--coral2))}
.del{background:#2a1713;color:#ff8f75;border:1px solid #48221a;box-shadow:none}
.abtn{display:inline-flex;align-items:center;gap:5px;padding:9px 13px;border-radius:999px;font-size:14px;font-weight:600;background:#221c18;color:var(--tx);border:1px solid #33291f;margin-right:6px;text-decoration:none}
.abtn:hover{border-color:rgba(232,90,52,.5)}
button:disabled{opacity:.55;cursor:default}
.row{display:flex;gap:9px;flex-wrap:wrap;align-items:center}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--mut);word-break:break-all;margin:8px 0}
.champ{font-size:13px;margin:2px 0;overflow-wrap:anywhere}.champ b{color:var(--tx)}
.pill{display:inline-block;padding:3px 9px;border-radius:999px;font-size:12px;border:1px solid #33291f;background:#241d18;color:var(--mut)}
.on{background:rgba(232,90,52,.16);color:#ffa982;border-color:rgba(232,90,52,.4)}
.ok{color:#7fd88f}.bad{color:#ff8f75}.mut,.muted{color:var(--mut)}small{color:var(--mut)}
.chk{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--tx);background:#1c1713;border:1px solid #33291f;border-radius:999px;padding:6px 12px}
.hint{display:inline-flex;align-items:center;gap:8px;margin:8px 0 2px;padding:9px 12px;border:1px solid rgba(232,90,52,.42);border-radius:10px;background:rgba(232,90,52,.1);color:#ffab86;font-size:13px}
.hint:hover{background:rgba(232,90,52,.18);color:#ffc4a8}.hint svg{flex:none;stroke:var(--coral)}
.nav{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));margin-top:4px}
.navbtn{display:flex;align-items:center;gap:12px;background:var(--panel);border:1px solid var(--bd);border-radius:16px;padding:16px 15px;color:var(--tx);transition:border-color .15s}
.navbtn:hover{border-color:rgba(232,90,52,.55)}
.navbtn .nt{font-weight:700;font-size:15px}.navbtn .ns{color:var(--mut);font-size:12px;margin-top:1px}
.navbtn .chev{margin-left:auto;color:var(--coral);font-size:20px}
.ic{width:40px;height:40px;border-radius:11px;background:rgba(232,90,52,.14);border:1px solid rgba(232,90,52,.32);display:flex;align-items:center;justify-content:center;flex:none}
.ic svg{stroke:var(--coral)}
.sbar{display:flex;flex-wrap:wrap;align-items:center;gap:7px 13px;background:var(--panel);border:1px solid var(--bd);border-radius:14px;padding:10px 14px;margin:12px 0 16px;font-size:13px}
.sbar .seg{display:flex;align-items:center;gap:7px}
.sbar .sep{color:#3a2f28}
.dot{width:9px;height:9px;border-radius:50%;flex:none}
.dot.g{background:#5ac86e;box-shadow:0 0 8px rgba(90,200,110,.5)}
.dot.r{background:#ff6a4d;box-shadow:0 0 8px rgba(255,106,77,.45)}
.bars{display:inline-flex;align-items:flex-end;gap:2px;height:14px}
.bars i{width:3px;background:#4a3f38;border-radius:1px}.bars i.on{background:var(--coral)}
</style></head><body><div class=wrap>
<div class=brand><svg width="30" height="30" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="cg" x1="6" y1="29" x2="24" y2="5" gradientUnits="userSpaceOnUse"><stop stop-color="#ff9a6a"/><stop offset="1" stop-color="#e85a34"/></linearGradient></defs><path d="M16 3 L27.3 9.5 L16 16 L4.7 9.5 Z" fill="#3d302b"/><path d="M4.7 9.5 L16 16 L16 29 L4.7 22.5 Z" fill="url(#cg)"/><path d="M27.3 9.5 L27.3 22.5 L16 29 L16 16 Z" fill="#241d19"/></svg><div class=wm>VULN<b>CAST</b></div></div>
<div id=sbar class=sbar><span class=mut>connecting&hellip;</span></div>
)WEB";

// Shared status-bar renderer (WiFi + signal bars + IP + Vulners key + time) and
// document close. Runs on every page.
const char kTail[] PROGMEM = R"WEB(<script>
/* RSSI->bars thresholds mirror ui.cpp drawStatusBar — keep in sync. */
function _bars(r){var n=r>-55?4:r>-67?3:r>-78?2:1,h=[6,9,12,15],s='';for(var i=0;i<4;i++)s+='<i class="'+(i<n?'on':'')+'" style="height:'+h[i]+'px"></i>';return '<span class=bars>'+s+'</span>';}
function _esc(t){return (t||'').replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function _seg(id,h){var e=document.getElementById(id);if(e&&e.dataset.h!==h){e.dataset.h=h;e.innerHTML=h}}
async function _sb(){var s={};try{s=await(await fetch('/status')).json();}catch(e){}
var el=document.getElementById('sbar');if(!el)return;
if(!el.dataset.b){el.dataset.b='1';el.innerHTML='<span id=sbw class=seg></span><span class=sep>&middot;</span><span id=sbi class=seg></span><span class=sep>&middot;</span><span id=sbk class=seg></span><span class=sep>&middot;</span><span id=sbt class=seg></span>';}
var conn=s.connected,ap=s.mode=='portal';
var wifi=conn?('<span class="dot g"></span>'+_bars(s.rssi)+' <b>'+_esc(s.ssid)+'</b> <span class=mut>'+s.rssi+'dBm</span>'):(ap?'<span class="dot r"></span><b>Setup mode</b> <span class=mut>SoftAP</span>':'<span class="dot r"></span><b>Not connected</b>');
var ip=conn?('<span class=mut>IP</span> '+s.ip):(ap?'<span class=mut>IP</span> 192.168.4.1':'');
var key=s.apiKeySet?(s.apiKeyValid?'<span class=ok>Vulners key OK</span>':(s.apiKeyChecked?'<span class=bad>Vulners key invalid</span>':'<span class=mut>key unverified</span>')):'<span class=bad>no API key</span>';
var tm=s.synced?('<b>'+s.time+'</b> <span class=mut>'+(s.tzLabel||'')+'</span>'):'<span class=mut>time syncing&hellip;</span>';
_seg('sbw',wifi);_seg('sbi',ip);_seg('sbk',key);_seg('sbt',tm);}
_sb();setInterval(_sb,8000);
</script></div></body></html>)WEB";

}  // namespace

void vcSendHead(WebServer &s, const char *title) {
    s.setContentLength(CONTENT_LENGTH_UNKNOWN);
    s.send(200, "text/html", "");
    s.sendContent_P(kHead1);
    s.sendContent(title);
    s.sendContent_P(kHead2);
}

void vcSendTail(WebServer &s) {
    s.sendContent_P(kTail);
    s.sendContent("");  // terminating (zero-length) chunk
}

void vcSendJson(WebServer &s, int code, JsonDocument &d) {
    String out;
    serializeJson(d, out);
    s.send(code, "application/json", out);
}
