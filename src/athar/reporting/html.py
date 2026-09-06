"""Self-contained HTML forensic report.

Renders a :class:`~athar.model.Case` into a single stand-alone HTML file with no
external dependencies: the styling, the data, and the client-side rendering are
all inlined. The centrepiece is an interactive investigation map -- hosts as
nodes, conversations as edges, findings highlighted -- backed by an evidence
table, a per-host dossier, and a timeline.
"""

from __future__ import annotations

import datetime as _dt
import html
import json

from ..backend import backend
from ..model import Case
from .data import build_report_data


def render_html(case: Case) -> str:
    """Return the full HTML document for *case* as a string."""
    data = build_report_data(case)
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    return _TEMPLATE.format(css=_CSS, js=_JS, data=blob,
                            generated=html.escape(generated), backend=html.escape(backend()))


_CSS = """
:root{
  --bg:#0A1315; --panel:#0F1E21; --panel2:#13272B; --line:#1D343A; --line2:#2B4A52;
  --ink:#E6F0ED; --muted:#8AA6A3; --faint:#5C7B79; --accent:#E7B24C;
  --crit:#EF5F52; --high:#F0954F; --med:#E7C24C; --low:#59B0C9; --info:#6E8F8B;
  --server:#E7B24C; --endpoint:#63B7B0; --scanner:#EF5F52; --external:#9A93D6;
  --mono:ui-monospace,"JetBrains Mono","SF Mono",Menlo,Consolas,monospace;
  --sans:"Inter",system-ui,-apple-system,"Segoe UI",sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:14px;line-height:1.6;
  background-image:linear-gradient(var(--line) .5px,transparent .5px),
    linear-gradient(90deg,var(--line) .5px,transparent .5px);
  background-size:26px 26px;background-position:-1px -1px;}
.wrap{max-width:1180px;margin:0 auto;padding:32px 24px 80px}
a{color:var(--accent);text-decoration:none}
.mono{font-family:var(--mono)}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.18em;text-transform:uppercase;
  color:var(--faint)}

/* case header */
.case{border:.5px solid var(--line2);background:var(--panel);border-radius:14px;overflow:hidden}
.case-top{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;
  padding:22px 26px;border-bottom:.5px solid var(--line);
  background:repeating-linear-gradient(90deg,transparent,transparent 7px,rgba(231,178,76,.04) 7px,rgba(231,178,76,.04) 8px)}
.case-id{font-family:var(--mono);font-size:12px;color:var(--accent);letter-spacing:.1em}
.case h1{font-size:22px;font-weight:600;margin:6px 0 3px;letter-spacing:-.01em}
.case .src{font-family:var(--mono);font-size:12px;color:var(--muted);word-break:break-all}
.window{text-align:right;font-family:var(--mono);font-size:12px;color:var(--muted);white-space:nowrap}
.window b{color:var(--ink);font-weight:500}
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:.5px;background:var(--line)}
.stat{background:var(--panel);padding:16px 18px}
.stat .n{font-family:var(--mono);font-size:22px;font-weight:500}
.stat .l{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.12em;margin-top:2px}
.stat.alert .n{color:var(--crit)}

/* sections */
.section{margin-top:34px}
.section>h2{font-size:13px;font-family:var(--mono);letter-spacing:.14em;text-transform:uppercase;
  color:var(--muted);font-weight:500;margin:0 0 14px;display:flex;align-items:center;gap:10px}
.section>h2::after{content:"";flex:1;height:.5px;background:var(--line)}

/* findings */
.finding{display:grid;grid-template-columns:4px 1fr auto;gap:0;border:.5px solid var(--line2);
  border-radius:10px;background:var(--panel);margin-bottom:10px;overflow:hidden}
.finding .bar{width:4px}
.finding .body{padding:14px 18px}
.finding .head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.finding .title{font-weight:600;font-size:15px}
.finding .sum{color:var(--muted);margin-top:3px;font-size:13.5px}
.finding .meta{padding:14px 18px;text-align:right;font-family:var(--mono);font-size:11px;
  color:var(--faint);border-left:.5px solid var(--line);min-width:120px}
.finding .meta .att{color:var(--accent)}
.chip{font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;
  padding:2px 7px;border-radius:4px;border:.5px solid currentColor}
.sev-critical{color:var(--crit)} .sev-high{color:var(--high)} .sev-medium{color:var(--med)}
.sev-low{color:var(--low)} .sev-info{color:var(--info)}
.bar.sev-critical{background:var(--crit)} .bar.sev-high{background:var(--high)}
.bar.sev-medium{background:var(--med)} .bar.sev-low{background:var(--low)} .bar.sev-info{background:var(--info)}
.route{font-family:var(--mono);font-size:12px;color:var(--muted);margin-top:6px}
.route b{color:var(--ink);font-weight:500}

/* map + dossier */
.investigation{display:grid;grid-template-columns:1fr 340px;gap:.5px;background:var(--line);
  border:.5px solid var(--line2);border-radius:12px;overflow:hidden}
#map-panel{background:var(--panel);position:relative;min-height:440px}
#map{display:block;width:100%;height:100%}
.map-legend{position:absolute;left:14px;bottom:12px;display:flex;gap:14px;flex-wrap:wrap;
  font-family:var(--mono);font-size:11px;color:var(--muted)}
.map-legend span{display:flex;align-items:center;gap:5px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.hint{position:absolute;right:14px;top:12px;font-family:var(--mono);font-size:11px;color:var(--faint)}
.dossier{background:var(--panel2);padding:20px;overflow-y:auto;max-height:560px}
.dossier .empty{color:var(--faint);font-size:13px;text-align:center;margin-top:40px}
.dossier h3{font-family:var(--mono);font-size:16px;margin:0 0 2px}
.dossier .role{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.1em}
.d-grid{display:grid;grid-template-columns:1fr 1fr;gap:.5px;background:var(--line);
  margin:14px 0;border-radius:8px;overflow:hidden}
.d-grid div{background:var(--panel2);padding:9px 11px}
.d-grid .k{font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.1em}
.d-grid .v{font-family:var(--mono);font-size:14px}
.d-block{margin-top:16px}
.d-block .lbl{font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--faint);margin-bottom:7px}
.d-list{font-family:var(--mono);font-size:12px;color:var(--muted);max-height:150px;overflow-y:auto}
.d-list div{padding:3px 0;border-bottom:.5px solid var(--line);word-break:break-all}
.d-list .t{color:var(--accent);margin-right:8px}
.cred{color:var(--crit)}

/* tables */
table{width:100%;border-collapse:collapse;font-size:13px;
  border:.5px solid var(--line2);border-radius:10px;overflow:hidden}
th{font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--faint);text-align:left;font-weight:500;padding:11px 14px;background:var(--panel2);
  border-bottom:.5px solid var(--line)}
td{padding:10px 14px;border-bottom:.5px solid var(--line);font-family:var(--mono);font-size:12.5px}
tr:last-child td{border-bottom:none}
tr.host-row{cursor:pointer}
tr.host-row:hover{background:var(--panel2)}
tr.flagged td:first-child{box-shadow:inset 3px 0 0 var(--crit)}
.tag{font-family:var(--mono);font-size:10px;padding:2px 6px;border-radius:4px;
  background:var(--panel2);border:.5px solid var(--line2);color:var(--muted)}
.role-server{color:var(--server)} .role-endpoint{color:var(--endpoint)}
.role-scanner{color:var(--scanner)} .role-external{color:var(--external)}
.num{text-align:right}

/* timeline */
#timeline{background:var(--panel);border:.5px solid var(--line2);border-radius:10px;padding:20px}
.tl-track{position:relative;height:60px;margin:18px 6px 6px}
.tl-line{position:absolute;top:30px;left:0;right:0;height:.5px;background:var(--line2)}
.tl-ev{position:absolute;top:22px;width:2px;height:16px;border-radius:2px;cursor:pointer}
.tl-axis{display:flex;justify-content:space-between;font-family:var(--mono);font-size:10px;
  color:var(--faint);margin-top:8px}
.foot{margin-top:40px;text-align:center;font-family:var(--mono);font-size:11px;color:var(--faint)}
.evidence{border:.5px solid var(--line2);background:var(--panel);border-radius:10px;overflow:hidden}
.story{border:.5px solid var(--line2);background:var(--panel);border-radius:10px;margin-bottom:14px;overflow:hidden}
.story-head{display:flex;align-items:center;gap:14px;padding:14px 18px;background:var(--panel2);border-bottom:.5px solid var(--line)}
.story-host{font-family:var(--mono);font-size:16px;color:var(--accent);font-weight:600}
.story-score{font-family:var(--mono);font-size:12px;color:var(--crit)}
.story-span{font-family:var(--mono);font-size:12px;color:var(--faint);margin-left:auto}
.killchain{display:flex;align-items:center;flex-wrap:wrap;gap:6px;padding:12px 18px;border-bottom:.5px solid var(--line)}
.phase{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink);background:var(--panel2);border:.5px solid var(--line2);border-radius:5px;padding:3px 9px}
.arrow{color:var(--faint)}
.stage{padding:10px 18px;border-bottom:.5px solid var(--line)}
.stage:last-child{border-bottom:none}
.stage-tactic{font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.stage-ev{font-size:13px;padding:3px 0}
.stage-ev .att{font-family:var(--mono);font-size:10px;color:var(--faint)}
.ev-row{display:grid;grid-template-columns:180px 1fr;gap:12px;padding:10px 16px;border-bottom:.5px solid var(--line);font-family:var(--mono);font-size:12.5px}
.ev-row:last-child{border-bottom:none}
.ev-k{color:var(--faint);text-transform:uppercase;letter-spacing:.08em;font-size:11px}
.ev-v{color:var(--ink);word-break:break-all}
"""

_JS = r"""
const D = JSON.parse(document.getElementById('case-data').textContent);
const roleColor = {server:'var(--server)',endpoint:'var(--endpoint)',
  scanner:'var(--scanner)',external:'var(--external)'};
const fmtBytes = n => n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(1)+' MB';

/* ---- investigation map: tiny deterministic force layout ---- */
function layout(){
  const W=680,H=460,hosts=D.hosts,idx={};
  hosts.forEach((h,i)=>idx[h.ip]=i);
  let rng=1337; const rnd=()=>((rng=(rng*1103515245+12345)&0x7fffffff)/0x7fffffff);
  const N=hosts.map((h,i)=>({ip:h.ip,role:h.role,flagged:h.flagged,
    r:6+Math.min(22,Math.sqrt(h.bytes)/40),
    x:W/2+(rnd()-.5)*W*.7,y:H/2+(rnd()-.5)*H*.7,vx:0,vy:0}));
  const E=D.edges.filter(e=>idx[e.a]!=null&&idx[e.b]!=null)
    .map(e=>({s:idx[e.a],t:idx[e.b],w:e.bytes,sus:e.suspicious}));
  for(let it=0;it<320;it++){
    for(let i=0;i<N.length;i++)for(let j=i+1;j<N.length;j++){
      let dx=N[i].x-N[j].x,dy=N[i].y-N[j].y,d=Math.hypot(dx,dy)||.1;
      let f=2600/(d*d); N[i].vx+=dx/d*f;N[i].vy+=dy/d*f;N[j].vx-=dx/d*f;N[j].vy-=dy/d*f;}
    E.forEach(e=>{let a=N[e.s],b=N[e.t],dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||.1,
      f=(d-120)*.012;a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f;});
    N.forEach(n=>{n.vx+=(W/2-n.x)*.006;n.vy+=(H/2-n.y)*.006;
      n.x+=n.vx*.85;n.y+=n.vy*.85;n.vx*=.82;n.vy*=.82;
      n.x=Math.max(n.r+8,Math.min(W-n.r-8,n.x));n.y=Math.max(n.r+8,Math.min(H-n.r-8,n.y));});
  }
  return {N,E,W,H};
}
function drawMap(){
  const {N,E,W,H}=layout();
  const svg=['<svg id="map" viewBox="0 0 '+W+' '+H+'" xmlns="http://www.w3.org/2000/svg">'];
  E.forEach(e=>{const a=N[e.s],b=N[e.t];
    const col=e.sus?'var(--crit)':'var(--line2)';
    const sw=e.sus?2:Math.max(.5,Math.min(3,Math.log2(e.w/2000+1)*.5));
    if(e.sus)svg.push(`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="var(--crit)" stroke-width="6" opacity=".14"/>`);
    svg.push(`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${col}" stroke-width="${sw}" opacity="${e.sus?.9:.5}"/>`);});
  N.forEach(n=>{const c=roleColor[n.role]||'var(--endpoint)';
    if(n.flagged)svg.push(`<circle cx="${n.x}" cy="${n.y}" r="${n.r+6}" fill="none" stroke="var(--crit)" stroke-width="1" opacity=".7"/>`);
    svg.push(`<circle class="node" data-ip="${n.ip}" cx="${n.x}" cy="${n.y}" r="${n.r}" fill="${c}" fill-opacity=".22" stroke="${c}" stroke-width="1.5" style="cursor:pointer"/>`);
    const short=n.ip.length>15?n.ip.split('.').slice(-2).join('.'):n.ip;
    svg.push(`<text x="${n.x}" y="${n.y+n.r+13}" text-anchor="middle" font-family="ui-monospace,monospace" font-size="10" fill="var(--muted)" style="pointer-events:none">${short}</text>`);});
  svg.push('</svg>');
  document.getElementById('map-panel').insertAdjacentHTML('afterbegin',svg.join(''));
  document.querySelectorAll('#map .node').forEach(el=>
    el.addEventListener('click',()=>showDossier(el.getAttribute('data-ip'))));
}

/* ---- host dossier ---- */
function showDossier(ip){
  const h=D.hosts.find(x=>x.ip===ip); if(!h)return;
  document.querySelectorAll('#map .node').forEach(n=>
    n.setAttribute('stroke-width',n.getAttribute('data-ip')===ip?'3':'1.5'));
  const findings=h.findings.map(i=>D.events[i]).filter(Boolean);
  let html=`<h3>${h.ip}</h3><div class="role role-${h.role}">${h.role}${h.flagged?' \u00b7 flagged':''}</div>`;
  html+=`<div class="d-grid">
    <div><div class="k">packets</div><div class="v">${h.packets.toLocaleString()}</div></div>
    <div><div class="k">volume</div><div class="v">${fmtBytes(h.bytes)}</div></div>
    <div><div class="k">peers</div><div class="v">${h.peers}</div></div>
    <div><div class="k">services</div><div class="v">${h.services.join(', ')||'\u2014'}</div></div></div>`;
  if(h.mac)html+=`<div class="d-block"><div class="lbl">hardware</div><div class="d-list"><div>${h.mac}</div></div></div>`;
  if(h.geo&&h.geo.scope){
    const g=h.geo;
    const geoline=[g.scope, g.country, g.city, g.asn, g.organization].filter(Boolean).join(' \u00b7 ');
    html+=`<div class="d-block"><div class="lbl">network scope</div><div class="d-list"><div>${geoline}</div></div></div>`;
  }
  if(findings.length)html+=`<div class="d-block"><div class="lbl">findings</div>`+
    findings.map(f=>`<div class="route" style="margin-top:6px"><span class="chip sev-${f.severity}">${f.severity}</span> ${f.title}</div>`).join('')+`</div>`;
  if(h.dns.length)html+=block('dns lookups',h.dns.map(q=>`<div><span class="t">${q.type}</span>${q.name}</div>`).join(''));
  if(h.http.length)html+=block('http requests',h.http.map(r=>
    `<div><span class="t">${r.method}</span>${r.host}${r.path}${r.creds?` <span class="cred">[auth: ${r.creds}]</span>`:''}</div>`).join(''));
  if(h.sni.length)html+=block('tls server names',h.sni.map(s=>`<div>${s}</div>`).join(''));
  if(h.ja3&&h.ja3.length)html+=block('ja3 fingerprints',h.ja3.map(s=>`<div>${s}</div>`).join(''));
  if(h.ja3s&&h.ja3s.length)html+=block('ja3s (server) fingerprints',h.ja3s.map(s=>`<div>${s}</div>`).join(''));
  if(h.certificates&&h.certificates.length)html+=block('tls certificates',h.certificates.map(c=>{
    const tags=[c.self_signed?'self-signed':'',c.expired?'expired':'',c.lifetime_days!=null?c.lifetime_days+'d':''].filter(Boolean).join(' \u00b7 ');
    return `<div><span class="t">${(c.subject||'?').replace(/[<>&]/g,'')}</span>${tags}${c.self_signed?' <span class="cred">[self-signed]</span>':''}</div>`;
  }).join(''));
  if(h.sessions&&h.sessions.length)html+=block('protocol sessions',h.sessions.map(s=>
    `<div><span class="t">${s.protocol}</span>${s.detail.replace(/[<>&]/g,'')}</div>`).join(''));
  if(h.objects&&h.objects.length)html+=block('reconstructed content (cleartext http)',h.objects.map(o=>{
    const size=(o.declared_bytes/1024).toFixed(1)+' KB'+(o.truncated?' (truncated)':'');
    const name=o.filename?` <span class="t">${o.filename}</span>`:'';
    const prev=o.preview?`<div style="opacity:.7;white-space:pre-wrap;word-break:break-all;margin-top:3px">${o.preview.replace(/[<>&]/g,'')}</div>`:'';
    return `<div><span class="t">${o.method||o.kind}</span>${o.host}${o.path} · ${size}${name}<div style="opacity:.6">sha256 ${o.sha256.slice(0,32)}…</div>${prev}</div>`;
  }).join(''));
  document.getElementById('dossier').innerHTML=html;
}
const block=(lbl,inner)=>`<div class="d-block"><div class="lbl">${lbl}</div><div class="d-list">${inner}</div></div>`;

/* ---- timeline ---- */
function drawTimeline(){
  if(!D.events.length)return;
  const span=Math.max(D.duration,1),track=document.getElementById('tl-track');
  D.events.forEach(e=>{const x=(e.t/span)*100;
    const d=document.createElement('div');d.className='tl-ev sev-'+e.severity;
    d.style.left=x+'%';d.style.background=getComputedStyle(document.documentElement).getPropertyValue('--'+e.severity)||'#fff';
    d.title=`+${e.t}s  ${e.title}: ${e.summary}`;track.appendChild(d);});
  document.getElementById('tl-end').textContent='+'+span.toFixed(0)+'s';
}

drawMap();drawTimeline();
if(D.hosts.some(h=>h.flagged))showDossier(D.hosts.find(h=>h.flagged).ip);
"""

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>athar \u2014 forensic report</title>
<style>{css}</style></head>
<body><div class="wrap" id="app">
<div class="case">
  <div class="case-top">
    <div>
      <div class="case-id" id="caseid"></div>
      <h1>Network forensic report</h1>
      <div class="src" id="src"></div>
    </div>
    <div class="window" id="window"></div>
  </div>
  <div class="stats" id="stats"></div>
</div>

<div class="section" id="evidence-section" style="display:none">
  <h2>Evidence &amp; chain of custody</h2>
  <div id="evidence" class="evidence"></div>
</div>

<div class="section" id="findings-section">
  <h2>Findings</h2>
  <div id="findings"></div>
</div>

<div class="section" id="stories-section" style="display:none">
  <h2>Attack narratives</h2>
  <div id="stories"></div>
</div>

<div class="section">
  <h2>Investigation map</h2>
  <div class="investigation">
    <div id="map-panel">
      <div class="hint">click any device</div>
      <div class="map-legend">
        <span><i class="dot" style="background:var(--server)"></i>server</span>
        <span><i class="dot" style="background:var(--endpoint)"></i>endpoint</span>
        <span><i class="dot" style="background:var(--scanner)"></i>scanner</span>
        <span><i class="dot" style="background:var(--external)"></i>external</span>
        <span><i class="dot" style="background:var(--crit)"></i>suspicious link</span>
      </div>
    </div>
    <div class="dossier" id="dossier"><div class="empty">Select a device on the map<br>to open its dossier.</div></div>
  </div>
</div>

<div class="section">
  <h2>Timeline</h2>
  <div id="timeline">
    <div class="eyebrow">events across the capture window</div>
    <div class="tl-track" id="tl-track"><div class="tl-line"></div></div>
    <div class="tl-axis"><span>+0s</span><span id="tl-end"></span></div>
  </div>
</div>

<div class="section">
  <h2>Host inventory</h2>
  <table><thead><tr><th>Address</th><th>Role</th><th>Protocols</th>
    <th class="num">Packets</th><th class="num">Volume</th><th class="num">Peers</th></tr></thead>
    <tbody id="hosts"></tbody></table>
</div>

<div class="section">
  <h2>Top conversations</h2>
  <table><thead><tr><th>Source</th><th>Destination</th><th>Service</th>
    <th class="num">Packets</th><th class="num">Volume</th><th class="num">Duration</th></tr></thead>
    <tbody id="flows"></tbody></table>
</div>

<div class="foot">Generated by athar \u00b7 {generated} \u00b7 decoded via {backend} core \u00b7 authorised forensic use only</div>
</div>

<script type="application/json" id="case-data">{data}</script>
<script>
(function(){{
{js}
/* server-rendered content that doesn't need the map */
const fmt = n => n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(1)+' MB';
document.getElementById('caseid').textContent=D.case_id;
document.getElementById('src').textContent=D.source;
document.getElementById('window').innerHTML=
  `capture window<br><b>${{D.started_iso}}</b><br>to <b>${{D.ended_iso}}</b><br>span <b>${{D.duration}}s</b>`;
const alerts=Object.values(D.severity).reduce((a,b)=>a+b,0);
document.getElementById('stats').innerHTML=[
  ['hosts',D.host_count],['conversations',D.flow_count],['packets',D.packets.toLocaleString()],
  ['volume',fmt(D.bytes)],['duration',D.duration+'s']
].map(s=>`<div class="stat"><div class="n">${{s[1]}}</div><div class="l">${{s[0]}}</div></div>`).join('')
 +`<div class="stat alert"><div class="n">${{alerts}}</div><div class="l">findings</div></div>`;

if(D.provenance){{
  const p=D.provenance;
  const row=(k,v)=>v?`<div class="ev-row"><span class="ev-k">${{k}}</span><span class="ev-v">${{v}}</span></div>`:'';
  document.getElementById('evidence-section').style.display='';
  document.getElementById('evidence').innerHTML=
    row('source',p.source_path)
   +row('source sha-256',p.source_sha256)
   +row('source size',p.source_bytes+' bytes')
   +row('examiner',p.examiner)
   +row('organization',p.organization)
   +row('case number',p.case_number)
   +row('legal authority',p.authority)
   +row('analyzed at',p.analyzed_at)
   +row('tool',(p.tool||'athar')+' '+p.tool_version+' ('+p.backend+' core)')
   +(p.notes?`<div class="ev-row"><span class="ev-k">notes</span><span class="ev-v">${{p.notes}}</span></div>`:'');
}}

if(D.stories&&D.stories.length){{
  document.getElementById('stories-section').style.display='';
  document.getElementById('stories').innerHTML=D.stories.map(s=>`
    <div class="story">
      <div class="story-head">
        <span class="story-host">${{s.host}}</span>
        <span class="story-score">threat score ${{s.score}}</span>
        <span class="story-span">over ${{s.span}}s</span>
      </div>
      <div class="killchain">${{s.tactics.map(t=>`<span class="phase">${{t}}</span>`).join('<span class="arrow">\u2192</span>')}}</div>
      ${{s.stages.map(st=>`
        <div class="stage">
          <div class="stage-tactic">${{st.tactic}}</div>
          ${{st.events.map(e=>`<div class="stage-ev"><span class="chip sev-${{e.severity}}">${{e.severity}}</span> ${{e.summary}} <span class="att">${{e.technique}}</span></div>`).join('')}}
        </div>`).join('')}}
    </div>`).join('');
}}

document.getElementById('findings').innerHTML = D.events.length? D.events.map(e=>`
  <div class="finding"><div class="bar sev-${{e.severity}}"></div>
    <div class="body"><div class="head"><span class="chip sev-${{e.severity}}">${{e.severity}}</span>
      <span class="title">${{e.title}}</span></div>
      <div class="sum">${{e.summary}}</div>
      ${{e.src?`<div class="route"><b>${{e.src}}</b>${{e.dst?` \u2192 <b>${{e.dst}}</b>`:''}}</div>`:''}}</div>
    <div class="meta">${{e.detector}}${{e.technique?`<br><span class="att">${{e.technique}}</span>`:''}}</div>
  </div>`).join('') : '<div class="empty" style="color:var(--faint)">No suspicious activity detected.</div>';

document.getElementById('hosts').innerHTML=D.hosts.map(h=>`
  <tr class="host-row ${{h.flagged?'flagged':''}}" data-ip="${{h.ip}}">
    <td>${{h.ip}}</td><td class="role-${{h.role}}">${{h.role}}</td>
    <td>${{h.protocols.map(p=>`<span class="tag">${{p}}</span>`).join(' ')}}</td>
    <td class="num">${{h.packets.toLocaleString()}}</td><td class="num">${{fmt(h.bytes)}}</td>
    <td class="num">${{h.peers}}</td></tr>`).join('');
document.querySelectorAll('#hosts .host-row').forEach(r=>r.addEventListener('click',()=>{{
  showDossier(r.getAttribute('data-ip'));
  document.getElementById('map-panel').scrollIntoView({{behavior:'smooth',block:'center'}});}}));

document.getElementById('flows').innerHTML=D.flows.slice(0,40).map(f=>`
  <tr><td>${{f.src}}:${{f.sport}}</td><td>${{f.dst}}:${{f.dport}}</td>
    <td>${{f.service||f.proto}}</td><td class="num">${{f.packets}}</td>
    <td class="num">${{fmt(f.bytes)}}</td><td class="num">${{f.dur}}s</td></tr>`).join('');
}})();
</script>
</body></html>"""
