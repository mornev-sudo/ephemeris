// The web portal's script, served as /app.js so the page's Content-Security-
// Policy can forbid inline scripts entirely.
"use strict";
const $ = (id) => document.getElementById(id);
let signedIn = false;
let timer = null, current = "dash";

// The session lives in an HttpOnly cookie the page can't read; X-Ephemeris
// proves to the router that a request came from this page (anti-CSRF).
async function api(method, path, body, isJson) {
  const headers = { "X-Ephemeris": "1" };
  if (isJson) headers["Content-Type"] = "application/json";
  const r = await fetch("/api/v1" + path, { method, headers, body, credentials: "same-origin" });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { showLogin(signedIn ? "Your session ended; please sign in again." : ""); throw new Error("unauthorised"); }
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

// --- tiny DOM helpers: every value goes in as text, never as HTML
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function table(t, head, rows) {
  t.replaceChildren();
  const tr = el("tr"); head.forEach(h => tr.append(el("th", h))); t.append(tr);
  if (!rows.length) { const r = el("tr"), c = el("td", "none", "s"); c.colSpan = head.length; r.append(c); t.append(r); return; }
  rows.forEach(cells => { const r = el("tr"); cells.forEach(c => r.append(c instanceof Node ? c : el("td", c))); t.append(r); });
}
function td(text, cls) { return el("td", text, cls); }
function n(x) { return Number(x).toLocaleString(); }
function bytes(b) { const u = ["B","KB","MB","GB","TB"]; let i = 0; while (b >= 1000 && i < 4) { b /= 1000; i++; } return (i ? b.toFixed(1) : b) + " " + u[i]; }
function dur(s) { if (s < 60) return s + "s"; if (s < 3600) return Math.floor(s/60) + "m"; if (s < 86400) return Math.floor(s/3600) + "h" + Math.floor(s%3600/60) + "m"; return Math.floor(s/86400) + "d"; }

function card(title, value, sub) { const c = el("div", undefined, "card"); c.append(el("h3", title), el("div", value, "v"), el("div", sub || "", "s")); return c; }

/// Bits per second, scaled: 950 bps, 12.5 kbps, 3.20 Mbps, 1.05 Gbps.
function bps(x) {
  const u = [["Gbps", 1e9], ["Mbps", 1e6], ["kbps", 1e3]].find(([, d]) => x >= d);
  if (!u) return Math.round(x) + " bps";
  const v = x / u[1];
  return (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + " " + u[0];
}
function pps(x) { return x >= 10 ? n(Math.round(x)) + " pps" : x.toFixed(1) + " pps"; }

/// A line chart as inline SVG (the CSP allows no chart libraries, and none
/// are needed). `series`: [{label, color, values}], all as long as `times`.
function lineChart(box, title, times, series, fmt) {
  const W = 640, H = 180, L = 70, R = 10, T = 10, B = 24;
  const ns = "http://www.w3.org/2000/svg";
  const mk = (tag, attrs, text) => { const e = document.createElementNS(ns, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (text != null) e.textContent = text; return e; };
  const max = Math.max(1e-9, ...series.flatMap(s => s.values));
  // A "nice" top for the axis: 1, 2 or 5 times a power of ten.
  const p = 10 ** Math.floor(Math.log10(max)), top = [1, 2, 5, 10].map(m => m * p).find(v => v >= max);
  const x = i => L + (times.length < 2 ? 0 : (i / (times.length - 1)) * (W - L - R));
  const y = v => T + (1 - v / top) * (H - T - B);
  const svg = mk("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": title });
  for (let k = 0; k <= 4; k++) {
    const v = top * k / 4;
    svg.append(mk("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), class: "grid" }));
    svg.append(mk("text", { x: L - 6, y: y(v) + 4, "text-anchor": "end", class: "axis" }, fmt(v)));
  }
  if (times.length) {
    const hhmm = t => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    [0, Math.floor((times.length - 1) / 2), times.length - 1].forEach((i, k) =>
      svg.append(mk("text", { x: x(i), y: H - 6, "text-anchor": ["start", "middle", "end"][k], class: "axis" }, hhmm(times[i]))));
  }
  series.forEach(s => {
    if (!s.values.length) return;
    const d = s.values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    svg.append(mk("path", { d, fill: "none", style: `stroke:${s.color}`, "stroke-width": 2, "vector-effect": "non-scaling-stroke" }));
  });
  const head = el("div", undefined, "charthead");
  head.append(el("h3", title));
  series.forEach(s => {
    const k = el("span", `${s.label}: ${s.values.length ? fmt(s.values[s.values.length - 1]) : "–"}`, "legend");
    k.style.setProperty("--c", s.color); head.append(k);
  });
  const c = el("div", undefined, "card chartcard"); c.append(head, svg);
  box.append(c);
}

let reportRange = 900;
async function refreshReports() {
  const h = await api("GET", "/stats/history?secs=" + reportRange);
  const S = h.samples, t = S.map(s => s.t);
  const IN = "var(--accent)", OUT = "var(--ok)";
  const box = $("charts"); box.replaceChildren();
  if (S.length < 2) box.append(el("p", "Collecting: the first points appear within 10 seconds.", "s"));
  lineChart(box, "Open sessions", t, [{ label: "sessions", color: IN, values: S.map(s => s.sessions) }], v => n(Math.round(v)));
  lineChart(box, "Packets per second", t, [
    { label: "in", color: IN, values: S.map(s => s.rx_pps) }, { label: "out", color: OUT, values: S.map(s => s.tx_pps) }], pps);
  lineChart(box, "Throughput", t, [
    { label: "in", color: IN, values: S.map(s => s.rx_bps) }, { label: "out", color: OUT, values: S.map(s => s.tx_bps) }], bps);
  lineChart(box, "Dropped packets per second", t, [{ label: "drops", color: "var(--bad)", values: S.map(s => s.drops_per_sec) }], pps);
  const latest = S[S.length - 1];
  $("reportmeta").textContent = latest
    ? `Every ${h.interval_secs} s · dropped packets since start: ${n(latest.drops_total)} · last sample ${new Date(latest.t * 1000).toLocaleTimeString()}`
    : `Every ${h.interval_secs} s`;
  table($("ifrates"), ["Interface", "In", "Out", "In (pps)", "Out (pps)"],
    latest ? h.interfaces.map((name, i) => { const p = latest.ports[i] || {}; return [name, bps(p.rx_bps || 0), bps(p.tx_bps || 0), pps(p.rx_pps || 0), pps(p.tx_pps || 0)]; }) : []);
}
document.querySelectorAll("#reportrange button").forEach(b => b.onclick = () => {
  reportRange = Number(b.dataset.secs);
  document.querySelectorAll("#reportrange button").forEach(x => x.classList.toggle("on", x === b));
  refreshReports().catch(() => {});
});

async function refreshDash() {
  const s = await api("GET", "/status");
  const r = s.rates;
  $("meta").textContent = `v${s.version} · build ${s.build} · up ${dur(s.uptime_secs)} · ${s.workers} worker(s)`
    + (s.pending_confirm_secs != null ? ` · ⚠ unconfirmed commit rolls back in ${s.pending_confirm_secs}s` : "");
  const warn = [];
  if (s.dataplane_error) warn.push("The data plane is not running, so nothing is being routed: " + s.dataplane_error
    + ". Fix the configuration (Configuration tab), commit, then restart the data plane.");
  if (s.fallback) warn.push(`A newer configuration failed to start (${s.fallback.error}), so the router went back to the last one that worked. `
    + `The failed one was kept as ${s.fallback.failed_file}.`);
  $("dashwarn").replaceChildren(...warn.map(w => el("p", w)));
  $("dashwarn").classList.toggle("hidden", !warn.length);
  const wan = await api("GET", "/wan");
  table($("wantab"), ["Interface", "Mode", "State", "Address", "Gateway", "DNS", ""], wan.map(w => {
    const ok = w.state === "up" || w.state === "bound";
    let detail = "";
    if (w.mode === "pppoe") detail = w.pppoe.session != null
      ? `${w.pppoe.concentrator || "ISP"} · session ${w.pppoe.session} · MTU ${w.pppoe.mtu} · up ${dur(w.pppoe.up_for_secs)}`
      : (w.pppoe.last_error ? "last error: " + w.pppoe.last_error : "dialling as " + w.pppoe.username);
    if (w.mode === "dhcp" && w.dhcp.server) detail = `from ${w.dhcp.server} · lease ends in ${dur(w.dhcp.expires_in_secs)}`;
    return [w.interface, { pppoe: "PPPoE", dhcp: "DHCP", static: "static" }[w.mode], td(w.state || "—", ok ? "ok" : "warn"),
      td(w.address || "—", "mono"), td(w.gateway || "—", "mono"), td((w.dns || []).join(", ") || "—", "mono"), td(detail, "s")];
  }));
  // The same four numbers as the Reporting graphs (last 5 s).
  $("cards").replaceChildren(
    card("Open sessions", n(s.sessions.active), n(s.sessions.created) + " created · " + n(s.sessions.expired) + " expired"),
    card("Packets per second", r ? pps(r.rx_pps + r.tx_pps) : "–", r ? `in ${pps(r.rx_pps)} · out ${pps(r.tx_pps)}` : "measuring…"),
    card("Throughput", r ? bps(r.rx_bps + r.tx_bps) : "–", r ? `in ${bps(r.rx_bps)} · out ${bps(r.tx_bps)}` : "measuring…"),
    card("Dropped packets", n(s.drops_total), r ? `${pps(r.drops_per_sec)} now · see Drops by reason` : "see Drops by reason"));
  table($("ports"), ["Name", "Role", "Device", "Address", "MAC", "XDP", "Zero-copy", "New sessions", "MSS adjust"],
    s.ports.map(p => [p.name, p.role, td(p.device, "mono"), td(p.address, "mono"), td(p.mac, "mono"),
      td(p.xdp_mode, p.xdp_mode === "Native" ? "ok" : "warn"), p.zero_copy ? "yes" : "no",
      td(p.allow_new_sessions ? "allowed" : "replies only", p.allow_new_sessions ? "" : "warn"),
      p.mss_adjust ?? "off"]));
  table($("drops"), ["Reason", "Packets"], Object.entries(s.drops).map(([k, v]) => [td(k, "mono"), n(v)]));
  const ne = await api("GET", "/neighbors");
  table($("neigh"), ["IP", "MAC", "Interface"], ne.map(x => [td(x.ip, "mono"), td(x.mac, "mono"), x.port]));
}

async function refreshSessions() {
  const list = await api("GET", "/sessions?limit=1000");
  const f = $("sessfilter").value.trim().toLowerCase();
  const shown = list.filter(x => !f || JSON.stringify(x).toLowerCase().includes(f));
  $("sesscount").textContent = `${shown.length} of ${list.length} sessions (busiest first)`;
  table($("sess"), ["Proto", "Initiator", "NAT as", "Responder", "State", "Packets →/←", "Bytes →/←", "Age", "Idle"],
    shown.map(x => [x.proto, td(x.initiator, "mono"), td(x.nat || "—", "mono"), td(x.responder, "mono"),
      td(x.state, x.state === "established" ? "ok" : ""), n(x.packets[0]) + " / " + n(x.packets[1]),
      bytes(x.bytes[0]) + " / " + bytes(x.bytes[1]), dur(x.age_secs), dur(x.idle_secs)]));
}

async function refreshSdwan() {
  await refreshSites();
  const v = await api("GET", "/overlay");
  if (!v.enabled) { $("sdwanmeta").textContent = "No SD-WAN overlay configured on this router."; table($("tun"), ["Tether"], []); table($("pathtab"), ["Class"], []); return; }
  $("sdwanmeta").textContent = `Site ${v.site_id} · overlay MTU ${v.mtu} · path generation ${v.path_generation}`;
  table($("tun"), ["Tether", "Via", "Remote", "Site", "State", "RTT", "Jitter", "Loss", "Tx", "Rx"],
    v.tethers.map(t => [t.name, t.interface, td(t.remote, "mono"), String(t.site), td(t.up ? "up" : "DOWN", t.up ? "ok" : "bad"),
      t.rtt_ms.toFixed(1) + " ms", t.jitter_ms.toFixed(1) + " ms", td(t.loss_pct.toFixed(1) + "%", t.loss_pct > 1 ? "warn" : ""),
      bytes(t.tx_bytes), bytes(t.rx_bytes)]));
  table($("pathtab"), ["Site", "Class", "Using"], v.paths.map(p => [String(p.site), p.class, td(p.tether || "no path", p.tether ? "" : "bad")]));
}

async function refreshSites() {
  const v = await api("GET", "/overlay/sites");
  table($("sitetab"), ["Site", "Id", "Role", "Connection", "Key", "Tethers", ""], v.sites.map(x => {
    const b = el("button", "Copy entry for its router", "btn");
    b.onclick = async () => {
      try {
        const e = await api("GET", "/overlay/entry?site=" + encodeURIComponent(x.name));
        const note = e.dynamic ? "\n# This router has no fixed WAN address: the other router learns it. It must have one itself.\n" : "";
        try { await navigator.clipboard.writeText(e.toml + note); b.textContent = "Copied"; } catch { prompt("Copy this into " + x.name + "'s configuration:", e.toml); }
        setTimeout(() => b.textContent = "Copy entry for its router", 2000);
      } catch (err) { alert(err.message); }
    };
    return [x.name, String(x.id), x.role, td(x.connected ? "direct" : "through a hub", x.connected ? "ok" : ""),
      x.connected ? td(x.has_key ? "set" : "missing", x.has_key ? "ok" : "bad") : td("not needed", "s"),
      td(x.tethers.join(", ") || "—", "mono"), b];
  }));
  $("sitemeta").textContent = v.this ? `This router: ${v.this.name} (site ${v.this.id}, ${v.this.role})` : "";
}

async function refreshDhcp() {
  const v = await api("GET", "/dhcp");
  table($("dhcpclients"), ["Interface", "State", "Address", "Gateway", "DNS", "Server", "Expires in"],
    v.clients.map(c => [c.interface, td(c.state, c.state === "bound" ? "ok" : "warn"), td(c.address || "—", "mono"),
      td(c.gateway || "—", "mono"), td((c.dns || []).join(", ") || "—", "mono"), td(c.server || "—", "mono"),
      c.expires_in_secs == null ? "—" : dur(c.expires_in_secs)]));
  const box = $("dhcpservers");
  box.replaceChildren();
  if (!v.servers.length) box.append(el("p", "No interface serves DHCP (Configuration → DHCP server).", "s"));
  v.servers.forEach(srv => {
    const t = document.createElement("table");
    table(t, ["IP", "MAC", "Host name", "State", "Expires in"],
      srv.leases.map(l => [td(l.ip, "mono"), td(l.mac, "mono"), l.hostname || "", l.state, dur(l.expires_in_secs)]));
    const w = el("div", undefined, "tablewrap"); w.append(t);
    box.append(el("h3", `${srv.interface}: ${srv.leases.length} lease(s)`), w);
  });
}

async function refreshRoutes() {
  const rt = await api("GET", "/routes");
  table($("rt"), ["Prefix", "Next hop", "Interface", "Kind", ""], rt.map(r => {
    const action = td("");
    if (r.kind === "static") {
      const b = el("button", "Remove", "btn");
      b.onclick = async () => { if (!confirm("Remove route " + r.prefix + "?")) return;
        try { await api("DELETE", "/routes?prefix=" + encodeURIComponent(r.prefix)); refreshRoutes(); } catch (e) { alert(e.message); } };
      action.append(b);
    }
    return [td(r.prefix, "mono"), td(r.via || "directly connected", "mono"), r.port, r.kind, action];
  }));
}

/// The update's phase in words: [card title, card value, card note].
function updateText(u) {
  switch (u && u.phase) {
    case "installing": return ["Update", "Installing…", `${u.version || "the newest version"} into the idle slot; the router keeps forwarding`];
    case "installed": return ["Update", "Ready: reboot to switch", `${u.version} is installed; Reboot starts it (about a minute of downtime)`];
    case "failed": return ["Update", "Install failed", u.detail];
    default: return ["Update", "Nothing pending", "Check for updates to look for a newer version"];
  }
}
let sysUpdate = null;
async function refreshSystem() {
  const s = await api("GET", "/system");
  sysUpdate = s.update;
  const [t, v, note] = updateText(s.update);
  const c = card(t, v, note);
  if (s.update && s.update.phase === "installed") c.classList.add("warnbox");
  $("syscards").replaceChildren(card("Running version", "v" + s.version, "build " + s.build), c);
}
function sysmsg(t, cls) { $("sysmsg").textContent = t; $("sysmsg").className = cls || ""; }
$("syscheck").onclick = async () => { sysmsg("Checking…"); try {
  const r = await api("POST", "/system/update/check");
  const pre = $("sysout"); pre.textContent = r.versions; pre.classList.remove("hidden");
  sysmsg(r.available ? "Newer version available: " + r.available : "Up to date.", "ok"); } catch (e) { sysmsg(e.message, "bad"); } };
$("sysupdate").onclick = async () => {
  if (!confirm("Download and install the newest version into the idle slot? The router keeps running this version until you reboot.")) return;
  try { const r = await api("POST", "/system/update"); sysmsg(r.note, "ok"); refreshSystem().catch(() => {}); } catch (e) { sysmsg(e.message, "bad"); } };
$("sysreboot").onclick = async () => {
  await refreshSystem().catch(() => {});
  const u = sysUpdate || {};
  let q = "Reboot the router now? Traffic stops for about a minute.";
  if (u.phase === "installing")
    q = "An update is still installing. Rebooting now cancels it (the router comes back on the current version, safely). Reboot anyway?";
  else if (u.phase === "installed")
    q = `Reboot into ${u.version}? Traffic stops for about a minute. If it doesn't come up healthy, the router goes back to the current version by itself.`;
  if (!confirm(q)) return;
  try { await api("POST", "/system/reboot"); sysmsg(u.phase === "installed" ? `Rebooting into ${u.version}…` : "Rebooting…", "warn"); } catch (e) { sysmsg(e.message, "bad"); } };

$("pwform").onsubmit = async (e) => {
  e.preventDefault();
  const m = $("pwmsg");
  if ($("pwnew").value !== $("pwnew2").value) { m.textContent = "The new passwords don't match."; m.className = "bad"; return; }
  try {
    await api("POST", "/system/password", JSON.stringify({ current: $("pwcur").value, new: $("pwnew").value }), true);
    ["pwcur", "pwnew", "pwnew2"].forEach(id => $(id).value = "");
    m.textContent = "Password changed."; m.className = "ok";
  } catch (err) { m.textContent = err.message === "unauthorised" ? "Session ended." : err.message; m.className = "bad"; }
};

// ---------------------------------------------------------- configuration
// The forms edit a structured copy of the configuration (`cfg`). Nothing is
// sent until "Review & commit": then the router turns it into the config
// file, validates it and shows the diff; Commit applies it.
let cfg = null, devices = [], cfgDirty = false, cfgSec = "ifaces";

async function loadConfig() {
  $("tab-config").dataset.ready = "0"; // the forms are about to be redrawn
  const r = await api("GET", "/config/model");
  cfg = r.config; devices = r.devices; cfgDirty = false;
  renderCfg();
  updateCfgBar(r.candidate_staged, r.pending_confirm_secs);
  const c = await api("GET", "/config");
  $("cfgtext").value = c.candidate ?? c.running;
  const h = await api("GET", "/config/history");
  $("histsel").replaceChildren(...(h.length ? h.map(e => { const o = el("option", `#${e.index} · ${new Date(e.saved_unix * 1000).toLocaleString()}`); o.value = e.index; return o; })
                                             : [el("option", "no history yet")]));
  $("tab-config").dataset.ready = "1";
}

function updateCfgBar(staged, pending) {
  $("cfgstate").textContent = cfgDirty ? "Unsaved changes" : staged ? "Changes staged, not committed" : "Running configuration";
  $("cfgstate").className = cfgDirty || staged ? "warn" : "";
  $("cfgdiscard").disabled = !(cfgDirty || staged);
  $("cfgpending").classList.toggle("hidden", pending == null);
  if (pending != null) $("cfgpendingtext").textContent = `A committed change rolls back in ${pending} s unless you confirm it. `;
}
function dirty() { cfgDirty = true; updateCfgBar(); }

// --- small form builders; every value goes in as text, never as HTML
function control(c, obj) {
  const v = obj[c.key];
  let e;
  if (c.type === "select") {
    e = document.createElement("select");
    const opts = typeof c.options === "function" ? c.options() : c.options;
    const vals = opts.map(o => String(o[0]));
    if (v != null && !vals.includes(String(v))) opts.push([v, String(v)]); // keep unknown current values
    opts.forEach(([val, label]) => { const o = el("option", label); o.value = val; e.append(o); });
    e.value = v == null ? "" : String(v);
    e.onchange = () => { const x = e.value; obj[c.key] = x === "" ? (c.empty ?? null) : c.bool ? x === "true" : c.num ? Number(x) : x; dirty(); if (c.rerender) renderCfg(); };
  } else if (c.type === "check") {
    e = document.createElement("input"); e.type = "checkbox"; e.checked = !!v;
    e.onchange = () => { obj[c.key] = e.checked; dirty(); };
  } else if (c.type === "key") {
    // A pre-shared key: hidden unless asked, generated in the browser
    // (crypto.getRandomValues), copyable for the other router.
    e = el("div", undefined, "row");
    const inp = document.createElement("input");
    inp.type = "password"; inp.autocomplete = "off"; inp.spellcheck = false;
    inp.value = v || ""; inp.placeholder = c.generate === false ? "" : "none: tethers stay down";
    inp.className = "mono"; inp.style.minWidth = "14em";
    inp.oninput = () => { obj[c.key] = c.generate === false ? inp.value : (inp.value.trim() || null); dirty(); };
    const show = el("button", "Show", "btn"); show.type = "button";
    show.onclick = () => { const hidden = inp.type === "password"; inp.type = hidden ? "text" : "password"; show.textContent = hidden ? "Hide" : "Show"; };
    const gen = el("button", "Generate", "btn"); gen.type = "button";
    gen.onclick = () => {
      if (inp.value && !confirm("Replace this key? The other router must then get the new one too.")) return;
      const b = new Uint8Array(32); crypto.getRandomValues(b);
      inp.value = Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
      inp.type = "text"; show.textContent = "Hide"; inp.oninput();
    };
    const copy = el("button", "Copy", "btn"); copy.type = "button";
    copy.onclick = async () => { if (!inp.value) return; try { await navigator.clipboard.writeText(inp.value); copy.textContent = "Copied"; setTimeout(() => copy.textContent = "Copy", 1500); } catch { inp.type = "text"; inp.select(); } };
    e.append(inp, show);
    if (c.generate !== false) e.append(gen, copy);
    e.dataset.field = c.key;
    return e;
  } else {
    e = document.createElement("input");
    if (c.type === "number") { e.type = "number"; e.min = c.min ?? 0; }
    e.value = v == null ? "" : c.type === "list" ? v.join(", ") : String(v);
    if (c.placeholder) e.placeholder = c.placeholder;
    e.oninput = () => {
      const x = e.value.trim();
      obj[c.key] = c.type === "number" ? (x === "" ? (c.optional ? null : 0) : Number(x))
        : c.type === "list" ? x.split(/[,\s]+/).filter(Boolean)
        : x === "" && c.optional ? null : x;
      dirty();
    };
  }
  e.setAttribute("aria-label", c.label);
  e.dataset.field = c.key;
  return e;
}

/// An editable table bound to an array of objects.
function formTable(container, rows, cols, makeNew, addLabel) {
  container.replaceChildren();
  const t = document.createElement("table");
  const hr = el("tr"); cols.forEach(c => hr.append(el("th", c.label))); hr.append(el("th", "")); t.append(hr);
  if (!rows.length) { const r = el("tr"), d = el("td", "none", "s"); d.colSpan = cols.length + 1; r.append(d); t.append(r); }
  rows.forEach((row, i) => {
    const tr = el("tr");
    cols.forEach(c => { const d = el("td"); d.append(control(c, row)); tr.append(d); });
    const del = el("button", "Remove", "btn"); del.type = "button";
    del.onclick = () => { rows.splice(i, 1); dirty(); renderCfg(); };
    const d = el("td"); d.append(del); tr.append(d);
    t.append(tr);
  });
  const add = el("button", addLabel, "btn"); add.type = "button";
  add.onclick = () => { rows.push(makeNew()); dirty(); renderCfg(); };
  const foot = el("div", undefined, "row"); foot.style.padding = "8px 12px"; foot.append(add);
  container.append(t, foot);
}

/// A form for the fields of one object.
function formFields(container, obj, fields) {
  container.replaceChildren();
  const g = el("div", undefined, "fields");
  fields.forEach(f => {
    const l = el("label", undefined, "field");
    l.append(el("span", f.label), control(f, obj));
    if (f.help) l.append(el("small", f.help, "s"));
    g.append(l);
  });
  container.append(g);
}

/// Cards the data plane could use that no interface has claimed yet.
const unusedNics = () => devices.filter(d => !d.kernel && !cfg.interface.some(i => i.device === d.name));

/// Every network card the router found that isn't configured, so a newly
/// added NIC (e.g. PCI passthrough) is visible without guessing.
function renderNics() {
  const free = devices.filter(d => !cfg.interface.some(i => i.device === d.name));
  const box = $("f-nics");
  box.replaceChildren();
  if (!free.length) { box.append(el("p", "Every network card is in use.", "s")); return; }
  const t = document.createElement("table");
  const hr = el("tr"); ["Device", "MAC", "Driver", "Link", ""].forEach(h => hr.append(el("th", h))); t.append(hr);
  free.forEach(d => {
    const tr = el("tr");
    tr.append(el("td", d.name, "mono"), el("td", d.mac, "mono"), el("td", d.driver || "?"), el("td", d.link));
    const c = el("td");
    if (d.kernel) c.append(el("span", "management: used by the system", "s"));
    else {
      const b = el("button", "Use", "btn"); b.type = "button"; b.dataset.nic = d.name;
      b.onclick = () => { cfg.interface.push({ name: "", device: d.name, address: "", role: "inside", allow_new_sessions: null, mss_adjust: null }); dirty(); renderCfg(); };
      c.append(b);
    }
    tr.append(c); t.append(tr);
  });
  box.append(t);
}

/// Internet connection: per outside interface, static / DHCP / PPPoE.
function renderWanCfg() {
  const box = $("f-wan");
  box.replaceChildren();
  const outside = cfg.interface.filter(i => i.role === "outside");
  if (!outside.length) box.append(el("p", "No outside interface yet: set an interface's role to outside (Interfaces).", "s"));
  outside.forEach(i => {
    const mode = ["dhcp", "pppoe"].includes((i.address || "").toLowerCase()) ? i.address.toLowerCase() : "static";
    const c = el("div", undefined, "card"); c.style.marginBottom = "12px";
    c.append(el("h3", `${i.name} (${i.device})`));
    const f = el("div");
    const m = { mode };
    formFields(f, m, [{ key: "mode", label: "Connection", type: "select",
      options: [["static", "Static address"], ["dhcp", "DHCP (from the ISP)"], ["pppoe", "PPPoE (dial with a username)"]] }]);
    f.querySelector("select").onchange = e => {
      const v = e.target.value;
      i.address = v === "static" ? "" : v;
      i.pppoe = v === "pppoe" ? (i.pppoe || { username: "", password: "", service: "", mtu: null }) : null;
      if (v !== "static") i.gateway = null;
      dirty(); renderCfg();
    };
    c.append(f);
    const g = el("div");
    if (mode === "static") {
      formFields(g, i, [
        { key: "address", label: "Address / prefix", placeholder: "203.0.113.2/29" },
        { key: "gateway", label: "Gateway (the ISP's router)", optional: true, placeholder: "203.0.113.1",
          help: "Add a default route via it under Static routes to reach the internet." },
      ]);
    } else if (mode === "pppoe") {
      i.pppoe = i.pppoe || { username: "", password: "", service: "", mtu: null };
      formFields(g, i.pppoe, [
        { key: "username", label: "Username", placeholder: "you@isp" },
        { key: "password", label: "Password", type: "key", generate: false },
        { key: "service", label: "Service name", placeholder: "any (most ISPs)" },
        { key: "mtu", label: "MTU", type: "number", min: 576, optional: true, placeholder: "1492" },
      ]);
    } else {
      g.append(el("p", "The address, gateway, default route and DNS servers come from the ISP's DHCP server.", "s"));
    }
    c.append(g);
    box.append(c);
  });
}

/// SD-WAN: this router's place in the network, and the other sites.
function renderSdwanCfg() {
  const box = $("f-sdwan");
  box.replaceChildren();
  const on = document.createElement("input"); on.type = "checkbox"; on.checked = !!cfg.overlay; on.id = "sdwanon";
  on.onchange = () => {
    cfg.overlay = on.checked ? { site_id: 1, udp_port: 4800, mtu: 1440, allow_new_sessions: true, name: null, role: "mesh" } : null;
    if (!on.checked) cfg.site = [];
    dirty(); renderCfg();
  };
  const l = el("label", undefined, "field"); l.append(on, el("span", " This router is part of an SD-WAN"));
  const top = el("div", undefined, "card"); top.style.marginBottom = "12px"; top.append(l);
  box.append(top);
  if (!cfg.overlay) return;
  const f = el("div");
  formFields(f, cfg.overlay, [
    { key: "name", label: "This router's name", optional: true, placeholder: "e.g. jhb" },
    { key: "site_id", label: "Site id (unique in the network)", type: "number", min: 1 },
    { key: "role", label: "Role", type: "select", options: [["hub", "hub: connects to every site"], ["spoke", "spoke: connects only to hubs"], ["mesh", "mesh: connects to hubs and other meshes"]], empty: "mesh" },
    { key: "udp_port", label: "UDP port", type: "number", min: 1 },
    { key: "mtu", label: "Overlay MTU", type: "number", min: 576 },
    { key: "allow_new_sessions", label: "Hosts at other sites may start sessions here", type: "check" },
  ]);
  top.append(f);
  cfg.site = cfg.site || [];
  box.append(el("h2", "Other sites"), el("p",
    "Every other router in the network. Tethers are built to the sites this router's role connects to " +
    "(one per outside interface and address); the rest are reached through a hub. " +
    "Leave Addresses empty for a site without a fixed address: it's learned when that site gets in touch. " +
    "The key must be the same on both routers: generate it here, then copy it into the other router's entry for this one " +
    "(SD-WAN tab → Copy entry, after committing).", "s"));
  const t = el("div", undefined, "tablewrap");
  formTable(t, cfg.site, [
    { key: "name", label: "Name", placeholder: "cpt" },
    { key: "id", label: "Site id", type: "number", min: 1 },
    { key: "role", label: "Role", type: "select", options: [["hub", "hub"], ["spoke", "spoke"], ["mesh", "mesh"]], empty: "mesh" },
    { key: "addresses", label: "WAN addresses", type: "list", placeholder: "learned" },
    { key: "prefixes", label: "Networks", type: "list", placeholder: "10.2.0.0/16" },
    { key: "key", label: "Key", type: "key" },
  ], () => ({ name: "", id: nextSiteId(), role: "spoke", addresses: [], prefixes: [], key: null }), "Add site");
  box.append(t);
}

function nextSiteId() {
  const used = new Set([cfg.overlay?.site_id, ...(cfg.site || []).map(s => s.id)]);
  let i = 1; while (used.has(i)) i++; return i;
}

/// One card per interface: serve DHCP there or not, and how.
function renderDhcpCfg() {
  const box = $("f-dhcp");
  box.replaceChildren();
  cfg.interface.forEach(i => {
    const c = el("div", undefined, "card");
    c.style.marginBottom = "12px";
    c.append(el("h3", `${i.name || "(unnamed)"} · ${i.address || "no address"}`));
    if (["dhcp", "pppoe"].includes((i.address || "").toLowerCase())) {
      c.append(el("p", `Gets its own address (${i.address.toUpperCase()}): can't serve DHCP.`, "s"));
      box.append(c);
      return;
    }
    const on = document.createElement("input"); on.type = "checkbox"; on.checked = !!i.dhcp;
    on.dataset.dhcp = i.name;
    on.onchange = () => {
      i.dhcp = on.checked ? { range: suggestRange(i.address), lease_secs: 86400, dns: [], domain: null, reservation: [] } : null;
      dirty(); renderCfg();
    };
    const l = el("label", undefined, "field"); l.append(on, el("span", " Serve DHCP on this interface"));
    c.append(l);
    if (i.dhcp) {
      i.dhcp.dns = i.dhcp.dns || [];
      i.dhcp.reservation = i.dhcp.reservation || [];
      const f = el("div");
      formFields(f, i.dhcp, [
        { key: "range", label: "Address range", placeholder: "10.0.0.100-10.0.0.199" },
        { key: "lease_secs", label: "Lease time (s)", type: "number", min: 120 },
        { key: "dns", label: "DNS servers", type: "list", placeholder: "learned from the WAN" },
        { key: "domain", label: "Domain", optional: true, placeholder: "home.arpa" },
      ]);
      const r = el("div", undefined, "tablewrap");
      formTable(r, i.dhcp.reservation, [
        { key: "mac", label: "MAC address", placeholder: "52:54:00:12:34:56" },
        { key: "address", label: "Fixed address", placeholder: "10.0.0.10" },
        { key: "name", label: "Name", optional: true, placeholder: "nas" },
      ], () => ({ mac: "", address: "", name: null }), "Add reservation");
      c.append(f, el("h3", "Reservations"), r);
    }
    box.append(c);
  });
}

/// "10.0.0.1/24" → "10.0.0.100-10.0.0.199" (or the upper part of a small subnet).
function suggestRange(addr) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(addr || "");
  if (!m) return "";
  const ip = ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4], len = +m[5];
  const size = 2 ** (32 - len), net = ip - (ip % size);
  const str = x => [x >>> 24, (x >>> 16) & 255, (x >>> 8) & 255, x & 255].join(".");
  if (size >= 256) return `${str(net + 100)}-${str(net + 199)}`;
  if (size < 8) return "";
  return `${str(net + size / 2)}-${str(net + size - 2)}`;
}

function renderCfg() {
  if (!cfg) return;
  const ifaceNames = () => [["", "any"], ...cfg.interface.map(i => [i.name, i.name])];
  formTable($("f-ifaces"), cfg.interface, [
    { key: "name", label: "Name", placeholder: "lan" },
    { key: "device", label: "Device", type: "select", options: () => devices.filter(d => !d.kernel).map(d => [d.name, d.driver ? `${d.name} (${d.driver})` : d.name]) },
    { key: "address", label: "Address / prefix", placeholder: "10.0.0.1/24 or dhcp" },
    { key: "role", label: "Role", type: "select", options: [["inside", "inside"], ["outside", "outside"]], empty: "inside" },
    { key: "allow_new_sessions", label: "New sessions", type: "select", bool: true,
      options: [["", "default for role"], ["true", "allowed"], ["false", "replies only"]] },
    { key: "mss_adjust", label: "MSS adjust", type: "number", min: 536, optional: true, placeholder: "off" },
    { key: "gateway", label: "Gateway", optional: true, placeholder: "ISP router (static WAN)" },
  ], () => ({ name: "", device: unusedNics()[0]?.name || "", address: "", role: "inside", allow_new_sessions: null, mss_adjust: null, gateway: null, dhcp: null }), "Add interface");
  renderNics();
  renderDhcpCfg();
  renderWanCfg();
  renderSdwanCfg();

  formTable($("f-routes"), cfg.route, [
    { key: "prefix", label: "Destination prefix", placeholder: "0.0.0.0/0" },
    { key: "via", label: "Gateway", placeholder: "203.0.113.254" },
  ], () => ({ prefix: "", via: "" }), "Add route");

  formFields($("f-natmain"), cfg.nat, [
    { key: "masquerade", label: "Translate inside → outside traffic to the outside interface's address (PAT)", type: "check",
      help: "The default for internet access. Rules below take precedence." },
  ]);
  cfg.nat.pool = cfg.nat.pool || [];
  cfg.nat.rule = cfg.nat.rule || [];
  formTable($("f-pools"), cfg.nat.pool, [
    { key: "name", label: "Name", placeholder: "public" },
    { key: "addresses", label: "Addresses", type: "list", placeholder: "203.0.113.10-203.0.113.20, 203.0.113.32/29" },
  ], () => ({ name: "", addresses: [] }), "Add pool");
  formTable($("f-natrules"), cfg.nat.rule, [
    { key: "name", label: "Name", placeholder: "servers" },
    { key: "source", label: "Source", placeholder: "any", optional: true },
    { key: "destination", label: "Destination", placeholder: "any", optional: true },
    { key: "outbound", label: "Out interface", type: "select", options: ifaceNames },
    { key: "translate", label: "Translate to", type: "select", rerender: true,
      options: [["interface", "interface address"], ["pool", "pool"], ["none", "no translation"]], empty: "interface" },
    { key: "pool", label: "Pool", type: "select", options: () => [["", "—"], ...cfg.nat.pool.map(p => [p.name, p.name])] },
  ], () => ({ name: "", source: null, destination: null, outbound: null, translate: "interface", pool: null }), "Add rule");

  formFields($("f-sess"), cfg.sessions, [
    { key: "max_per_worker", label: "Sessions per worker", type: "number", min: 1, help: "Memory is reserved up front (~150 bytes each)." },
    { key: "tcp_strict", label: "Strict TCP (only a SYN may open a session)", type: "check" },
    { key: "tcp_handshake_timeout_secs", label: "TCP handshake timeout (s)", type: "number", min: 1 },
    { key: "tcp_established_timeout_secs", label: "TCP established timeout (s)", type: "number", min: 1 },
    { key: "udp_timeout_secs", label: "UDP timeout (s)", type: "number", min: 1 },
    { key: "udp_stream_timeout_secs", label: "UDP stream timeout (s)", type: "number", min: 1 },
    { key: "icmp_timeout_secs", label: "ICMP timeout (s)", type: "number", min: 1 },
  ]);
  formFields($("f-dp"), cfg.dataplane, [
    { key: "workers", label: "Worker threads (one per NIC queue)", type: "number", min: 1 },
    { key: "xdp_mode", label: "XDP mode", type: "select", options: [["auto", "auto"], ["native", "native"], ["generic", "generic"]] },
    { key: "bind_mode", label: "AF_XDP mode", type: "select", options: [["auto", "auto"], ["copy", "copy"], ["zerocopy", "zero-copy"]] },
    { key: "ring_size", label: "Ring size", type: "number", min: 64 },
    { key: "busy_poll", label: "Busy polling (lowest latency, 100% CPU)", type: "check" },
    { key: "stats_interval_secs", label: "Log statistics every (s)", type: "number", min: 1 },
  ]);
  formFields($("f-mgmt"), cfg.management, [
    { key: "enabled", label: "Web portal and API enabled", type: "check" },
    { key: "listen", label: "Listen address (plain HTTP)", placeholder: "127.0.0.1:8080",
      help: "Keep this on loopback: the portal reaches the network over HTTPS (nginx, port 8443)." },
    { key: "hostnames", label: "Extra host names", type: "list", placeholder: "router.example.net",
      help: "DNS names the portal may be opened by, besides addresses and the router's own name." },
  ]);
}

document.querySelectorAll("#cfgnav button").forEach(b => b.onclick = () => {
  cfgSec = b.dataset.sec;
  document.querySelectorAll("#cfgnav button").forEach(x => x.classList.toggle("on", x === b));
  document.querySelectorAll(".cfgsec").forEach(x => x.classList.toggle("hidden", x.id !== "sec-" + cfgSec));
});

function showDiff(d, apply, done) {
  const pre = $("cfgdiff"); pre.replaceChildren(); pre.classList.toggle("hidden", !d);
  (d || "").split("\n").forEach(line => { const s = el("span", line + "\n"); if (line.startsWith("+")) s.className = "add"; if (line.startsWith("-")) s.className = "del"; pre.append(s); });
  const before = { "unchanged": "No effect on the running router.", "live": "Will be applied live, without interrupting traffic.",
                   "restart-required": "Will be saved; some of it needs a data-plane restart to take effect." };
  const after = { "unchanged": "No effect on the running router.", "live": "Applied live, without interrupting traffic.",
                  "restart-required": "Saved; some of it takes effect after a data-plane restart." };
  return (done ? after : before)[apply] || "";
}
function msg(text, cls) { const m = $("msg"); m.textContent = text; m.className = cls || ""; }
function openReview() { $("cfgreviewbox").classList.remove("hidden"); $("cfgreviewbox").scrollIntoView({ block: "nearest" }); }

// Review: stage the edited forms (or the text) and show what would change.
async function review(fromText) {
  openReview(); $("cfgrestartrow").classList.add("hidden");
  let p;
  try {
    p = fromText ? await api("PUT", "/config/candidate", $("cfgtext").value)
                 : await api("PUT", "/config/model", JSON.stringify(cfg), true);
  } catch (e) { msg("Not valid: " + e.message, "bad"); showDiff(""); $("cfgcommit").disabled = $("cfgcommitc").disabled = true; return; }
  cfgDirty = false; updateCfgBar(true);
  const what = showDiff(p.diff, p.apply);
  $("cfgcommit").disabled = $("cfgcommitc").disabled = !p.diff;
  msg(p.diff ? "Valid. " + what : "No changes.", "ok");
}
async function commit(confirmSecs) {
  const r = await api("POST", "/config/commit" + (confirmSecs ? "?confirm=" + confirmSecs : ""));
  msg("Committed. " + showDiff(r.diff, r.applied, true) + (r.confirm_within_secs ? ` Confirm within ${r.confirm_within_secs} s or it rolls back.` : ""), "ok");
  $("cfgcommit").disabled = $("cfgcommitc").disabled = true;
  $("cfgrestartrow").classList.toggle("hidden", r.applied !== "restart-required");
  await loadConfig();
}
function guard(fn) { return async () => { try { await fn(); } catch (e) { openReview(); msg(e.message, "bad"); } }; }
$("cfgreview").onclick = guard(() => review(false));
$("cfgvalidate").onclick = guard(() => review(true));
$("cfgreviewclose").onclick = () => $("cfgreviewbox").classList.add("hidden");
$("cfgcommit").onclick = guard(() => commit(0));
$("cfgcommitc").onclick = guard(() => commit(Math.max(30, Number($("cfgconfirmsecs").value) || 120)));
$("cfgconfirm").onclick = guard(async () => { await api("POST", "/config/confirm"); await loadConfig(); });
$("cfgrestart").onclick = guard(async () => { await api("POST", "/restart"); msg("Restarting the data plane…", "warn"); });
$("cfgdiscard").onclick = guard(async () => {
  if (!confirm("Discard all changes that haven't been committed?")) return;
  await api("DELETE", "/config/candidate"); $("cfgreviewbox").classList.add("hidden"); await loadConfig();
});
$("cfgrollback").onclick = guard(async () => { const to = $("histsel").value; if (!confirm("Roll back to history entry #" + to + "?")) return;
  const r = await api("POST", "/config/rollback?to=" + to); openReview(); msg("Rolled back. " + showDiff(r.diff, r.applied, true), "ok"); await loadConfig(); });
$("radd").onclick = async () => { try { await api("POST", "/routes", JSON.stringify({ prefix: $("rprefix").value.trim(), via: $("rvia").value.trim() }), true);
  $("rprefix").value = $("rvia").value = ""; refreshRoutes(); } catch (e) { alert(e.message); } };
$("sessfilter").oninput = () => refreshSessions().catch(() => {});

function show(tab) {
  current = tab;
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === tab));
  ["dash", "reports", "sessions", "routes", "dhcp", "sdwan", "config", "system"].forEach(t => $("tab-" + t).classList.toggle("hidden", t !== tab));
  tick(true);
}
document.querySelectorAll("#tabs button").forEach(b => b.onclick = () => show(b.dataset.tab));

async function tick(first) {
  clearTimeout(timer);
  // Refresh the tab this tick started for: the user may switch tabs while
  // a request is in flight, and that tab's own tick takes care of it.
  const tab = current;
  try {
    if (tab === "dash") await refreshDash();
    else if (tab === "sessions") await refreshSessions();
    else if (tab === "routes") await refreshRoutes();
    else if (tab === "sdwan") await refreshSdwan();
    else if (tab === "dhcp") await refreshDhcp();
    else if (tab === "reports") await refreshReports();
    else if (tab === "config" && first && !cfgDirty) await loadConfig(); // never throw away unsaved edits
    else if (tab === "system") await refreshSystem();
  } catch (e) { if (e.message !== "unauthorised") console.warn(e); }
  // Reporting follows the 5-second samples; nothing polls while the page
  // is hidden (a background tab, a minimised window).
  if (tab === current && tab !== "config" && !document.hidden) timer = setTimeout(tick, tab === "reports" ? 5000 : 2000);
}

function showLogin(err) {
  signedIn = false; clearTimeout(timer);
  $("login").classList.remove("hidden"); $("loginerr").textContent = err || "";
  $("tabs").classList.add("hidden"); $("logout").classList.add("hidden"); $("meta").textContent = "";
  ["dash", "reports", "sessions", "routes", "dhcp", "sdwan", "config", "system"].forEach(t => $("tab-" + t).classList.add("hidden"));
  $("password").focus();
}
function signedInUi() {
  signedIn = true;
  $("login").classList.add("hidden"); $("tabs").classList.remove("hidden"); $("logout").classList.remove("hidden");
  show("dash");
}
$("login").onsubmit = async (e) => {
  e.preventDefault();
  $("loginerr").textContent = "";
  try {
    await api("POST", "/login", JSON.stringify({ username: $("username").value.trim(), password: $("password").value }), true);
    $("password").value = "";
    signedInUi();
  } catch (err) { if (err.message !== "unauthorised") $("loginerr").textContent = err.message; else $("loginerr").textContent = "Wrong username or password."; }
};
$("logout").onclick = async () => { try { await api("POST", "/logout"); } catch (e) {} showLogin("Signed out."); };

// Already signed in (session cookie still valid)?
api("GET", "/whoami").then(signedInUi, () => showLogin());

document.addEventListener("visibilitychange", () => {
  if (!signedIn) return;
  if (document.hidden) clearTimeout(timer); else tick();
});
