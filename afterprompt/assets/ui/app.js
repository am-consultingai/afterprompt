// Afterprompt local UI. Talks only to the scanner that served it. The key arrives in the URL fragment (never sent
// to any server), is kept in memory, and is removed from the address bar at once.
"use strict";
(function () {
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  if (location.hash) history.replaceState(null, "", location.pathname);
  const $ = (id) => document.getElementById(id);
  const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; };
  if (!token) { $("notoken").hidden = false; $("conn").textContent = "no key"; return; }
  const headers = { "Authorization": "Bearer " + token };
  const api = (path, opts) => fetch(path, Object.assign({ headers: headers, cache: "no-store", credentials: "omit" }, opts || {}));
  const post = (path, body) => api(path, { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, headers), body: JSON.stringify(body) });

  let state = { stages: [], lines: [] };
  function renderStages() {
    const ol = $("stages"); ol.replaceChildren();
    for (const s of state.stages) ol.append(el("li", s.label, s.done ? "done" : (s.current ? "current" : "")));
  }
  function addLine(t) { const log = $("log"); log.textContent += t + "\n"; log.scrollTop = log.scrollHeight; }

  async function refresh() {
    const r = await api("/api/status"); if (!r.ok) return;
    const s = await r.json(); state.stages = s.stages; renderStages();
    if (s.finished) showFindings();
  }

  async function showFindings() {
    const r = await api("/api/findings"); if (!r.ok) return;
    const { findings: d, checklist } = await r.json();
    $("results").hidden = false;
    const n = d.summary.rotate;
    $("headline").textContent = n ? `${n} credential${n === 1 ? "" : "s"} to rotate` : "Nothing to rotate";
    $("context").textContent = `${d.mode} scan · ${d.finished.replace("T", " ").slice(0, 16)}`;
    const stats = $("stats"); stats.replaceChildren();
    for (const [v, k] of [[d.summary.rotate, "Rotate now"], [d.summary.review, "To review"],
                          [d.summary.dismissed, "Dismissed"], [d.coverage.files, "Files scanned"]]) {
      const s = el("div", null, "stat"); s.append(el("b", (v || 0).toLocaleString()), el("span", k)); stats.append(s);
    }
    const ul = $("rotate"); ul.replaceChildren();
    $("rotate-empty").hidden = d.rotate.length > 0;
    for (const f of d.rotate) {
      const li = el("li"); const lab = el("label"); const cb = el("input"); cb.type = "checkbox";
      cb.checked = !!checklist[f.hash]; li.classList.toggle("ticked", cb.checked);
      cb.addEventListener("change", async () => {
        li.classList.toggle("ticked", cb.checked);
        const res = await post("/api/checklist", { hash: f.hash, done: cb.checked });
        if (!res.ok) { cb.checked = !cb.checked; li.classList.toggle("ticked", cb.checked); }
      });
      lab.append(cb, el("span", `${f.id}. ${f.label} `), el("code", f.masked)); li.append(lab);
      const where = (f.locations || []).map((l) => l.display).join(" · ");
      li.append(el("div", `Exposed in ${(f.tools || []).join(", ")}: ${where}`, "meta"));
      if ((f.still_on_disk || []).length) li.append(el("div", "Still on disk: " + f.still_on_disk.map((x) => `${x.store} (${x.key})`).join(", "), "meta"));
      if (f.revoke) {
        const m = el("div", "Revoke: ", "meta");
        if (f.revoke.url && /^https:\/\//.test(f.revoke.url)) {
          const a = el("a", f.revoke.where); a.href = f.revoke.url; a.target = "_blank"; a.rel = "noreferrer noopener"; m.append(a);
        } else m.append(document.createTextNode(f.revoke.where));
        li.append(m);
      }
      ul.append(li);
    }
    const rv = $("review"); rv.replaceChildren();
    const counts = {};
    for (const f of d.review) counts[f.category] = (counts[f.category] || 0) + 1;
    for (const [c, k] of Object.entries(counts)) rv.append(el("li", `${c.replace("_", " ")}: ${k} (details in report.html)`));
    const cov = $("coverage"); cov.replaceChildren();
    for (const e of d.environments || []) {
      const tr = el("tr"); tr.append(el("td", e.label), el("td", e.status + (e.reason ? ": " + e.reason : ""))); cov.append(tr);
    }
    for (const i of (d.coverage.installed || []).filter((i) => i.status !== "scanned")) {
      const tr = el("tr"); tr.append(el("td", "Installed but not scanned"), el("td", `${i.product}: ${i.note}`)); cov.append(tr);
    }
  }

  async function stream() {
    try {
      const r = await api("/api/events");
      if (!r.ok) { $("conn").textContent = r.status === 401 ? "wrong key" : "refused"; $("conn").className = "pill bad"; return; }
      $("conn").textContent = "live"; $("conn").className = "pill ok";
      const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = "";
      for (;;) {
        const { value, done } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, i); buf = buf.slice(i + 2);
          if (!chunk.startsWith("data: ")) continue;
          const ev = JSON.parse(chunk.slice(6));
          if (ev.type === "hello") { state.stages = ev.stages; renderStages(); for (const l of ev.lines) addLine(l); if (ev.finished) showFindings(); }
          else if (ev.type === "line") addLine(ev.text);
          else if (ev.type === "stage" || ev.type === "stages") refresh();
          else if (ev.type === "finished") { refresh(); }
        }
      }
    } catch (e) { /* fall through to reconnect */ }
    $("conn").textContent = "reconnecting…"; $("conn").className = "pill";
    setTimeout(stream, 2000);
  }

  setInterval(() => { post("/api/heartbeat", {}).catch(() => {}); }, 15000);
  post("/api/heartbeat", {}).catch(() => {});
  stream();
})();
