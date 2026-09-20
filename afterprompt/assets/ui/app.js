/*
 * Afterprompt browser view.
 *
 * Talks only to the scanner that served it. The key arrives in the URL fragment (never sent to any server), is
 * kept in memory, and leaves the address bar at once.
 *
 * Shape: a list and a detail pane. While the scan runs the list is its stages and the detail is the console;
 * when it finishes they become the credentials and the one you are working on. Keyboard first — arrows and j/k
 * move, Enter opens the detail, Escape comes back — because this is a list you work down, one rotation at a time.
 *
 * Every user-visible string is in TEXT, so there is one place to translate and a test can prove no sentence was
 * left inline (U-UI-19). Every node is built with textContent: a label from a scan is data, never markup.
 */
"use strict";
(function () {
  const TEXT = {
    connecting: "connecting", live: "scanning", done: "scan finished", lost: "reconnecting", refused: "refused",
    noKey: "no key", theme: "Theme", themeAuto: "Match system", themeLight: "Light", themeDark: "Dark",
    stages: "Scan", credentials: "Credentials", rotateNow: "Rotate now", review: "Review",
    needKey: "Open the link printed in your terminal: it carries the key this page needs. The key is kept out of " +
             "the address bar, so a reload needs that link again.",
    scanning: "The scan is running. Findings appear here as soon as it has triaged them.",
    nothing: "Nothing to rotate. No credential from this machine and no vendor-specific key was found in AI " +
             "tool history.",
    nothingSelected: "Choose a credential on the left to see where it leaked and how to revoke it.",
    connectionLost: "Lost the connection to the scanner. It will keep trying; the scan itself is unaffected and " +
                    "its report is written to disk either way.",
    refusedText: "The scanner refused this page's key. Open the link printed in the terminal again.",
    exposedIn: "Exposed in", stillOnDisk: "Still on disk", revoke: "Revoke", why: "Why", environments: "Environments",
    tools: "Tools", occurrences: "Occurrences", filesScanned: "Files scanned", dismissed: "Dismissed automatically",
    toReview: "To review", rotateCount: "Rotate now", console: "Console output",
    tickLabel: "Rotated and revoked", tickWhy: "Kept on this machine, by value hash, so it survives the next scan.",
    tickFailed: "Could not save that tick — the scanner may have closed. Your report on disk is unaffected.",
    coverage: "Coverage", installedNotScanned: "Installed but not scanned", notScanned: "not scanned",
    reviewOnly: "This one is weaker evidence: look at it and decide. The report has the full list.",
    of: "of",
  };

  const ICON = {   // 16×16, stroke 1.5: never a 24px icon scaled down, which lands strokes on half pixels
    dot: "M8 4.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z",
    check: "M3.5 8.5l3 3 6-6.5",
    alert: "M8 3.2 14 13H2L8 3.2Zm0 4v3m0 2.2v.1",
    key: "M10.5 3a3.5 3.5 0 1 1-3.4 4.4L3 11.5V13h1.5l.9-.9.9.9 1.2-1.2-.9-.9 1.1-1.1A3.5 3.5 0 0 1 10.5 3Z",
    spinner: "M8 1.8v2.6M8 11.6v2.6M14.2 8h-2.6M4.4 8H1.8M12.4 3.6l-1.8 1.8M5.4 10.6l-1.8 1.8M12.4 12.4l-1.8-1.8M5.4 5.4 3.6 3.6",
  };

  const $ = (id) => document.getElementById(id);
  const el = (tag, text, cls) => {
    const e = document.createElement(tag);
    if (text != null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  };
  function icon(name, tone, spin) {
    const cell = el("span", null, "ic");
    if (tone) cell.dataset.tone = tone;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.5");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    if (spin) svg.setAttribute("class", "spin");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", ICON[name]);
    svg.append(path);
    cell.append(svg);
    return cell;
  }

  // ---- key and transport
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  if (location.hash) history.replaceState(null, "", location.pathname);
  const headers = { Authorization: "Bearer " + token };
  const api = (path, opts) =>
    fetch(path, Object.assign({ headers, cache: "no-store", credentials: "omit" }, opts || {}));
  const post = (path, body) =>
    api(path, { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, headers),
                body: JSON.stringify(body) });

  const state = { stages: [], lines: [], findings: null, checklist: {}, selected: null, conn: "connecting" };

  // ---- theme: an explicit choice beats assuming the system's. Only this preference is stored in the browser;
  // nothing from the scan ever is.
  const THEME_KEY = "afterprompt.theme";
  function applyTheme(value) {
    if (value === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = value;
    try { localStorage.setItem(THEME_KEY, value); } catch (e) { /* private window: the choice lasts this page */ }
  }

  function setState(kind) {
    state.conn = kind;
    const pill = $("state");
    pill.dataset.state = kind === "live" || kind === "done" || kind === "lost" ? kind : "connecting";
    pill.textContent = TEXT[kind] || kind;
  }

  // ---- list
  function items() {
    if (!state.findings) return [];
    const rotate = state.findings.rotate.map((f) => ({ f, section: "rotate" }));
    const review = state.findings.review.slice(0, 40).map((f) => ({ f, section: "review" }));
    return rotate.concat(review);
  }

  function renderList() {
    const list = $("list");
    const heading = $("list-heading");
    list.replaceChildren();
    if (!state.findings) {
      heading.textContent = TEXT.stages;
      list.setAttribute("role", "list");
      for (const s of state.stages) {
        const li = el("li", null, "stage" + (s.done ? " done" : s.current ? " current" : ""));
        li.append(s.done ? icon("check", "success") : s.current ? icon("spinner", "quiet", true) : icon("dot", "quiet"),
                  el("span", s.label));
        list.append(li);
      }
      return;
    }
    heading.textContent = TEXT.credentials;
    list.setAttribute("role", "listbox");
    let section = null;
    for (const { f, section: sec } of items()) {
      if (sec !== section) {
        section = sec;
        const head = el("li", sec === "rotate" ? TEXT.rotateNow : TEXT.review, "group");
        head.setAttribute("role", "presentation");
        list.append(head);
      }
      const li = el("li", null, "row" + (state.checklist[f.hash] ? " ticked" : ""));
      li.id = "row-" + f.hash;
      li.setAttribute("role", "option");
      li.setAttribute("aria-selected", String(f.hash === state.selected));
      li.append(state.checklist[f.hash] ? icon("check", "success")
                : icon(sec === "rotate" ? "alert" : "key", sec === "rotate" ? "danger" : "warning"));
      li.append(el("span", f.label, "title"), el("span", f.masked, "value"));
      li.addEventListener("click", () => select(f.hash));
      list.append(li);
    }
    const active = state.selected ? "row-" + state.selected : "";
    list.setAttribute("aria-activedescendant", active);
  }

  function select(hash, scroll) {
    state.selected = hash;
    renderList();
    renderDetail();
    if (scroll) {
      const row = document.getElementById("row-" + hash);
      if (row) row.scrollIntoView({ block: "nearest" });
    }
  }

  function move(delta) {
    const all = items().map((i) => i.f.hash);
    if (!all.length) return;
    const at = all.indexOf(state.selected);
    const next = at < 0 ? 0 : Math.min(all.length - 1, Math.max(0, at + delta));
    select(all[next], true);
  }

  $("list").addEventListener("keydown", (ev) => {
    const key = ev.key;
    if (key === "ArrowDown" || key === "j") move(1);
    else if (key === "ArrowUp" || key === "k") move(-1);
    else if (key === "Home") move(-9999);
    else if (key === "End") move(9999);
    else if (key === "Enter" || key === "o") $("detail").focus();
    else return;
    ev.preventDefault();
  });
  // Escape handles the innermost thing only: from the detail back to the list, and nothing else.
  $("detail").addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") { $("list").focus(); ev.preventDefault(); }
  });

  // ---- detail
  function renderDetail() {
    const box = $("detail");
    box.replaceChildren();
    box.classList.remove("swap");
    void box.offsetWidth;                   // restart the fade; content fades in only, never out and in
    box.classList.add("swap");
    if (!token) return box.append(el("p", TEXT.needKey, "empty"));
    if (state.conn === "refused") return box.append(note(TEXT.refusedText, "danger"));
    if (!state.findings) return renderRunning(box);
    const found = items().find((i) => i.f.hash === state.selected);
    if (!found) return renderSummary(box);
    renderFinding(box, found.f, found.section);
  }

  function note(text, tone) {
    const n = el("div", null, "note");
    if (tone) n.dataset.tone = tone;
    n.append(icon("alert", tone === "danger" ? "danger" : "warning"), el("p", text));
    return n;
  }

  function renderRunning(box) {
    box.append(el("h2", TEXT.stages), el("p", TEXT.scanning, "sub"));
    if (state.conn === "lost") box.append(note(TEXT.connectionLost));
    const pre = el("pre", state.lines.join("\n"), "console");
    pre.setAttribute("aria-label", TEXT.console);
    box.append(pre);
    pre.scrollTop = pre.scrollHeight;
  }

  function renderSummary(box) {
    const d = state.findings;
    const n = d.summary.rotate;
    box.append(el("h2", n ? `${n} ${TEXT.rotateNow}` : TEXT.nothing.split(".")[0]));
    box.append(el("p", n ? TEXT.nothingSelected : TEXT.nothing, "sub"));
    const counts = el("div", null, "counts");
    for (const [v, k] of [[d.summary.rotate, TEXT.rotateCount], [d.summary.review, TEXT.toReview],
                          [d.summary.dismissed, TEXT.dismissed], [d.coverage.files, TEXT.filesScanned]]) {
      const c = el("div", null, "count");
      c.append(el("b", (v || 0).toLocaleString()), el("span", k));
      counts.append(c);
    }
    box.append(counts);
    const rows = [];
    for (const e of d.environments || []) rows.push([e.label, e.status + (e.reason ? ": " + e.reason : "")]);
    for (const i of (d.coverage.installed || []).filter((i) => i.status !== "scanned")) {
      rows.push([TEXT.installedNotScanned, `${i.product}: ${i.note}`]);
    }
    if (rows.length) {
      box.append(el("h3", TEXT.coverage));
      const table = el("table", null, "cov");
      for (const [k, v] of rows) {
        const tr = el("tr");
        tr.append(el("td", k), el("td", v));
        table.append(tr);
      }
      box.append(table);
    }
  }

  function renderFinding(box, f, section) {
    const head = el("div", null, "detail-head");
    head.append(el("h2", f.label), el("code", f.masked));
    box.append(head);
    box.append(el("p", section === "rotate" ? f.reason : TEXT.reviewOnly, "sub"));

    const facts = el("dl", null, "facts");
    const add = (term, build) => {
      const row = el("div", null, "fact");
      const dd = el("dd");
      build(dd);
      row.append(el("dt", term), dd);
      facts.append(row);
    };
    add(TEXT.exposedIn, (dd) => {
      dd.append(el("span", (f.tools || []).join(", ")));
      for (const loc of f.locations || []) {
        dd.append(el("span", loc.display + (loc.decoded ? " (decoded)" : ""), "mono"));
      }
    });
    if ((f.still_on_disk || []).length) {
      add(TEXT.stillOnDisk, (dd) => {
        for (const x of f.still_on_disk) dd.append(el("span", `${x.store} (${x.key})`, "mono"));
      });
    }
    if (f.revoke) {
      add(TEXT.revoke, (dd) => {
        if (f.revoke.url && /^https:\/\//.test(f.revoke.url)) {
          const a = el("a", f.revoke.where);
          a.href = f.revoke.url;
          a.target = "_blank";
          a.rel = "noreferrer noopener";
          dd.append(a);
        } else dd.append(el("span", f.revoke.where));
      });
    }
    add(TEXT.occurrences, (dd) => dd.append(el("span", `${f.occurrences} ${TEXT.of} ${f.files}`)));
    box.append(facts);

    if (section === "rotate") box.append(tick(f));
  }

  function tick(f) {
    const wrap = el("div", null, "tick");
    const cb = el("input");
    cb.type = "checkbox";
    cb.id = "tick-" + f.hash;
    cb.checked = !!state.checklist[f.hash];
    const label = el("label", TEXT.tickLabel);
    label.htmlFor = cb.id;                        // clicking the label works, as it should
    const text = el("div", null, "grow");
    text.append(label, el("div", TEXT.tickWhy, "why"));
    wrap.append(cb, text);
    cb.addEventListener("change", async () => {
      const want = cb.checked;
      state.checklist[f.hash] = want;             // optimistic: the control's own state is the acknowledgement
      renderList();
      const res = await post("/api/checklist", { hash: f.hash, done: want }).catch(() => null);
      if (!res || !res.ok) {
        state.checklist[f.hash] = !want;
        cb.checked = !want;
        renderList();
        wrap.after(note(TEXT.tickFailed));
      }
    });
    return wrap;
  }

  // ---- data
  async function loadFindings() {
    const r = await api("/api/findings");
    if (!r.ok) return;
    const { findings, checklist } = await r.json();
    const before = state.selected;
    state.findings = findings;
    state.checklist = checklist || {};
    // Selection survives by id, never by index; if it is gone, take its nearest surviving neighbour.
    const all = items().map((i) => i.f.hash);
    if (!all.includes(before)) state.selected = all[0] || null;
    setState("done");
    renderList();
    renderDetail();
  }

  async function refresh() {
    const r = await api("/api/status").catch(() => null);
    if (!r) return setState("lost");
    if (r.status === 401) { setState("refused"); renderDetail(); return; }
    if (!r.ok) return;
    const s = await r.json();
    state.stages = s.stages;
    if (s.finished && !state.findings) await loadFindings();
    else renderList();
  }

  async function stream() {
    try {
      const r = await api("/api/events");
      if (!r.ok) { setState(r.status === 401 ? "refused" : "refused"); renderDetail(); return; }
      setState("live");
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, i);
          buf = buf.slice(i + 2);
          if (!chunk.startsWith("data: ")) continue;
          handle(JSON.parse(chunk.slice(6)));
        }
      }
    } catch (e) { /* the scanner closed or the machine slept: reconnect below */ }
    if (state.conn !== "refused") {
      setState(state.findings ? "done" : "lost");
      renderDetail();
      setTimeout(stream, 2000);
    }
  }

  function handle(ev) {
    if (ev.type === "hello") {
      state.stages = ev.stages;
      state.lines = ev.lines || [];
      setState(ev.finished ? "done" : "live");
      if (ev.finished) loadFindings(); else { renderList(); renderDetail(); }
    } else if (ev.type === "line") {
      state.lines.push(ev.text);
      if (!state.findings) renderDetail();
    } else if (ev.type === "finished") {
      loadFindings();
    } else if (ev.type === "stage" || ev.type === "stages") {
      refresh();
    }
  }

  // ---- start
  function start() {
    $("theme-label").textContent = TEXT.theme;
    const sel = $("theme");
    const opts = [["auto", TEXT.themeAuto], ["light", TEXT.themeLight], ["dark", TEXT.themeDark]];
    opts.forEach(([v, label], i) => { sel.options[i].value = v; sel.options[i].textContent = label; });
    let saved = "auto";
    try { saved = localStorage.getItem(THEME_KEY) || "auto"; } catch (e) { /* private window */ }
    sel.value = saved;
    applyTheme(saved);
    sel.addEventListener("change", () => applyTheme(sel.value));

    if (!token) { setState("noKey"); renderDetail(); return; }
    setInterval(() => { post("/api/heartbeat", {}).catch(() => {}); }, 15000);
    post("/api/heartbeat", {}).catch(() => {});
    renderDetail();
    stream();
    $("list").focus();                      // the keyboard works without a click first
  }

  start();
})();
