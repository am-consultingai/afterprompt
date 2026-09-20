/*
 * Afterprompt browser view: three screens over one scan — Scan (while it runs), Credentials (what it found and
 * what to do), Settings (what the next scan will do).
 *
 * Talks only to the scanner that served it. The key arrives in the URL fragment (never sent to any server), is
 * kept in memory, and leaves the address bar at once. Nothing here is fetched from the internet: the vendor marks
 * and the rotation guidance are files the scanner serves.
 *
 * Every user-visible string is in TEXT (U-UI-22 proves none is left inline), and every node is built with
 * textContent, so a label that came out of a transcript is data and never markup.
 */
"use strict";
(function () {
  const TEXT = {
    connecting: "connecting", live: "scanning", done: "scan finished", lost: "reconnecting", refused: "refused",
    noKey: "no key",
    tabScan: "Scan", tabFindings: "Credentials", tabSettings: "Settings",
    needKey: "Open the link printed in your terminal: it carries the key this page needs. The key is kept out of " +
             "the address bar, so a reload needs that link again.",
    refusedText: "The scanner refused this page's key. Open the link printed in the terminal again.",
    connectionLost: "Lost the connection to the scanner. It will keep trying; the scan itself is unaffected and " +
                    "its report is written to disk either way.",
    scanRunning: "Scanning", scanDone: "Scan finished",
    scanRunningSub: "Each step stays on screen with what it found. You can move to Settings and back; the scan " +
                    "keeps running.",
    ofTotal: "of", filesFound: "found so far", totalUnknown: "total not known yet",
    console: "Console output", showConsole: "Console output",
    rotateNow: "Rotate now", review: "Review", nothingYet: "Nothing found yet.",
    nothing: "Nothing to rotate. No credential from this machine and no vendor-specific key was found in AI tool " +
             "history.",
    pickOne: "Choose a credential on the left to see where it leaked and what to do about it.",
    liveCredential: "Live credential", liveCredentialWhy: "This exact value is set up on this machine, so it is " +
                    "certainly real.",
    vendorFormat: "Vendor format", vendorFormatWhy: "It matches a credential format that vendor issues.",
    structural: "Structural match", structuralWhy: "It looks like a secret by shape rather than by format.",
    weaker: "Weaker evidence", weakerWhy: "Worth a look; decide whether it is a credential of yours.",
    exposedIn: "Exposed in", stillOnDisk: "Still on disk", occurrences: "Occurrences", inFiles: "files",
    whatToDo: "What to do", about: "about", minutes: "min", openConsole: "Open", checkAudit: "Check the audit log",
    tickLabel: "Rotated and revoked", tickWhy: "Kept on this machine, by value hash, so it survives the next scan.",
    tickFailed: "Could not save that tick — the scanner may have closed. Your report on disk is unaffected.",
    groupBy: "Grouped by", groupVendor: "vendor", groupSeverity: "urgency", groupTool: "AI tool",
    otherCreds: "Other credentials", privateKeys: "Private keys", sessionCookies: "Session cookies",
    passwords: "Passwords in text", connectionStrings: "Connection strings",
    unverified: "Not confirmed in the vendor's documentation",
    partlyVerified: "Parts of this are not confirmed in the vendor's documentation",
    settingsScan: "The next scan", settingsView: "This page",
    settingsIntro: "These are the defaults for the next scan. A command-line flag still wins over them, and they " +
                   "are saved on this machine only.",
    settingsFailed: "Could not save that change — the scanner may have closed.",
    auto: "Automatic", savedTo: "Saved in",
    coverage: "Coverage", environments: "Environments", installedNotScanned: "Installed but not scanned",
    possibleUnknown: "Possible AI tool data, not scanned", filesScanned: "Files scanned",
    dismissed: "Dismissed automatically", toReview: "To review", trademarks: "Product names and marks belong to " +
               "their owners and are shown only to identify the service.",
    done: "done", ofRotated: "rotated",
  };

  const ICON = {   // 16×16, stroke 1.5: never a 24px icon scaled down, which lands strokes on half pixels
    dot: "M8 6.2a1.8 1.8 0 1 0 0 3.6 1.8 1.8 0 0 0 0-3.6Z",
    check: "M3.5 8.5l3 3 6-6.5",
    alert: "M8 3.2 14 13H2L8 3.2Zm0 4v3m0 2.2v.1",
    key: "M10.5 3a3.5 3.5 0 1 1-3.4 4.4L3 11.5V13h1.5l.9-.9.9.9 1.2-1.2-.9-.9 1.1-1.1A3.5 3.5 0 0 1 10.5 3Z",
    cross: "M4 4l8 8M12 4l-8 8",
    chevron: "M6 4l4 4-4 4",
    spinner: "M8 1.8v2.6M8 11.6v2.6M14.2 8h-2.6M4.4 8H1.8M12.4 3.6l-1.8 1.8M5.4 10.6l-1.8 1.8M12.4 12.4l-1.8-1.8M5.4 5.4 3.6 3.6",
    external: "M6.5 3.5h-3v9h9v-3M9.5 3.5h3v3M12.5 3.5 7 9",
  };

  const $ = (id) => document.getElementById(id);
  const el = (tag, text, cls) => {
    const e = document.createElement(tag);
    if (text != null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  };
  const svgEl = (name, attrs) => {
    const e = document.createElementNS("http://www.w3.org/2000/svg", name);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    return e;
  };
  function icon(name, tone, spin) {
    const cell = el("span", null, "ic");
    if (tone) cell.dataset.tone = tone;
    const svg = svgEl("svg", { viewBox: "0 0 16 16", fill: "none", stroke: "currentColor", "stroke-width": "1.5",
                              "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" });
    if (spin) svg.setAttribute("class", "spin");
    svg.append(svgEl("path", { d: ICON[name] }));
    cell.append(svg);
    return cell;
  }
  /* A vendor mark: one ink colour in a uniform box, never a brand-coloured logotype. Vendors whose marks are not
     redistributable are drawn as a monogram instead — identification, not endorsement. */
  const isVendor = (name) => Object.values(REF.vendors.patterns || {}).includes(name);
  function vendorMark(vendor) {
    const cell = el("span", null, "mark");
    if (!isVendor(vendor)) {
      cell.append(icon("key", "quiet"));
      return cell;
    }
    const art = (REF.vendors.icons || {})[vendor];
    if (art) {
      const svg = svgEl("svg", { viewBox: "0 0 24 24", fill: "currentColor", "aria-hidden": "true" });
      svg.append(svgEl("path", { d: art.path }));
      cell.append(svg);
    } else {
      cell.append(el("span", (vendor || "?").replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase(), "mono-mark"));
    }
    return cell;
  }

  // ---- key and transport
  const params = new URLSearchParams(location.hash.slice(1));
  const token = params.get("token");
  const wantedScreen = params.get("screen");        // the link may name a screen: #token=…&screen=settings
  if (location.hash) history.replaceState(null, "", location.pathname);
  const headers = { Authorization: "Bearer " + token };
  const api = (path, opts) =>
    fetch(path, Object.assign({ headers, cache: "no-store", credentials: "omit" }, opts || {}));
  const post = (path, body) =>
    api(path, { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, headers),
                body: JSON.stringify(body) });

  const REF = { vendors: { icons: {}, patterns: {} }, rotation: { vendors: {}, generic: {}, universal: [] } };
  const state = {
    screen: ["scan", "findings", "settings"].includes(wantedScreen) ? wantedScreen : "scan",
    stages: [], progress: {}, lines: [], findings: null, checklist: {}, selected: null,
    collapsed: {}, settings: null, conn: "connecting", notice: null,
  };
  const setting = (key) => (state.settings && state.settings.values ? state.settings.values[key] : undefined);

  // ---- theme: an explicit choice beats assuming the system's. Only this preference is stored in the browser;
  // nothing from the scan ever is.
  function applyTheme(value) {
    if (!value || value === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = value;
  }

  function setState(kind) {
    state.conn = kind;
    const pill = $("state");
    pill.dataset.state = ["live", "done", "lost"].includes(kind) ? kind : "connecting";
    pill.textContent = TEXT[kind] || kind;
  }

  // ---- screens -----------------------------------------------------------
  function renderTabs() {
    const tabs = $("tabs");
    tabs.replaceChildren();
    const items = [["scan", TEXT.tabScan], ["findings", TEXT.tabFindings], ["settings", TEXT.tabSettings]];
    for (const [id, label] of items) {
      const b = el("button", label, "tab");
      b.type = "button";
      b.setAttribute("aria-current", String(state.screen === id));
      if (id === "findings" && state.findings) {
        b.append(el("span", String(state.findings.summary.rotate), "pip"));
      }
      b.addEventListener("click", () => show(id));
      tabs.append(b);
    }
  }

  function show(screen) {
    state.screen = screen;
    renderTabs();
    render();
  }

  function render() {
    const box = $("screen");
    box.replaceChildren();
    box.classList.remove("swap");
    void box.offsetWidth;                  // restart the fade; content fades in only, never out and in
    box.classList.add("swap");
    if (!token) return box.append(note(TEXT.needKey, "warning"));
    if (state.conn === "refused") return box.append(note(TEXT.refusedText, "danger"));
    $("foot").hidden = state.screen === "findings";
    if (state.screen === "settings") return renderSettings(box);
    if (state.screen === "findings") return renderFindings(box);
    renderScan(box);
  }

  function note(text, tone) {
    const n = el("div", null, "note");
    if (tone) n.dataset.tone = tone;
    n.append(icon(tone === "danger" ? "cross" : "alert", tone), el("p", text));
    return n;
  }

  // ---- scan screen
  function renderScan(box) {
    const wrap = el("section", null, "column");
    const running = !state.findings;
    wrap.append(el("h2", running ? TEXT.scanRunning : TEXT.scanDone));
    wrap.append(el("p", running ? TEXT.scanRunningSub : TEXT.pickOne, "sub"));
    if (state.conn === "lost") wrap.append(note(TEXT.connectionLost, "warning"));

    const list = el("ol", null, "phases");
    for (const s of state.stages) {
      const li = el("li", null, "phase" + (s.done ? " done" : s.current ? " current" : ""));
      const head = el("div", null, "phase-head");
      head.append(s.done ? icon("check", "success") : s.current ? icon("spinner", "accent", true) : icon("dot", "quiet"),
                  el("span", s.label, "phase-name"));
      const p = state.progress[s.name];
      if (s.done && s.summary) head.append(el("span", s.summary, "phase-note"));
      else if (p && p.note) head.append(el("span", p.note, "phase-note"));
      li.append(head);
      if (!s.done && p) li.append(progressBar(p));
      list.append(li);
    }
    wrap.append(list);

    const details = el("details", null, "console-box");
    if (running) details.open = true;
    details.append(el("summary", TEXT.showConsole));
    const pre = el("pre", state.lines.join("\n"), "console");
    pre.setAttribute("aria-label", TEXT.console);
    details.append(pre);
    wrap.append(details);
    box.append(wrap);
    pre.scrollTop = pre.scrollHeight;
  }

  /* A bar when the total is knowable, a counter when it is not — same line either way, so nothing jumps when a
     phase changes kind. Nothing here estimates: an invented total is worse than saying it is unknown. */
  function progressBar(p) {
    const wrap = el("div", null, "progress");
    if (p.total) {
      const track = el("div", null, "track");
      const fill = el("i");
      const pct = Math.max(0, Math.min(100, Math.round((p.done / p.total) * 100)));
      fill.style.width = pct + "%";
      track.setAttribute("role", "progressbar");
      track.setAttribute("aria-valuemin", "0");
      track.setAttribute("aria-valuemax", String(p.total));
      track.setAttribute("aria-valuenow", String(p.done));
      track.append(fill);
      wrap.append(track, el("span", `${p.done.toLocaleString()} ${TEXT.ofTotal} ${p.total.toLocaleString()}`, "count"));
    } else {
      wrap.append(el("span", `${p.done.toLocaleString()} ${p.note || TEXT.filesFound}`, "count"),
                  el("span", TEXT.totalUnknown, "quiet"));
    }
    return wrap;
  }

  // ---- findings: grouping
  function severityOf(f, section) {
    if (section === "review") return "review";
    return f.category === "live_credential" ? "live" : (f.tier === "A" ? "vendor" : "structural");
  }

  function vendorOf(f) {
    for (const p of f.patterns || []) {
      const v = REF.vendors.patterns[p];
      if (v) return v;
    }
    if (f.category === "live_credential") return null;          // grouped by its store instead
    const p = (f.patterns || [])[0] || "";
    if (/private_key|openssh|pkcs|pgp|putty|age_secret/.test(p)) return TEXT.privateKeys;
    if (/cookie|session/.test(p)) return TEXT.sessionCookies;
    if (/password|htpasswd|basic_auth|user_password/.test(p)) return TEXT.passwords;
    if (/conn_string|url_with_credentials/.test(p)) return TEXT.connectionStrings;
    return null;
  }

  function items() {
    if (!state.findings) return [];
    const rotate = state.findings.rotate.map((f) => ({ f, section: "rotate" }));
    const review = setting("show_review") === false ? []
      : state.findings.review.map((f) => ({ f, section: "review" }));
    return rotate.concat(review);
  }

  function groups() {
    const by = setting("group_by") || "vendor";
    const out = new Map();
    for (const it of items()) {
      let key, label, vendor = null;
      if (by === "severity") {
        key = severityOf(it.f, it.section);
        label = { live: TEXT.liveCredential, vendor: TEXT.vendorFormat, structural: TEXT.structural,
                  review: TEXT.weaker }[key];
      } else if (by === "tool") {
        label = key = (it.f.tools || [])[0] || TEXT.otherCreds;
      } else {
        vendor = vendorOf(it.f);
        label = key = vendor || TEXT.otherCreds;
      }
      if (!out.has(key)) out.set(key, { key, label, vendor, items: [], rotate: 0, review: 0, ticked: 0 });
      const g = out.get(key);
      g.items.push(it);
      g[it.section] += 1;
      if (state.checklist[it.f.hash]) g.ticked += 1;
    }
    // Groups with something to rotate come first, then by how much there is to do.
    return [...out.values()].sort((a, b) => (b.rotate > 0) - (a.rotate > 0) || b.rotate - a.rotate ||
                                            b.items.length - a.items.length || a.label.localeCompare(b.label));
  }

  function visibleRows() {
    const rows = [];
    for (const g of groups()) {
      if (state.collapsed[g.key]) continue;
      for (const it of g.items) rows.push(it.f.hash);
    }
    return rows;
  }

  function renderFindings(box) {
    const panes = el("div", null, "panes");
    const listPane = el("section", null, "pane");
    const heading = el("div", null, "pane-head");
    heading.append(el("span", `${TEXT.groupBy} ${{ vendor: TEXT.groupVendor, severity: TEXT.groupSeverity,
                                                   tool: TEXT.groupTool }[setting("group_by") || "vendor"]}`,
                      "field-label"));
    listPane.append(heading);
    const list = el("div", null, "list");
    list.id = "list";
    list.tabIndex = 0;
    list.setAttribute("role", "listbox");
    list.setAttribute("aria-activedescendant", state.selected ? "row-" + state.selected : "");
    list.addEventListener("keydown", onListKey);

    const gs = groups();
    if (!gs.length) list.append(el("p", state.findings ? TEXT.nothing : TEXT.nothingYet, "empty"));
    for (const g of gs) {
      const collapsed = !!state.collapsed[g.key];
      const head = el("button", null, "group");
      head.type = "button";
      head.setAttribute("aria-expanded", String(!collapsed));
      const chev = icon("chevron", "quiet");
      chev.classList.add("chev");
      if (!collapsed) chev.classList.add("open");
      head.append(chev);
      if (g.vendor) head.append(vendorMark(g.vendor));
      head.append(el("span", g.label, "group-name"));
      if (g.rotate) head.append(el("span", `${g.rotate}`, "pip danger"));
      if (g.review) head.append(el("span", `${g.review}`, "pip"));
      if (g.ticked) head.append(el("span", `${g.ticked} ${TEXT.done}`, "pip success"));
      head.addEventListener("click", () => {
        state.collapsed[g.key] = !collapsed;
        render();
      });
      list.append(head);
      if (collapsed) continue;
      for (const { f, section } of g.items) {
        const row = el("div", null, "row" + (state.checklist[f.hash] ? " ticked" : ""));
        row.id = "row-" + f.hash;
        row.setAttribute("role", "option");
        row.setAttribute("aria-selected", String(f.hash === state.selected));
        const sev = severityOf(f, section);
        row.append(state.checklist[f.hash] ? icon("check", "success")
                   : icon(sev === "review" ? "key" : "alert", sev === "review" ? "warning" : "danger"));
        row.append(el("span", f.label, "title"), el("span", f.masked, "value"));
        if (f.files > 1) row.append(el("span", `${f.files}`, "pip"));
        row.addEventListener("click", () => select(f.hash));
        list.append(row);
      }
    }
    listPane.append(list);
    const detail = el("section", null, "pane");
    detail.dataset.pane = "detail";
    detail.id = "detail";
    detail.tabIndex = 0;
    detail.setAttribute("aria-live", "polite");
    detail.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") { $("list").focus(); ev.preventDefault(); }
    });
    renderDetail(detail);
    panes.append(listPane, detail);
    box.append(panes);
  }

  function onListKey(ev) {
    const rows = visibleRows();
    const at = rows.indexOf(state.selected);
    const key = ev.key;
    if (key === "ArrowDown" || key === "j") select(rows[Math.min(rows.length - 1, at + 1)] || rows[0], true);
    else if (key === "ArrowUp" || key === "k") select(rows[Math.max(0, at - 1)] || rows[0], true);
    else if (key === "Home") select(rows[0], true);
    else if (key === "End") select(rows[rows.length - 1], true);
    else if (key === "ArrowRight" || key === "ArrowLeft") {
      const g = groups().find((x) => x.items.some((i) => i.f.hash === state.selected)) || groups()[0];
      if (g) { state.collapsed[g.key] = key === "ArrowLeft"; render(); $("list").focus(); }
    } else if (key === "Enter" || key === "o") $("detail").focus();
    else if (key === " ") {
      const found = items().find((i) => i.f.hash === state.selected);
      if (found) tickValue(found.f, !state.checklist[found.f.hash]);
    } else return;
    ev.preventDefault();
  }

  function select(hash, scroll) {
    if (!hash) return;
    state.selected = hash;
    render();
    const row = document.getElementById("row-" + hash);
    if (row && scroll) row.scrollIntoView({ block: "nearest" });
    if (scroll) $("list").focus();
  }

  // ---- the credential card
  function renderDetail(box) {
    const found = items().find((i) => i.f.hash === state.selected);
    if (!found) return box.append(el("p", state.findings && state.findings.summary.rotate ? TEXT.pickOne
                                      : TEXT.nothing, "empty"), coverage());
    const { f, section } = found;
    const sev = severityOf(f, section);
    const vendor = vendorOf(f);
    const head = el("div", null, "detail-head");
    if (vendor) head.append(vendorMark(vendor));
    head.append(el("h2", f.label), el("code", f.masked));
    box.append(head);

    const badge = el("div", null, "badges");
    const kind = { live: [TEXT.liveCredential, TEXT.liveCredentialWhy, "danger"],
                   vendor: [TEXT.vendorFormat, TEXT.vendorFormatWhy, "danger"],
                   structural: [TEXT.structural, TEXT.structuralWhy, "warning"],
                   review: [TEXT.weaker, TEXT.weakerWhy, "warning"] }[sev];
    const b = el("span", kind[0], "badge");
    b.dataset.tone = kind[2];
    badge.append(b, el("span", kind[1], "sub"));
    box.append(badge);

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
    add(TEXT.occurrences, (dd) => dd.append(el("span", `${f.occurrences} ${TEXT.ofTotal} ${f.files} ${TEXT.inFiles}`)));
    box.append(facts);
    box.append(actions(f, section, vendor));
    if (section === "rotate") box.append(tick(f));
  }

  /* What to do, from rotation.json: the vendor's own steps when we have them, the generic ones for the category
     otherwise, and always the two that hold whatever the credential is. */
  function actions(f, section, vendor) {
    const wrap = el("section", null, "actions");
    const guide = (REF.rotation.vendors || {})[vendor];
    const generic = (REF.rotation.generic || {})[genericKey(f, section)] || {};
    const head = el("div", null, "actions-head");
    head.append(el("h3", TEXT.whatToDo));
    const mins = (guide && guide.minutes) || generic.minutes;
    if (mins) head.append(el("span", `${TEXT.about} ${mins} ${TEXT.minutes}`, "field-label"));
    wrap.append(head);
    if (generic.headline) wrap.append(el("p", generic.headline, "sub"));

    const steps = el("ol", null, "steps");
    for (const s of (guide && guide.steps) || generic.steps || []) steps.append(el("li", s));
    for (const s of REF.rotation.universal || []) steps.append(el("li", s));
    wrap.append(steps);

    const links = el("div", null, "links");
    const link = (label, url, name) => {
      const a = el("a", null, "button");
      a.href = url;
      a.target = "_blank";
      a.rel = "noreferrer noopener";
      a.append(el("span", label), icon(name || "external", null));
      links.append(a);
    };
    if (guide && guide.console) link(`${TEXT.openConsole} ${guide.console.where}`, guide.console.url);
    else if (f.revoke && f.revoke.url && /^https:\/\//.test(f.revoke.url)) link(`${TEXT.openConsole} ${f.revoke.where}`, f.revoke.url);
    if (guide && guide.audit) link(TEXT.checkAudit, guide.audit.url);
    if (links.children.length) wrap.append(links);

    for (const n of (guide && guide.notes) || []) wrap.append(el("p", n, "quiet-note"));
    if (guide && guide.confidence && guide.confidence !== "verified") {
      wrap.append(note(TEXT.partlyVerified, "warning"));
    }
    return wrap;
  }

  function genericKey(f, section) {
    if (f.category === "live_credential") return "live_credential";
    if (f.category === "configuration") return "configuration";
    if (f.category === "session_cookie") return "session_cookie";
    if (f.category === "entropy") return "entropy";
    if (f.category === "prompt") return "prompt";
    const p = (f.patterns || []).join(" ");
    if (/private_key|openssh|pkcs|pgp|putty|age_secret/.test(p)) return "private_key";
    return section === "review" ? "entropy" : "pattern";
  }

  function tick(f) {
    const wrap = el("div", null, "tick");
    const cb = el("input");
    cb.type = "checkbox";
    cb.id = "tick-" + f.hash;
    cb.checked = !!state.checklist[f.hash];
    const label = el("label", TEXT.tickLabel);
    label.htmlFor = cb.id;
    const text = el("div", null, "grow");
    text.append(label, el("div", TEXT.tickWhy, "why"));
    wrap.append(cb, text);
    cb.addEventListener("change", () => tickValue(f, cb.checked));
    return wrap;
  }

  async function tickValue(f, want) {
    state.checklist[f.hash] = want;        // optimistic: the control's own state is the acknowledgement
    render();
    const res = await post("/api/checklist", { hash: f.hash, done: want }).catch(() => null);
    if (!res || !res.ok) {
      state.checklist[f.hash] = !want;
      state.notice = TEXT.tickFailed;
      render();
    }
  }

  function coverage() {
    const d = state.findings;
    const wrap = el("section", null, "coverage");
    if (!d) return wrap;
    const counts = el("div", null, "counts");
    for (const [v, k] of [[d.summary.rotate, TEXT.rotateNow], [d.summary.review, TEXT.toReview],
                          [d.summary.dismissed, TEXT.dismissed], [d.coverage.files, TEXT.filesScanned]]) {
      const c = el("div", null, "count");
      c.append(el("b", (v || 0).toLocaleString()), el("span", k));
      counts.append(c);
    }
    wrap.append(counts);
    const rows = [];
    for (const e of d.environments || []) rows.push([e.label, e.status + (e.reason ? ": " + e.reason : "")]);
    for (const i of (d.coverage.installed || []).filter((x) => x.status !== "scanned")) {
      rows.push([TEXT.installedNotScanned, `${i.product}: ${i.note}`]);
    }
    for (const u of d.coverage.unknown_tools || []) rows.push([TEXT.possibleUnknown, u]);
    if (rows.length) {
      wrap.append(el("h3", TEXT.coverage));
      const table = el("table", null, "cov");
      for (const [k, v] of rows) {
        const tr = el("tr");
        tr.append(el("td", k), el("td", v));
        table.append(tr);
      }
      wrap.append(table);
    }
    return wrap;
  }

  // ---- settings
  function renderSettings(box) {
    const wrap = el("section", null, "column");
    wrap.append(el("h2", TEXT.tabSettings), el("p", TEXT.settingsIntro, "sub"));
    if (state.notice) wrap.append(note(state.notice, "warning"));
    if (!state.settings) { box.append(wrap); return; }
    for (const [scope, title] of [["scan", TEXT.settingsScan], ["view", TEXT.settingsView]]) {
      wrap.append(el("h3", title));
      const cards = el("div", null, "cards");
      for (const f of state.settings.fields.filter((x) => x.scope === scope)) cards.append(settingRow(f));
      wrap.append(cards);
    }
    const where = el("p", `${TEXT.savedTo} ${state.settings.path}`, "quiet-note");
    wrap.append(where);
    box.append(wrap);
  }

  function settingRow(f) {
    const row = el("div", null, "setting");
    const text = el("div", null, "grow");
    const label = el("label", f.label);
    label.htmlFor = "set-" + f.key;
    text.append(label, el("div", f.help, "why"));
    const value = state.settings.values[f.key];
    let control;
    if (f.kind === "bool") {
      control = el("input");
      control.type = "checkbox";
      control.checked = !!value;
      control.addEventListener("change", () => saveSetting(f, control.checked, control));
    } else if (f.kind === "choice") {
      control = el("select");
      for (const c of f.choices) {
        const o = el("option", c.label);
        o.value = c.value;
        control.append(o);
      }
      control.value = value;
      control.addEventListener("change", () => saveSetting(f, control.value, control));
    } else {
      control = el("input");
      control.type = "number";
      control.min = String(f.min);
      control.max = String(f.max);
      control.value = value == null ? "" : String(value);
      control.placeholder = TEXT.auto;
      // Free text commits on blur or Enter: it is meaningless half-typed.
      control.addEventListener("change", () => saveSetting(f, control.value === "" ? "auto" : control.value, control));
    }
    control.id = "set-" + f.key;
    row.append(text, control);
    return row;
  }

  async function saveSetting(field, value, control) {
    const res = await post("/api/settings", { key: field.key, value }).catch(() => null);
    if (!res || !res.ok) {
      state.notice = TEXT.settingsFailed;
      render();
      return;
    }
    const { values } = await res.json();
    state.settings.values = values;
    state.notice = null;
    if (field.key === "ui_theme") applyTheme(values.ui_theme);
    if (["group_by", "show_review", "collapse_groups"].includes(field.key)) applyViewSettings();
    if (control) control.blur();
  }

  function applyViewSettings() {
    if (setting("collapse_groups")) {
      for (const g of groups()) state.collapsed[g.key] = true;
    }
  }

  // ---- data
  async function loadFindings() {
    const r = await api("/api/findings");
    if (!r.ok) return;
    const { findings, checklist } = await r.json();
    const before = state.selected;
    state.findings = findings;
    state.checklist = checklist || {};
    applyViewSettings();
    const all = items().map((i) => i.f.hash);
    // Selection survives by id, never by index; if it is gone, take its nearest surviving neighbour.
    if (!all.includes(before)) state.selected = all[0] || null;
    setState("done");
    if (state.screen === "scan" && !wantedScreen) show("findings");   // the result is what was asked for
    else render();
    renderTabs();
  }

  async function refresh() {
    const r = await api("/api/status").catch(() => null);
    if (!r) return setState("lost");
    if (r.status === 401) { setState("refused"); render(); return; }
    if (!r.ok) return;
    const s = await r.json();
    state.stages = s.stages;
    state.progress = s.progress || {};
    if (s.finished && !state.findings) await loadFindings();
    else if (state.screen === "scan") render();
  }

  async function loadReference() {
    for (const [key, path] of [["vendors", "/vendors.json"], ["rotation", "/rotation.json"]]) {
      const r = await fetch(path, { cache: "no-store", credentials: "omit" }).catch(() => null);
      if (r && r.ok) REF[key] = await r.json();
    }
  }

  async function loadSettings() {
    const r = await api("/api/settings").catch(() => null);
    if (!r || !r.ok) return;
    state.settings = await r.json();
    applyTheme(state.settings.values.ui_theme);
  }

  async function stream() {
    try {
      const r = await api("/api/events");
      if (!r.ok) { setState("refused"); render(); return; }
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
          if (chunk.startsWith("data: ")) handle(JSON.parse(chunk.slice(6)));
        }
      }
    } catch (e) { /* the scanner closed or the machine slept: reconnect below */ }
    if (state.conn !== "refused") {
      setState(state.findings ? "done" : "lost");
      render();
      setTimeout(stream, 2000);
    }
  }

  function handle(ev) {
    if (ev.type === "hello") {
      state.stages = ev.stages;
      state.progress = ev.progress || {};
      state.lines = ev.lines || [];
      setState(ev.finished ? "done" : "live");
      if (ev.finished) loadFindings(); else render();
    } else if (ev.type === "line") {
      state.lines.push(ev.text);
      if (state.screen === "scan") render();
    } else if (ev.type === "progress") {
      state.progress[ev.stage] = { done: ev.done, total: ev.total, note: ev.note };
      if (state.screen === "scan") render();
    } else if (ev.type === "finished") {
      loadFindings();
    } else if (ev.type === "stage" || ev.type === "stages") {
      refresh();
    }
  }

  // ---- start
  async function start() {
    renderTabs();
    if (!token) { setState("noKey"); render(); return; }
    await loadReference();
    await loadSettings();
    render();
    setInterval(() => { post("/api/heartbeat", {}).catch(() => {}); }, 15000);
    post("/api/heartbeat", {}).catch(() => {});
    $("foot").textContent = TEXT.trademarks;
    stream();
  }

  start();
})();
