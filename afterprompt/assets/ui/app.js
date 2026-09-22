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
    tabScan: "Scan", tabFindings: "Credentials", tabSettings: "Settings", tabAbout: "About",
    needKey: "Open the link printed in your terminal: it carries the key this page needs. The key is kept out of " +
             "the address bar, so a reload needs that link again.",
    refusedText: "The scanner refused this page's key. Open the link printed in the terminal again.",
    connectionLost: "Lost the connection to the scanner. It will keep trying; the scan itself is unaffected and " +
                    "its report is written to disk either way.",
    scanReady: "Ready to scan", scanStart: "Start scan", scanStarting: "Starting…",
    scanReadySub: "Nothing has been read yet. The scan opens the history your AI tools keep on this machine, " +
                  "reads the credentials already set up here, and looks for one inside the other. It stays on " +
                  "this machine: nothing is uploaded, and it starts when you press the button.",
    scanWillDo: "This scan will", scanSteps: "Steps",
    // The eleven steps are four pieces of work. The grouping is what keeps a long list from reading as a wall.
    groupFind: "Find what is here", groupRead: "Read it", groupSearch: "Look for credentials",
    groupFinish: "Decide and write", groupOf: "of",
    stepOpen: "Show what this step found", stepClose: "Hide what this step found",
    scanStartFailed: "Could not start the scan — the scanner may have closed. Run it again from the terminal.",
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
    doThis: "What to do about this one", revokeHere: "Revoke it here", replaceIt: "Then replace it in",
    searchFor: "Find it in a file by searching for",
    searchWhy: "The first characters only — enough to land on the line, and no more of the value than this " +
               "page already shows.",
    copyCmd: "Copy command", copyPath: "Copy path", copied: "Copied", copyFailed: "Press ⌘/Ctrl-C to copy",
    withCli: "From the vendor's own command line", openWith: "Open it",
    whatToDo: "What to do", about: "about", minutes: "min", openConsole: "Open", checkAudit: "Check the audit log",
    overlap: "can be rotated without downtime", breaksAtOnce: "revoking breaks callers at once",
    endsSession: "signing out ends the session at once",
    tickFailed: "Could not save that change — the scanner may have closed. Your report on disk is unaffected.",
    status: "Status", statusOpen: "Needs rotating", statusRotating: "Rotating", statusRotated: "Rotated",
    statusIgnored: "Ignored",
    statusWhy: "Kept on this machine by value hash, so it survives the next scan.",
    seen: "On this machine", seenPresent: "Still in the files it was found in",
    seenGone: "No longer in the files it was found in", seenUnknown: "Not re-checked",
    seenChecked: "checked", justNow: "just now", minutesAgo: "min ago", hoursAgo: "h ago",
    checkNow: "Check now", checking: "Checking…",
    watchdogWhy: "Afterprompt re-reads those files every few minutes while this page is open and tells you " +
                 "whether the value is still in them. Whether the credential still works is the vendor's to " +
                 "say, and this never asks them.",
    rotatedButPresent: "Rotated at the vendor, but the value is still in a file here. Deleting that history " +
                       "is a separate step.",
    sameSteps: "These need the same steps", sameStepsWhy: "Same vendor, same answer: do it once for all of them.",
    markAll: "Mark all rotated", openItem: "Open",
    groupBy: "Grouped by", groupVendor: "vendor", groupSeverity: "what it opens", groupTool: "AI tool",
    // What someone holding the value can do. The same four bands, and the same words, as the report:
    // afterprompt/impact.py is where they are defined, and a test keeps these in step with it.
    impactMoney: "Can spend money", impactData: "Can reach stored data", impactAccess: "Can act as you",
    impactService: "One service",
    impactMoneyWhy: "Whoever has this can run up charges on the account that issued it.",
    impactDataWhy: "Whoever has this can read, and usually change, what is stored there.",
    impactAccessWhy: "Whoever has this can act as you on that account or machine.",
    impactServiceWhy: "Limited to the one service that issued it.",
    startHere: "Start here", startHereWhy: "These reach furthest. The rest follow, worst first.",
    folded: "values of this kind, in the same place", unfold: "Show each one", refold: "Fold them back",
    otherCreds: "Other credentials", privateKeys: "Private keys", sessionCookies: "Session cookies",
    passwords: "Passwords in text", connectionStrings: "Connection strings",
    apiKeys: "API keys and tokens", randomTokens: "Random-looking tokens",
    fromEnvFiles: "Secrets from your .env files",
    unverified: "Not confirmed in the vendor's documentation",
    partlyVerified: "Parts of this are not confirmed in the vendor's documentation",
    settingsScan: "The next scan", settingsView: "This page",
    settingsIntro: "These are the defaults for the next scan. A command-line flag still wins over them, and they " +
                   "are saved on this machine only.",
    settingsFailed: "Could not save that change — the scanner may have closed.",
    auto: "Automatic", savedTo: "Saved in",
    machines: "Machines", machinesIntro: "Afterprompt scans this machine and every environment on it that " +
              "keeps its own AI tool history — each WSL distribution has its own home folder, and a key " +
              "pasted in one of them is invisible from the other.",
    machineThis: "This machine", machineScanned: "Scanned", machineNotScanned: "Not scanned",
    machineFiles: "Files read", machineBytes: "Read", machineFound: "Found here",
    otherHomes: "Other home folders on this machine", otherHomesWhy: "Listed, never read: Afterprompt " +
                "does not elevate and does not look inside another account's files.",
    foundOn: "Found on", everywhere: "every environment", oneMachineOnly: "Only this environment was " +
             "scanned. If you use WSL, run the scan again with WSL enabled in Settings to cover those too.",
    aboutWhat: "Afterprompt looks through the history your AI coding tools keep on this " +
               "machine and finds credentials that were pasted into a prompt or read into context.",
    aboutLocal: "Everything happens on this machine. Nothing is uploaded, and the page you are reading " +
                "is served by the scan itself on a loopback address.",
    aboutVersion: "Version", aboutLicence: "Licence", aboutScanned: "AI tools it knows about",
    aboutPatterns: "Credential patterns", aboutSource: "Source", aboutPoweredBy: "Powered by",
    aboutAm: "AM Consulting", aboutAmWhat: "Afterprompt is built and maintained by AM Consulting.",
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
    machine: "M2.5 3.5h11v7h-11zM5.5 13h5M8 10.5V13",
    box: "M8 1.8 13.5 4.6v6.8L8 14.2 2.5 11.4V4.6zM2.5 4.6 8 7.4l5.5-2.8M8 7.4V14",
    search: "M7.2 2.6a4.6 4.6 0 1 0 0 9.2 4.6 4.6 0 0 0 0-9.2ZM10.6 10.6 14 14",
    file: "M9 1.8H4.5v12.4h7V4.3ZM9 1.8V4.3h2.5",
    database: "M8 1.9c2.8 0 5 .8 5 1.8S10.8 5.5 8 5.5 3 4.7 3 3.7s2.2-1.8 5-1.8ZM3 3.7v8.6c0 1 2.2 1.8 5 1.8s5-.8 5-1.8V3.7M3 8c0 1 2.2 1.8 5 1.8S13 9 13 8",
    chat: "M2.6 3.4h10.8v7.2H7.4L4.3 13.2v-2.6H2.6z",
    doc: "M3.6 2.4h8.8v11.2H3.6zM5.8 5.6h4.4M5.8 8h4.4M5.8 10.4h2.8",
    broom: "M8 1.8v6.4M4.4 8.2h7.2l1 5.9H3.4zM6.4 8.2 5.8 14M9.6 8.2l.6 5.8",
  };

  // What each step does, as a picture. A list of eleven sentences reads as a wall; the same list with a mark
  // in front of each reads as a shape first.
  const STEP_ICON = {
    environments: "box", discover: "search", env_scan: "box", databases: "database", manifest: "file",
    vendor_raw: "key", vendor_store: "key", expand: "box", entropy_raw: "key", entropy_store: "key",
    known: "key", prompts: "chat", triage: "check", report: "doc", cleanup: "broom",
  };
  // A detail row is about a machine, a tool, a file or a value; the scanner says which.
  const ROW_ICON = { machine: "machine", container: "box", tool: "chat", file: "file", database: "database",
                     key: "key", doc: "doc", note: "dot" };

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
    screen: ["scan", "findings", "settings", "about"].includes(wantedScreen) ? wantedScreen : "scan",
    stages: [], progress: {}, lines: [], findings: null, checklist: {}, selected: null,
    collapsed: {}, unfolded: {}, settings: null, about: null, statuses: {}, checking: {},
    conn: "connecting", notice: null, started: false, starting: false, details: {}, openStep: {},
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
    const items = [["scan", TEXT.tabScan], ["findings", TEXT.tabFindings], ["settings", TEXT.tabSettings],
                   ["about", TEXT.tabAbout]];
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
    if (state.screen === "about") return renderAbout(box);
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
  // Which piece of work each step belongs to. A step Afterprompt does not know about still appears, in the
  // group it is listed near, rather than vanishing because this table was not updated.
  const GROUPS = [["find", ["environments", "discover", "env_scan"]],
                  ["read", ["databases", "manifest"]],
                  ["search", ["vendor_raw", "expand", "vendor_store", "entropy_raw", "entropy_store",
                              "known", "prompts"]],
                  ["finish", ["triage", "report", "cleanup"]]];
  const GROUP_LABEL = () => ({ find: TEXT.groupFind, read: TEXT.groupRead, search: TEXT.groupSearch,
                               finish: TEXT.groupFinish });

  function grouped(stages) {
    const out = GROUPS.map(([key, names]) => ({ key, names, steps: [] }));
    const index = new Map();
    out.forEach((g) => g.names.forEach((n) => index.set(n, g)));
    let last = out[0];
    for (const s of stages) {
      const g = index.get(s.name) || last;
      g.steps.push(s);
      last = g;
    }
    return out.filter((g) => g.steps.length);
  }

  function detailRows(name) {
    const rows = state.details[name];
    if (!rows || !rows.length) return null;
    const ul = el("ul", null, "step-detail");
    for (const r of rows) {
      const li = el("li", null, r.tone ? "tone-" + r.tone : null);
      if (r.vendor && REF.vendors.icons[r.vendor]) li.append(vendorMark(r.vendor));
      else li.append(icon(ROW_ICON[r.icon] || "dot", r.tone === "warn" ? "warning" : "quiet"));
      li.append(el("span", r.label, "step-label"));
      if (r.note) li.append(el("span", r.note, "step-note"));
      ul.append(li);
    }
    return ul;
  }

  function phases(live) {
    const box = el("div", null, "phase-groups");
    for (const g of grouped(state.stages)) {
      const done = g.steps.filter((s) => s.done).length;
      const head = el("div", null, "phase-group-head");
      head.append(el("span", GROUP_LABEL()[g.key] || g.key, "phase-group-name"));
      if (live) head.append(el("span", `${done} ${TEXT.groupOf} ${g.steps.length}`, "pip"));
      box.append(head);
      const list = el("ol", null, "phases");
      for (const s of g.steps) {
        const rows = live ? detailRows(s.name) : null;
        const li = el("li", null, "phase" + (s.done ? " done" : s.current ? " current" : ""));
        // A step that found something opens; one that has nothing to show is a line, not a dead control.
        const head2 = el(rows ? "button" : "div", null, "phase-head");
        const open = rows && (state.openStep[s.name] === undefined ? !!s.current : state.openStep[s.name]);
        if (rows) {
          head2.type = "button";
          head2.setAttribute("aria-expanded", String(!!open));
          head2.title = open ? TEXT.stepClose : TEXT.stepOpen;
          head2.addEventListener("click", () => { state.openStep[s.name] = !open; render(); });
        }
        head2.append(live && s.done ? icon("check", "success")
                     : live && s.current ? icon("spinner", "accent", true)
                     : icon(STEP_ICON[s.name] || "dot", "quiet"),
                     el("span", s.label, "phase-name"));
        const p = live ? state.progress[s.name] : null;
        if (live && s.done && s.summary) head2.append(el("span", s.summary, "phase-note"));
        else if (p && p.note) head2.append(el("span", p.note, "phase-note"));
        if (rows) {
          const chev = icon("chevron", "quiet");
          chev.classList.add("chev");
          if (open) chev.classList.add("open");
          head2.append(chev);
        }
        li.append(head2);
        if (live && !s.done && p) li.append(progressBar(p));
        if (rows && open) li.append(rows);
        list.append(li);
      }
      box.append(list);
    }
    return box;
  }

  function renderReady(wrap) {
    wrap.append(el("h2", TEXT.scanReady), el("p", TEXT.scanReadySub, "sub"));
    if (state.conn === "lost") wrap.append(note(TEXT.connectionLost, "warning"));
    if (state.notice) wrap.append(note(state.notice, "warning"));

    const go = el("button", state.starting ? TEXT.scanStarting : TEXT.scanStart, "primary");
    go.type = "button";
    go.disabled = !!state.starting;
    go.addEventListener("click", startScan);
    const row = el("div", null, "ready-go");
    row.append(go);
    wrap.append(row);

    // What it will do, in the words the Settings screen uses, so the button is never a surprise.
    const field = ((state.settings && state.settings.fields) || []).find((f) => f.key === "mode");
    const chosen = field && (field.choices || []).find((c) => c.value === setting("mode"));
    if (chosen) wrap.append(el("p", `${TEXT.scanWillDo}: ${chosen.label}`, "sub"));

    // The steps it will take, greyed, grouped the way they will be while it runs.
    if (state.stages.length) wrap.append(el("p", TEXT.scanSteps, "field-label"), phases(false));
    return wrap;
  }

  async function startScan() {
    state.starting = true;
    render();
    const r = await post("/api/start", {}).catch(() => null);
    if (!r || !r.ok) {
      state.starting = false;
      state.notice = TEXT.scanStartFailed;
      render();
      return;
    }
    state.started = true;
    state.starting = false;
    state.notice = null;
    render();
  }

  function renderScan(box) {
    const wrap = el("section", null, "column");
    // Before the scan: the page is a control, not a view. Findings from the last run may already be loaded
    // — that is what the Credentials screen is for — but this scan has still read nothing.
    if (!state.started) return box.append(renderReady(wrap));
    const running = !state.findings;
    wrap.append(el("h2", running ? TEXT.scanRunning : TEXT.scanDone));
    wrap.append(el("p", running ? TEXT.scanRunningSub : TEXT.pickOne, "sub"));
    if (state.conn === "lost") wrap.append(note(TEXT.connectionLost, "warning"));

    wrap.append(envStrip());

    wrap.append(phases(true));

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

  // How far a credential reaches, worst first. The scanner decides this (afterprompt/impact.py) and writes it
  // on every finding; a report from an older version has none, and those sort last rather than loudest.
  const IMPACT = ["money", "data", "access", "service"];
  const impactOf = (f) => (IMPACT.includes(f.impact) ? f.impact : null);
  const impactText = (band) => ({ money: [TEXT.impactMoney, TEXT.impactMoneyWhy],
                                  data: [TEXT.impactData, TEXT.impactDataWhy],
                                  access: [TEXT.impactAccess, TEXT.impactAccessWhy],
                                  service: [TEXT.impactService, TEXT.impactServiceWhy] }[band]);

  // Repeats, folded. One transcript that lists thirty generated values used to fill the list with thirty
  // near-identical rows and push everything else off the screen. Same label in the same place is one row with
  // a count, which opens. Only ever review rows: something to rotate is a thing to do, and is never hidden.
  const FOLD_FROM = 3;
  function foldKey(f, section) {
    const place = (f.locations || [])[0];
    return section === "review" && place ? section + "\u0000" + f.label + "\u0000" + place.display : null;
  }
  function fold(list) {
    const out = [], seen = new Map();
    for (const it of list) {
      const key = foldKey(it.f, it.section);
      if (!key) { out.push({ one: it }); continue; }
      if (!seen.has(key)) {
        const row = { key, label: it.f.label, members: [] };
        seen.set(key, row);
        out.push(row);
      }
      seen.get(key).members.push(it);
    }
    // A pair is not a pile: below the threshold they stay the rows they were.
    return out.flatMap((row) => (row.one || row.members.length >= FOLD_FROM ? [row]
                                                                           : row.members.map((it) => ({ one: it }))));
  }

  function vendorOf(f) {
    // The scanner names the service where it can, from the pattern that matched or from the variable the
    // value was stored under — an AZURE_STORAGE_CONNECTION_STRING in a .env belongs to Azure, not to
    // "other credentials".
    if (f.vendor) return f.vendor;
    for (const p of f.patterns || []) {
      const v = REF.vendors.patterns[p];
      if (v) return v;
    }
    const p = (f.patterns || [])[0] || "";
    if (/private_key|openssh|pkcs|pgp|putty|age_secret/.test(p)) return TEXT.privateKeys;
    if (/cookie|session/.test(p)) return TEXT.sessionCookies;
    if (/password|htpasswd|basic_auth|user_password|prose/.test(p)) return TEXT.passwords;
    if (/conn_string|url_with_credentials|_url|dsn/.test(p)) return TEXT.connectionStrings;
    if (f.category === "prompt") return TEXT.passwords;
    // What is left has no vendor and no shape worth its own name: group it by what it is instead of
    // dropping every one of them into a single "other" bucket.
    if (/jwt|bearer|http_header|auth_header|api_key|prefixed_key|token/.test(p)) return TEXT.apiKeys;
    if (/hex|generic|entropy/.test(p) || f.category === "entropy") return TEXT.randomTokens;
    if (f.still_on_disk && f.still_on_disk.length) return TEXT.fromEnvFiles;
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
      let key, label, vendor = null, rank = null;
      // "severity" is what this grouping was called when it meant how sure we were. It now means how far the
      // credential reaches, which is the question that decides what to do first; saved settings still work.
      if (by === "severity" || by === "impact") {
        key = it.section === "review" ? "review" : (impactOf(it.f) || "service");
        label = key === "review" ? TEXT.weaker : impactText(key)[0];
        rank = key === "review" ? IMPACT.length : IMPACT.indexOf(key);
      } else if (by === "tool") {
        label = key = (it.f.tools || [])[0] || TEXT.otherCreds;
      } else if (by === "machine") {
        label = key = machineLabel(it.f);
      } else {
        vendor = vendorOf(it.f);
        label = key = vendor || TEXT.otherCreds;
      }
      if (!out.has(key)) out.set(key, { key, label, vendor, rank, items: [], rotate: 0, review: 0, done: 0 });
      const g = out.get(key);
      g.items.push(it);
      g[it.section] += 1;
      if (["rotated", "ignored"].includes(statusOf(it.f))) g.done += 1;
    }
    // Bands are already in their own order, worst first; every other grouping puts what must be rotated first,
    // then by how much there is to do.
    return [...out.values()].sort((a, b) => (a.rank !== null ? a.rank - b.rank : 0) ||
                                            (b.rotate > 0) - (a.rotate > 0) || b.rotate - a.rotate ||
                                            b.items.length - a.items.length || a.label.localeCompare(b.label));
  }

  function visibleRows() {
    const rows = [];
    for (const g of groups()) {
      if (state.collapsed[g.key]) continue;
      for (const row of fold(g.items)) {
        if (row.one) rows.push(row.one.f.hash);
        else if (state.unfolded[row.key]) for (const it of row.members) rows.push(it.f.hash);
      }
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
    // A list of twenty with no order reads as an afternoon and gets abandoned after three, so name the three.
    const lead = (state.findings ? state.findings.rotate : []).slice(0, 3);
    if (lead.length === 3 && state.findings.rotate.length > 3) {
      const start = el("div", null, "start");
      start.append(el("b", TEXT.startHere), el("span", TEXT.startHereWhy, "sub"));
      const ol = el("ol");
      for (const f of lead) {
        const li = el("li");
        const b = el("button", f.label);
        b.type = "button";
        b.addEventListener("click", () => select(f.hash, true));
        li.append(b);
        const band = impactOf(f);
        if (band) li.append(el("span", impactText(band)[0], "sub"));
        ol.append(li);
      }
      start.append(ol);
      listPane.append(start);
    }
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
      if (g.done) head.append(el("span", `${g.done} ${TEXT.done}`, "pip success"));
      head.addEventListener("click", () => {
        state.collapsed[g.key] = !collapsed;
        render();
      });
      list.append(head);
      if (collapsed) continue;
      const credential = ({ f, section }, sub) => {
        const st = statusOf(f);
        const row = el("div", null, "row" + (st === "rotated" ? " ticked" : "") +
                                    (st === "ignored" ? " ignored" : "") + (sub ? " sub" : ""));
        row.id = "row-" + f.hash;
        row.setAttribute("role", "option");
        row.setAttribute("aria-selected", String(f.hash === state.selected));
        const sev = severityOf(f, section);
        row.append(st === "rotated" ? icon("check", "success")
                   : st === "ignored" ? icon("dot", "quiet")
                   : icon(sev === "review" ? "key" : "alert", sev === "review" ? "warning" : "danger"));
        const band = section === "rotate" && impactOf(f);
        if (band) {
          const dot = el("span", null, "band " + band);
          dot.title = impactText(band)[0];
          row.append(dot);
        }
        row.append(el("span", f.label, "title"), el("span", f.masked, "value"));
        if (f.files > 1) row.append(el("span", `${f.files}`, "pip"));
        row.addEventListener("click", () => select(f.hash));
        list.append(row);
      };
      for (const row of fold(g.items)) {
        if (row.one) { credential(row.one, false); continue; }
        const open = !!state.unfolded[row.key];
        const head2 = el("button", null, "row fold");
        head2.type = "button";
        head2.setAttribute("aria-expanded", String(open));
        const chev2 = icon("chevron", "quiet");
        chev2.classList.add("chev");
        if (open) chev2.classList.add("open");
        head2.append(chev2, el("span", row.label, "title"),
                     el("span", `${row.members.length} ${TEXT.folded}`, "value"),
                     el("span", `${row.members.length}`, "pip"));
        head2.title = open ? TEXT.refold : TEXT.unfold;
        head2.addEventListener("click", () => { state.unfolded[row.key] = !open; render(); });
        list.append(head2);
        if (open) for (const it of row.members) credential(it, true);
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
      if (found) setStatus(found.f, statusOf(found.f) === "rotated" ? "open" : "rotated");
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

    // How sure we are is one question; what it opens is the other, and it is the one that sets the order.
    const band = section === "rotate" && impactOf(f);
    if (band) {
      const line = el("div", null, "badges");
      const chip = el("span", impactText(band)[0], "badge band " + band);
      line.append(chip, el("span", impactText(band)[1], "sub"));
      box.append(line);
    }

    box.append(doThis(f, section, vendor));

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
      const prefix = prefixOf(f);
      for (const loc of f.locations || []) {
        const line = el("div", null, "loc");
        line.append(el("span", loc.display + (loc.decoded ? " (decoded)" : ""), "mono"));
        const rule = openRule(loc.display);
        if (rule && !loc.decoded) {
          const cmd = command(rule, loc.display, prefix);
          const tools = el("div", null, "loc-tools");
          tools.append(copyButton(cmd, TEXT.openWith), copyButton(loc.display, TEXT.copyPath),
                       el("span", rule.what, "sub"));
          line.append(tools);
        }
        dd.append(line);
      }
    });
    add(TEXT.foundOn, (dd) => {
      const line = el("div", null, "env-inline");
      for (const m of machinesOf(f)) line.append(envMark(m), el("span", m.label || m.name));
      dd.append(line);
    });
    if ((f.still_on_disk || []).length) {
      add(TEXT.stillOnDisk, (dd) => {
        for (const x of f.still_on_disk) dd.append(el("span", `${x.store} (${x.key})`, "mono"));
      });
    }
    add(TEXT.occurrences, (dd) => dd.append(el("span", `${f.occurrences} ${TEXT.ofTotal} ${f.files} ${TEXT.inFiles}`)));
    box.append(facts);
    box.append(statusBlock(f));
    box.append(actions(f, section, vendor));
    box.append(sameSteps(f, section));
  }

  function prefixOf(f) {
    // The masked value already shows its first characters; using them as a search term reveals nothing new,
    // and it is what turns "somewhere in a 40 MB transcript" into a line number.
    const head = String(f.masked || "").split("\u2026")[0].trim();
    return head.length >= 4 ? head : null;
  }

  function copyButton(text, label) {
    const b = el("button", label || TEXT.copyCmd, "copy");
    b.type = "button";
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        b.textContent = TEXT.copied;
      } catch (e) {
        b.textContent = TEXT.copyFailed;
      }
      setTimeout(() => { b.textContent = label || TEXT.copyCmd; }, 1600);
    });
    return b;
  }

  function openRule(path) {
    for (const rule of REF.rotation.open_with || []) {
      try {
        if (new RegExp(rule.match).test(path)) return rule;
      } catch (e) { /* a rule that will not compile is skipped, not fatal */ }
    }
    return null;
  }

  function command(rule, path, prefix) {
    return String(rule.run).replace("{path}", path).replace("{prefix}", prefix || "");
  }

  /* The frame at the top of a card. Everything below it is evidence; this is the instruction. */
  function doThis(f, section, vendor) {
    const wrap = el("section", null, "do-this");
    wrap.append(el("h3", TEXT.doThis));
    const kind = genericKey(f, section);
    const generic = (REF.rotation.generic || {})[kind] || {};
    const guide = vendorGuide(vendor, kind);
    if (generic.headline) wrap.append(el("p", generic.headline, "do-headline"));

    const row = el("div", null, "do-actions");
    const link = (f.revoke && f.revoke.url) || (guide && guide.console && guide.console.url);
    const where = (f.revoke && f.revoke.where) || (guide && guide.console && guide.console.where);
    if (link) {
      const a = el("a", `${TEXT.revokeHere}: ${where}`, "do-link");
      a.href = link;
      a.target = "_blank";
      a.rel = "noreferrer noopener";
      row.append(a, icon("external", "quiet"));
    } else if (where) {
      row.append(el("span", where, "sub"));
    }
    wrap.append(row);

    if ((f.still_on_disk || []).length) {
      wrap.append(el("p", `${TEXT.replaceIt} ${f.still_on_disk[0].store} (${f.still_on_disk[0].key})`, "sub"));
    }

    // The vendor's own command, where it has one. Handed over, never run.
    const cli = guide && guide.cli;
    if (cli) {
      const line = command(cli, "", prefixOf(f) || "");
      const cmd = el("div", null, "cmd");
      cmd.append(el("code", line), copyButton(line));
      wrap.append(el("p", TEXT.withCli, "field-label"), cmd, el("p", cli.what, "sub"));
    }

    const prefix = prefixOf(f);
    if (prefix) {
      const hint = el("div", null, "cmd");
      hint.append(el("code", prefix), copyButton(prefix, TEXT.copyPath));
      wrap.append(el("p", `${TEXT.searchFor}:`, "field-label"), hint, el("p", TEXT.searchWhy, "sub"));
    }
    return wrap;
  }

  /* What to do, from rotation.json: the vendor's own steps when we have them, the generic ones for the category
     otherwise, and always the two that hold whatever the credential is. */
  function actions(f, section, vendor) {
    const wrap = el("section", null, "actions");
    const kind = genericKey(f, section);
    const guide = vendorGuide(vendor, kind);
    const generic = (REF.rotation.generic || {})[kind] || {};
    const head = el("div", null, "actions-head");
    head.append(el("h3", TEXT.whatToDo));
    const mins = (guide && guide.minutes) || generic.minutes;
    if (mins) head.append(el("span", `${TEXT.about} ${mins} ${TEXT.minutes}`, "field-label"));
    if (guide && guide.downtime) {
      // A cookie has no callers to break: ending the session is the whole of the fix.
      const cost = guide.downtime === "overlap" ? TEXT.overlap
        : kind === "session_cookie" ? TEXT.endsSession : TEXT.breaksAtOnce;
      head.append(el("span", cost, "downtime"));
    }
    wrap.append(head);
    if (generic.headline) wrap.append(el("p", generic.headline, "sub"));

    const steps = el("ol", null, "steps");
    // A vendor's procedure is confident; the evidence here may not be. Say which to settle first.
    if (guide && guide.steps && generic.confirm_first) steps.append(el("li", generic.confirm_first));
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
    // The finding's own revoke link is per credential format — GitHub's fine-grained tokens have their own page —
    // so it wins over the vendor-wide console link.
    if (f.revoke && f.revoke.url && /^https:\/\//.test(f.revoke.url)) link(`${TEXT.openConsole} ${f.revoke.where}`, f.revoke.url);
    else if (guide && guide.console) link(`${TEXT.openConsole} ${guide.console.where}`, guide.console.url);
    if (guide && guide.audit) link(TEXT.checkAudit, guide.audit.url);
    if (links.children.length) wrap.append(links);

    for (const n of (guide && guide.notes) || []) wrap.append(el("p", n, "quiet-note"));
    if (guide && guide.confidence && guide.confidence !== "verified") {
      wrap.append(note(TEXT.partlyVerified, "warning"));
    }
    return wrap;
  }

  /* One vendor can issue several kinds of credential — Google hands out API keys and sets session cookies, and the
     answer is not the same for both. A "kinds" block overrides the vendor's own fields for that finding kind. */
  function vendorGuide(vendor, kind) {
    const base = (REF.rotation.vendors || {})[vendor];
    if (!base) return null;
    const special = base.kinds && base.kinds[kind];
    return special ? Object.assign({}, base, special) : base;
  }

  function genericKey(f, section) {
    if (f.category === "live_credential") return "live_credential";
    if (f.category === "configuration") return "configuration";
    if (f.category === "session_cookie") return "session_cookie";
    if (f.category === "entropy") return "entropy";
    if (f.category === "prompt") return "prompt";
    const p = (f.patterns || []).join(" ");
    if (/private_key|openssh|pkcs|pgp|putty|age_secret/.test(p)) return "private_key";
    if (/conn_string|url_with_credentials/.test(p)) return "connection_string";
    return section === "review" ? "entropy" : "pattern";
  }

  const STATUS_TEXT = { open: "statusOpen", rotating: "statusRotating", rotated: "statusRotated",
                        ignored: "statusIgnored" };

  function statusOf(f) {
    const row = state.statuses[f.hash];
    if (row && row.status) return row.status;
    return state.checklist[f.hash] ? "rotated" : "open";     // a tick from an older run meant rotated
  }

  function seenOf(f) {
    const row = state.statuses[f.hash];
    return (row && row.seen) || null;
  }

  function ago(seconds) {
    if (!seconds) return null;
    const mins = Math.round((Date.now() / 1000 - seconds) / 60);
    if (mins < 1) return TEXT.justNow;
    if (mins < 60) return `${mins} ${TEXT.minutesAgo}`;
    return `${Math.round(mins / 60)} ${TEXT.hoursAgo}`;
  }

  /* Two separate facts, side by side: what you decided, and what the machine can still see. */
  function statusBlock(f) {
    const wrap = el("section", null, "status");
    const head = el("div", null, "status-head");
    head.append(el("h3", TEXT.status));
    wrap.append(head);

    const choices = el("div", null, "choices");
    choices.setAttribute("role", "group");
    const now = statusOf(f);
    for (const value of ["open", "rotating", "rotated", "ignored"]) {
      const b = el("button", TEXT[STATUS_TEXT[value]], "choice");
      b.type = "button";
      b.setAttribute("aria-pressed", String(value === now));
      b.addEventListener("click", () => setStatus(f, value));
      choices.append(b);
    }
    wrap.append(choices, el("p", TEXT.statusWhy, "why"));

    const seen = seenOf(f);
    const line = el("div", null, "seen");
    const state_ = seen ? seen.state : null;
    line.append(icon(state_ === "present" ? "alert" : state_ === "gone" ? "check" : "dot",
                     state_ === "present" ? "warning" : state_ === "gone" ? "success" : "quiet"));
    const words = el("div", null, "grow");
    const what = state_ === "present" ? TEXT.seenPresent : state_ === "gone" ? TEXT.seenGone : TEXT.seenUnknown;
    words.append(el("div", what));
    if (seen && seen.state === "present" && (seen.in || []).length) {
      for (const where of seen.in) words.append(el("div", where, "mono"));
    }
    const when = seen && ago(seen.checked);
    if (when) words.append(el("div", `${TEXT.seenChecked} ${when}`, "why"));
    if (seen && seen.why) words.append(el("div", seen.why, "why"));
    const again = el("button", state.checking[f.hash] ? TEXT.checking : TEXT.checkNow, "button");
    again.type = "button";
    again.disabled = !!state.checking[f.hash];
    again.addEventListener("click", () => recheck(f));
    line.append(words, again);
    wrap.append(line);
    if (now === "rotated" && state_ === "present") wrap.append(note(TEXT.rotatedButPresent, "warning"));
    wrap.append(el("p", TEXT.watchdogWhy, "why"));
    return wrap;
  }

  async function setStatus(f, value) {
    const before = state.statuses[f.hash];
    state.statuses[f.hash] = Object.assign({}, before, { status: value });   // optimistic, like the tick was
    render();
    const res = await post("/api/status", { hash: f.hash, status: value }).catch(() => null);
    if (!res || !res.ok) {
      state.statuses[f.hash] = before;
      state.notice = TEXT.tickFailed;
      render();
      return;
    }
    const body = await res.json();
    state.statuses = body.statuses || state.statuses;
    state.notice = null;
    render();
  }

  async function recheck(f) {
    state.checking[f.hash] = true;
    render();
    const res = await post("/api/recheck", { hash: f.hash }).catch(() => null);
    delete state.checking[f.hash];
    if (res && res.ok) {
      const body = await res.json();
      state.statuses = body.statuses || state.statuses;
    } else {
      state.notice = TEXT.tickFailed;
    }
    render();
  }

  /* What identifies "the same job". Two Anthropic keys take the same steps whether one is confirmed live
     and the other only matched the format, so the category is not part of it — but a Google cookie and a
     Google API key do not, and the vendor's kind-specific block is what says so. */
  function actionKey(f, section) {
    const vendor = vendorOf(f);
    if (!vendor) return null;
    const base = (REF.rotation.vendors || {})[vendor];
    if (!base || !base.steps) return null;          // no vendor steps: nothing to do once for all of them
    const kind = genericKey(f, section);
    return vendor + "\u0000" + (base.kinds && base.kinds[kind] ? kind : "");
  }

  /* Everything that takes the same steps as this one. Rotating a Stripe key is one job whether it leaked
     once or nine times. */
  function siblings(f, section) {
    const key = actionKey(f, section);
    if (!key) return [];
    return items().filter((it) => it.f.hash !== f.hash && actionKey(it.f, it.section) === key);
  }

  function sameSteps(f, section) {
    const rest = siblings(f, section);
    const wrap = el("section", null, "siblings");
    if (!rest.length) return wrap;
    const head = el("div", null, "actions-head");
    head.append(el("h3", TEXT.sameSteps), el("span", String(rest.length + 1), "pip"));
    wrap.append(head, el("p", TEXT.sameStepsWhy, "sub"));
    const list = el("div", null, "sib-list");
    for (const it of [{ f, section }].concat(rest)) {
      const row = el("div", null, "sib");
      const st = statusOf(it.f);
      row.append(icon(st === "rotated" ? "check" : "dot", st === "rotated" ? "success" : "quiet"));
      const words = el("div", null, "grow");
      words.append(el("div", it.f.label), el("div", it.f.masked, "mono"));
      row.append(words, el("span", TEXT[STATUS_TEXT[st]], "pill"));
      if (it.f.hash !== f.hash) {
        const open = el("button", TEXT.openItem, "linkish");
        open.type = "button";
        open.addEventListener("click", () => select(it.f.hash));
        row.append(open);
      }
      list.append(row);
    }
    wrap.append(list);
    const all = el("button", TEXT.markAll, "button");
    all.type = "button";
    all.addEventListener("click", async () => {
      for (const it of [{ f, section }].concat(rest)) await setStatus(it.f, "rotated");
    });
    wrap.append(all);
    return wrap;
  }

  /* A WSL distribution is a separate machine as far as a leaked key is concerned: its own home folder,
     its own AI tool history, invisible from the other side. One card each, scanned or not. */
  function machineRows() {
    const d = state.findings;
    if (!d) return [];
    if ((d.environments || []).length) return d.environments;
    const cov = d.coverage || {};
    return [{ name: cov.platform, kind: "host", side: cov.platform, label: TEXT.machineThis,
              status: "scanned", files: cov.files, bytes: cov.bytes,
              rotate: (d.summary || {}).rotate, review: (d.summary || {}).review,
              other_homes: cov.other_homes || [] }];
  }

  /* Which environment a finding was found in. Merged runs stamp every finding with its side; a scan of
     one machine leaves that empty, and then the answer is simply this machine. */
  function machinesOf(f) {
    const rows = machineRows();
    const sides = f.sides || [];
    if (!sides.length) return rows.filter((m) => m.kind === "host").slice(0, 1) || [];
    return sides.map((side) => rows.find((m) => machineSide(m) === side) ||
                               { name: side, kind: side.split(":")[0], label: side });
  }

  function machineLabel(f) {
    const sides = f.sides || [];
    if (!sides.length) return TEXT.machineThis;
    const rows = machineRows();
    const named = sides.map((side) => {
      const row = rows.find((m) => machineSide(m) === side);
      return row ? (row.label || row.name) : side;
    });
    return named.length > 2 ? TEXT.everywhere : named.join(" · ");
  }

  function machineSide(m) {
    if (m.side) return m.side;
    if (m.kind === "wsl") return "wsl:" + m.name;
    if (m.kind === "folder") return "env:" + m.name;
    return m.name;
  }

  /* The environments, as a strip rather than a screen of its own: which ones were looked at, what came
     from each. A WSL distribution or a container is a separate filesystem with its own AI tool history,
     so it is named everywhere its findings are, with its own mark. */
  function envStrip() {
    const wrap = el("section", null, "envs");
    const d = state.findings;
    const rows = machineRows();
    if (!d || !rows.length) return wrap;
    wrap.append(el("h3", TEXT.environments));
    const list = el("div", null, "env-list");
    for (const m of rows) {
      const card = el("div", null, "env" + (m.status === "scanned" ? "" : " off"));
      card.append(envMark(m));
      const words = el("div", null, "grow");
      words.append(el("div", m.label || m.name, "env-name"));
      const sources = (d.coverage.sources || []).filter((x) => x.side === machineSide(m));
      const bits = [];
      if (m.status === "scanned") {
        bits.push(`${(m.files || 0).toLocaleString()} ${TEXT.inFiles}`);
        if (m.rotate || m.review) {
          bits.push(`${(m.rotate || 0).toLocaleString()} ${TEXT.rotateNow.toLowerCase()}`);
        }
        if (sources.length) bits.push(sources.map((x) => x.tool).join(", "));
      } else if (m.reason) {
        bits.push(m.reason);
      }
      if (bits.length) words.append(el("div", bits.join(" · "), "why"));
      card.append(words);
      if (m.status !== "scanned") {
        const pill = el("span", TEXT.machineNotScanned, "pill");
        pill.dataset.tone = "warn";
        card.append(pill);
      }
      list.append(card);
    }
    wrap.append(list);

    // What else was looked for and found here but not scanned — containers, VMs, other accounts.
    for (const row of (d.coverage || {}).environments_looked_for || []) {
      if (row.status !== "found_not_scanned" || !row.found) continue;
      const card = el("div", null, "env off");
      card.append(envMark({ name: row.id, kind: row.id }));
      const words = el("div", null, "grow");
      words.append(el("div", `${row.label} · ${row.found}`, "env-name"));
      const why = [row.names && row.names.length ? row.names.slice(0, 4).join(", ") : null, row.why]
        .filter(Boolean).join(" — ");
      if (why) words.append(el("div", why, "why"));
      card.append(words);
      const pill = el("span", TEXT.machineNotScanned, "pill");
      pill.dataset.tone = "warn";
      card.append(pill);
      list.append(card);
    }

    const homes = rows.reduce((acc, m) => acc.concat(m.other_homes || []), []);
    if (homes.length) {
      wrap.append(el("p", `${TEXT.otherHomes}: ${homes.join(", ")}`, "why"));
      wrap.append(el("p", TEXT.otherHomesWhy, "why"));
    }
    return wrap;
  }

  /* An environment's mark: the distribution's own where we may redistribute it, a monogram otherwise. */
  function envMark(m) {
    const env = REF.vendors.environments || {};
    const name = (m && (m.name || m.label)) || "";
    let key = null;
    for (const [rx, icon] of env.match || []) {
      if (new RegExp(rx, "i").test(name)) { key = icon; break; }
    }
    if (!key && m && m.kind && (env.kinds || {})[m.kind]) key = env.kinds[m.kind];
    // The host's own mark comes from the platform, which coverage names as a plain string.
    if (!key && m && m.kind === "host") {
      const plat = ((state.findings || {}).coverage || {}).platform;
      key = (env.platforms || {})[plat] || null;
    }
    const cell = el("span", null, "mark");
    const art = (REF.vendors.icons || {})[key];
    if (!art) {
      cell.append(el("span", (name || "?").replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "?",
                     "mono-mark"));
      return cell;
    }
    const svg = svgEl("svg", { viewBox: "0 0 24 24", fill: "currentColor", "aria-hidden": "true" });
    svg.append(svgEl("path", { d: art.path }));
    cell.append(svg);
    cell.title = art.title || key;
    return cell;
  }

  function bytes(n) {
    const mb = n / (1024 * 1024);
    return mb >= 1024 ? (mb / 1024).toFixed(1) + " GB" : mb.toFixed(1) + " MB";
  }

  function renderAbout(host) {
    const box = el("section", null, "column");
    host.append(box);
    const head = el("section", null, "about-head");
    const art = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    art.setAttribute("viewBox", "0 0 64 40");
    art.setAttribute("width", "96");
    art.setAttribute("height", "60");
    art.setAttribute("aria-hidden", "true");
    art.setAttribute("fill", "none");
    art.setAttribute("stroke", "currentColor");
    art.setAttribute("stroke-width", "5.5");
    art.setAttribute("stroke-linecap", "round");
    art.setAttribute("stroke-linejoin", "round");
    for (const d of ["M6 8 L18 20 L6 32", "M40 20 H57", "M47 20 V26", "M53 20 V25"]) {
      const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
      p.setAttribute("d", d);
      art.append(p);
    }
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("cx", "33"); c.setAttribute("cy", "20"); c.setAttribute("r", "7");
    art.append(c);
    const words = el("div", null, "grow");
    words.append(el("h2", "Afterprompt"), el("p", TEXT.aboutWhat, "sub"));
    head.append(art, words);
    box.append(head);
    box.append(el("p", TEXT.aboutLocal, "sub"));

    const a = state.about || {};
    const facts = el("dl", null, "facts");
    const add = (k, v) => { const row = el("div", null, "fact");
                            row.append(el("dt", k), el("dd", v)); facts.append(row); };
    if (a.version) add(TEXT.aboutVersion, a.version);
    if (a.tools) add(TEXT.aboutScanned, String(a.tools));
    if (a.patterns) add(TEXT.aboutPatterns, String(a.patterns));
    if (a.licence) add(TEXT.aboutLicence, a.licence);
    box.append(facts);

    if (a.source) {
      const links = el("div", null, "links");
      const link = el("a", null, "button");
      link.href = a.source;
      link.target = "_blank";
      link.rel = "noreferrer noopener";
      link.append(el("span", TEXT.aboutSource), icon("external", null));
      links.append(link);
      box.append(links);
    }

    const by = el("section", null, "powered");
    by.append(el("div", TEXT.aboutPoweredBy, "field-label"));
    const amLink = el("a");
    amLink.href = (a.vendor && a.vendor.url) || "https://www.amconsulting.ai";
    amLink.target = "_blank";
    amLink.rel = "noreferrer noopener";
    // Two files, one shown at a time by CSS: the blue wordmark has too little contrast on the dark
    // background, and the white one disappears on the light one.
    for (const [src, cls, alt] of [["/logo/am-logo.png", "am-light", (a.vendor && a.vendor.name) || TEXT.aboutAm],
                                   ["/logo/am-logo-white.png", "am-dark", ""]]) {
      const am = el("img");
      am.src = src;
      am.classList.add("am-logo", cls);
      am.alt = alt;
      am.width = 180;
      am.height = 49;
      if (!alt) am.setAttribute("aria-hidden", "true");
      amLink.append(am);
    }
    by.append(amLink, el("p", TEXT.aboutAmWhat, "why"));
    box.append(by);
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
  async function loadFindings(done) {
    const r = await api("/api/findings");
    if (!r.ok) return;
    const { findings, checklist, statuses } = await r.json();
    const before = state.selected;
    state.findings = findings;
    state.checklist = checklist || {};
    state.statuses = statuses || {};
    applyViewSettings();
    const all = items().map((i) => i.f.hash);
    // Selection survives by id, never by index; if it is gone, take its nearest surviving neighbour.
    if (!all.includes(before)) state.selected = all[0] || null;
    if (done) setState("done");
    // The end of the scan moves the screen, because the result is what was asked for. Findings that arrive
    // mid-scan, or from the last scan, fill the tab and wait to be opened.
    if (done && state.screen === "scan" && !wantedScreen) show("findings");
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
    state.started = !!s.started || !!s.finished;
    state.details = s.details || {};
    if (s.finished && !state.findings) await loadFindings(true);
    else if (s.findings_ready && !state.findings) await loadFindings(false);
    else if (state.screen === "scan") render();
  }

  async function loadReference() {
    for (const [key, path] of [["vendors", "/vendors.json"], ["rotation", "/rotation.json"]]) {
      const r = await fetch(path, { cache: "no-store", credentials: "omit" }).catch(() => null);
      if (r && r.ok) REF[key] = await r.json();
    }
  }

  async function loadAbout() {
    const r = await api("/api/about").catch(() => null);
    if (r && r.ok) state.about = await r.json();
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
      state.started = !!ev.started || !!ev.finished;
      state.details = ev.details || {};
      setState(ev.finished ? "done" : "live");
      if (ev.finished) loadFindings(true);
      else { if (ev.findings_ready) loadFindings(false); render(); }
    } else if (ev.type === "line") {
      state.lines.push(ev.text);
      if (state.screen === "scan") render();
    } else if (ev.type === "progress") {
      state.progress[ev.stage] = { done: ev.done, total: ev.total, note: ev.note };
      if (state.screen === "scan") render();
    } else if (ev.type === "status") {
      state.statuses[ev.hash] = ev.row;
      if (state.screen === "findings") render();
    } else if (ev.type === "seen") {
      // The watchdog looked again: keep what it saw beside what the person decided.
      for (const [h, seen] of Object.entries(ev.seen || {})) {
        if (!seen) continue;
        state.statuses[h] = Object.assign({}, state.statuses[h], { seen });
      }
      if (state.screen === "findings") render();
    } else if (ev.type === "findings") {
      loadFindings(false);
    } else if (ev.type === "finished") {
      loadFindings(true);
    } else if (ev.type === "detail") {
      state.details[ev.stage] = ev.rows || [];
      if (state.screen === "scan") render();
    } else if (ev.type === "started") {
      state.started = true;
      refresh();
    } else if (ev.type === "stage" || ev.type === "stages") {
      refresh();
    }
  }

  // ---- start
  async function start() {
    renderTabs();
    if (!token) { setState("noKey"); render(); return; }
    await loadReference();
    await loadAbout();
    await loadSettings();
    render();
    setInterval(() => { post("/api/heartbeat", {}).catch(() => {}); }, 15000);
    post("/api/heartbeat", {}).catch(() => {});
    $("foot").textContent = TEXT.trademarks;
    stream();
  }

  start();
})();
