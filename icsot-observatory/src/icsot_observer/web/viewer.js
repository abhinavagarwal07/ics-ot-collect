"use strict";

// Captured strings are always inserted as text. No captured HTML, Markdown,
// URLs or script can become executable content in the local viewer.
const $ = (id) => document.getElementById(id);
const state = {repos: [], repo: null, metadataStatus: null, captures: [], left: "", right: "", category: "issues", comparison: null, items: [], item: null, tab: "fields", offset: 0, total: 0, token: "", epoch: 0, loading: false, repoLoading: false, comparisonLoading: false, comparisonKnown: false, gitBusy: false, gitResult: null, gitSelection: null, gitPath: null};
const categories = {issues: "Issues", pulls: "Pull requests", comments: "Comments", releases: "Releases", tags: "Tags", events: "Events", git: "Git refs & files", coverage: "Coverage & proofs"};
const key = (o) => String(o?.key ?? o?.id ?? "");
const list = (v) => Array.isArray(v) ? v : [];
const text = (v, max = 5000) => {
  if (v === undefined) return "—";
  if (v === null) return "null";
  const value = typeof v === "string" ? v : JSON.stringify(v, null, 2);
  return value.length > max ? value.slice(0, max) + "\n… excerpt limited in viewer" : value;
};
const human = (v) => ({not_observed_right: "not observed in B", not_observed_left: "not observed in A", not_advertised_right: "not advertised in B", not_advertised_left: "not advertised in A"}[v] ?? String(v ?? "unavailable").replaceAll("_", " "));
function el(tag, className, content) { const node = document.createElement(tag); if (className) node.className = className; if (content !== undefined) node.textContent = String(content); return node; }
function replace(id, ...nodes) { $(id).replaceChildren(...nodes); }
function notice(message = "", error = false) { $("notice").hidden = !message; $("notice").classList.toggle("error", error); $("notice").textContent = message; }
function busy(message = "") { $("loading").hidden = !message; $("loading-text").textContent = message; }
function badge(label, type = "neutral") { return el("span", "badge " + type, human(label).toUpperCase()); }
function statusStyle(value) {
  const v = String(value ?? "").toLowerCase();
  if (/added|observed|loaded|complete|verified|available|local/.test(v) && !/unavailable|not |not_|unverified/.test(v)) return "success";
  if (/changed|moved|modified/.test(v)) return "blue";
  if (/gap|partial|pending|not.observed|metadata|not.advertised/.test(v)) return "warning";
  if (/error|failed|invalid/.test(v)) return "danger";
  return "neutral";
}
function captureDate(c, full = false) {
  const value = c?.captured_at ?? c?.interval?.completed_at ?? c?.interval?.started_at ?? c?.capture_id ?? c?.run_id;
  if (!value) return "Time unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return text(value, 100);
  return date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, full ? " UTC" : "").slice(0, full ? undefined : 19);
}
function loaded(c) { return /^(loaded|local|available|ready|decrypted)$/.test(c?.load_state ?? ""); }
function repoSlug(r) { return r?.slug ?? r?.name ?? r?.repository_id ?? key(r); }
async function api(path, body) {
  const options = {cache: "no-store", credentials: "same-origin", headers: {Accept: "application/json"}};
  if (body !== undefined) { options.method = "POST"; options.headers["Content-Type"] = "application/json"; options.headers["X-Viewer-Token"] = state.token; options.body = JSON.stringify(body); }
  const response = await fetch(path, options);
  const value = await response.json();
  if (!response.ok) throw new Error(value?.error?.message ?? "The local viewer could not read this result.");
  return value;
}
function query(path, values) { return path + "?" + new URLSearchParams(values).toString(); }
function captureCountKnown(repo) {
  if (typeof repo?.capture_count_known === "boolean") return repo.capture_count_known;
  if (typeof repo?.remote_discovery?.availability_known === "boolean") return repo.remote_discovery.availability_known;
  if (state.metadataStatus && state.metadataStatus.state !== "complete") return false;
  return !(Number(repo?.pending_index_count ?? 0) > 0 && !repo?.capture_count);
}
function metadataStatus(value) {
  if (value) state.metadataStatus = value;
  const status = state.metadataStatus, box = $("metadata-status");
  const repoPartial = state.repo?.remote_discovery?.state === "partial";
  const sessionLimited = status?.state === "session_limit" || [[status?.attempts, status?.max_attempts], [status?.bytes_read, status?.byte_limit], [status?.request_count, status?.request_limit]].some(([used, limit]) => Number.isFinite(used) && Number.isFinite(limit) && limit > 0 && used >= limit);
  box.replaceChildren();
  box.hidden = !status || (status.state === "complete" && !repoPartial && !sessionLimited);
  $("refresh").title = "Refresh local metadata and explicitly retry remote metadata when allowed";
  $("refresh").setAttribute("aria-label", "Refresh local and remote metadata");
  if (box.hidden) return;
  const title = sessionLimited ? "Remote metadata session limit reached" : status.state === "offline" ? "Offline · local evidence only" : status.state === "rate_limited" ? "Remote metadata paused · GitHub rate limit" : repoPartial && status.state === "complete" ? "Selected repository metadata is incomplete" : status.state === "partial" ? "Remote metadata is incomplete" : "Remote metadata is unavailable";
  box.append(el("strong", "", title), el("p", "", "Registered local evidence remains available. Remote capture totals and history coverage are unknown wherever discovery is incomplete; an unknown count is not zero."));
  if (status.last_error) box.append(el("p", "", text(status.last_error, 600)));
  let retry = "";
  if (sessionLimited) retry = "The session metadata byte, request, or attempt limit has been reached. Remote metadata cannot be retried in this server session. Continue browsing registered evidence locally.";
  else if (status.retry_at) {
    const date = new Date(status.retry_at), label = Number.isNaN(date.getTime()) ? text(status.retry_at, 100) : date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
    retry = Number.isNaN(date.getTime()) || date.getTime() > Date.now() ? "Use Refresh (↻) after " + label + " to retry. Remote requests stay paused until then." : "The retry time has arrived. Use Refresh (↻) to retry remote metadata.";
  } else if (status.retry_allowed) retry = "Use Refresh (↻) to retry remote metadata. Opening repositories does not automatically retry a failed catalog request.";
  else if (status.state === "offline") retry = "Remote discovery is disabled for this server session.";
  else retry = "Remote retries are currently unavailable. Refresh still updates registered local metadata.";
  box.append(el("p", "", retry));
  $("refresh").title = retry;
}
function renderRepos() {
  const search = $("repo-search").value.toLowerCase().trim();
  const role = $("role-filter").value, status = $("status-filter").value;
  const filtered = state.repos.filter((r) => {
    const count = Number(r.capture_count ?? 0);
    const known = captureCountKnown(r);
    const local = loaded(r);
    return (!search || [repoSlug(r), r.role, r.cohort].join(" ").toLowerCase().includes(search)) && (!role || r.role === role) && (!status || (status === "local" ? local : status === "none" ? count === 0 && known : (count > 0 || !known) && !local));
  });
  $("repo-count").textContent = String(state.repos.length);
  const nodes = filtered.map((r) => {
    const slug = repoSlug(r), slash = slug.indexOf("/"), owner = slash < 0 ? "" : slug.slice(0, slash), name = slash < 0 ? slug : slug.slice(slash + 1);
    const button = el("button", "repo-button" + (key(r) === key(state.repo) ? " active" : ""));
    button.type = "button"; button.title = slug; button.setAttribute("aria-pressed", String(key(r) === key(state.repo)));
    const meta = el("span", "repo-meta"), sub = el("span", "repo-owner");
    meta.append(el("span", "repo-name", name));
    sub.append(el("span", "status-dot" + (loaded(r) ? " local" : "")), document.createTextNode([owner, r.role && human(r.role)].filter(Boolean).join(" · ")));
    const known = captureCountKnown(r), registered = Number(r.capture_count ?? 0);
    const count = el("span", "repo-count", known ? registered : registered ? registered + "+" : "?");
    count.title = known ? "Registered captures" : registered + " registered captures; remote capture total is unknown";
    meta.append(sub); button.append(el("span", "repo-glyph", "◇"), meta, count);
    button.addEventListener("click", () => chooseRepo(r));
    return button;
  });
  replace("repo-list", ...(nodes.length ? nodes : [el("p", "repo-empty", "No repositories match these filters.")]));
}
async function budget() {
  try {
    const b = await api("/api/budget");
    const used = b.admitted_bytes ?? b.allocated_bytes ?? b.used_bytes ?? b.current_bytes ?? b.bytes_used ?? b.local_bytes;
    const cap = b.limit_bytes ?? b.max_bytes ?? b.budget_bytes ?? 2000000000;
    $("budget-label").textContent = used === undefined ? "Local disk limit · " + (cap / 1e9).toFixed(1) + " GB" : (used / 1e6).toFixed(0) + " MB / " + (cap / 1e9).toFixed(1) + " GB local";
  } catch (_) { $("budget-label").textContent = "Local disk budget enforced"; }
}
async function refresh(retryRemote = false) {
  const navigationEpoch = state.epoch;
  busy("Reading repository metadata…"); notice();
  try {
    const session = await api("/api/session"); state.token = session.token;
    const overview = await api(retryRemote ? "/api/overview?refresh=1" : "/api/overview"); state.repos = overview.repos ?? overview.repositories ?? [];
    metadataStatus(overview.metadata_status);
    const selected = state.repo && state.repos.find((r) => key(r) === key(state.repo));
    const roles = [...new Set(state.repos.map((r) => r.role).filter(Boolean))].sort();
    const previousRole = $("role-filter").value;
    $("role-filter").replaceChildren(el("option", "", "All roles")); $("role-filter").firstChild.value = "";
    roles.forEach((role) => {const option = el("option", "", human(role)); option.value = role; $("role-filter").append(option);});
    $("role-filter").value = previousRole;
    renderRepos(); await budget();
    if (state.epoch !== navigationEpoch) return;
    if (selected) await chooseRepo(selected, true);
    else {
      const initial = state.repos.find((r) => loaded(r) && r.capture_count > 0) ?? state.repos.find((r) => r.capture_count > 0) ?? state.repos[0];
      if (initial) await chooseRepo(initial);
      else notice("No capture catalog was found. Add an existing capture root with --root, then refresh.");
    }
  } catch (error) { if (state.epoch === navigationEpoch) notice(error.message, true); }
  finally { if (state.epoch === navigationEpoch) busy(); }
}
async function chooseRepo(repo, preserve = false) {
  if (state.loading && !preserve) return;
  const epoch = ++state.epoch;
  state.repo = repo; state.offset = 0; state.item = null; state.comparison = null; state.items = []; state.total = 0; state.captures = []; state.repoLoading = true; state.comparisonLoading = false; state.comparisonKnown = false;
  metadataStatus();
  state.gitResult = null; state.gitSelection = null;
  if (!preserve) {state.left = ""; state.right = "";}
  $("change-search").value = "";
  renderCaptures(); renderChanges();
  replace("detail", empty("Loading capture history", "Reading metadata for " + repoSlug(repo) + ". Previous repository results have been cleared."));
  replace("qualification", el("span", "", "◌"), el("p", "", "Loading capture metadata for " + repoSlug(repo) + "."));
  renderRepos(); busy("Reading capture history…"); notice();
  $("repository-name").textContent = repoSlug(repo);
  $("repository-description").textContent = [repo.role && human(repo.role), repo.cohort && human(repo.cohort), "Captured repository history"].filter(Boolean).join(" · ");
  $("repo-status").textContent = "LOADING";
  $("repo-status").className = "badge neutral";
  try {
    const value = await api("/api/repos/" + encodeURIComponent(key(repo)));
    if (epoch !== state.epoch) return;
    state.repoLoading = false;
    state.repo = value.repo ?? value.repository ?? repo;
    state.repos = state.repos.map((row) => key(row) === key(repo) ? {...row, ...state.repo} : row);
    metadataStatus(value.metadata_status); renderRepos();
    $("repo-status").textContent = human(value.repo?.status ?? repo.status ?? repo.load_state ?? "read only").toUpperCase();
    $("repo-status").className = "badge " + statusStyle(value.repo?.status ?? repo.status ?? repo.load_state);
    state.captures = [...list(value.captures)].sort((a, b) => captureDate(a).localeCompare(captureDate(b)));
    if (!state.captures.some((c) => key(c) === state.left)) state.left = key(state.captures[Math.max(0, state.captures.length - 2)]);
    if (!state.captures.some((c) => key(c) === state.right)) state.right = key(state.captures[state.captures.length - 1]);
    renderCaptures();
    if (state.captures.length) await compare();
    else if (!captureCountKnown(state.repo)) {$("repo-status").textContent = "REMOTE UNKNOWN"; $("repo-status").className = "badge warning"; renderEmpty("Remote capture history is unknown", "No capture is registered locally for this repository. Remote metadata is unavailable or incomplete, so this does not establish that no captures exist. Use Refresh when remote retry is allowed.");}
    else renderEmpty("No registered captures", "This repository is in the cohort, but no capture is registered in the available catalog.");
  } catch (error) { if (epoch === state.epoch) {state.repoLoading = false; renderCaptures(); $("repo-status").textContent = "UNAVAILABLE"; notice(error.message, true); renderEmpty("Capture history unavailable", "Refresh after checking the local capture configuration.");} }
  finally { if (epoch === state.epoch) busy(); }
}
function selectedCapture(side) { return state.captures.find((c) => key(c) === state[side]); }
function renderCaptures() {
  if (state.repoLoading) {
    for (const id of ["capture-count", "lane-count", "proof-count"]) $(id).textContent = "—";
    $("capture-count-label").textContent = "captures";
    for (const side of ["left", "right"]) {const select = $(side + "-capture"); select.replaceChildren(); select.disabled = true;}
    document.querySelectorAll("#category-tabs button").forEach((button) => {button.disabled = true; button.querySelector("span").textContent = "";});
    $("load-captures").disabled = true; $("load-captures").textContent = "Loading capture metadata…"; $("swap-captures").disabled = true;
    $("timeline-caption").textContent = "Reading capture history…";
    $("selection-note").textContent = "Capture controls will be available after this repository's metadata is read.";
    replace("timeline", el("p", "empty-inline", "Loading captures for " + repoSlug(state.repo) + "…"));
    return;
  }
  document.querySelectorAll("#category-tabs button").forEach((button) => {button.disabled = !state.captures.length;});
  const known = captureCountKnown(state.repo), captureTotal = state.captures.length;
  $("capture-count").textContent = known ? captureTotal : captureTotal ? captureTotal + "+" : "—";
  $("capture-count-label").textContent = known ? "captures" : "captures · total unknown";
  const laneTotal = new Set(state.captures.map((c) => c.lane ?? c.kind ?? "unknown")).size;
  $("lane-count").textContent = known ? laneTotal : laneTotal ? laneTotal + "+" : "—";
  $("proof-count").textContent = state.captures.filter(loaded).length;
  ["left", "right"].forEach((side) => {
    const select = $(side + "-capture");
    select.replaceChildren(...state.captures.map((c) => { const option = el("option", "", captureDate(c) + " · " + human(c.lane ?? c.kind ?? c.mode ?? "capture") + " · " + human(c.load_state ?? "metadata only")); option.value = key(c); return option; }));
    select.value = state[side]; select.disabled = !state.captures.length || state.loading;
  });
  const nodes = state.captures.map((c) => {
    const left = key(c) === state.left, right = key(c) === state.right;
    const button = el("button", "capture-chip" + (left ? " selected-left" : "") + (right ? " selected-right" : ""));
    button.type = "button"; button.title = "Select as later capture. Shift-click to select as earlier capture.";
    button.append(el("span", "capture-marker", left && right ? "A + B" : left ? "A" : right ? "B" : ""), el("span", "capture-date", captureDate(c)), el("span", "capture-sub", human(c.lane ?? c.kind ?? "capture") + " · " + human(c.mode ?? c.status ?? "")), el("span", "capture-sub", human(c.load_state ?? "metadata only")));
    button.addEventListener("click", (event) => {if (state.loading) return; state[event.shiftKey ? "left" : "right"] = key(c); state.offset = 0; renderCaptures(); compare();});
    return button;
  });
  replace("timeline", ...(nodes.length ? nodes : [el("p", "empty-inline", known ? "No registered capture metadata is available." : "Remote capture history is unknown. No capture is registered locally.")]));
  const needsLoad = [selectedCapture("left"), selectedCapture("right")].filter((c) => c && !loaded(c));
  $("load-captures").disabled = !needsLoad.length || state.loading || state.gitBusy;
  $("load-captures").textContent = state.loading ? "Loading selected evidence…" : needsLoad.length ? "Load selected evidence" : state.captures.length ? "Selected evidence is local" : "Load selected evidence";
  $("swap-captures").disabled = !state.captures.length || state.loading;
  let note = state.left === state.right && state.left ? "One capture selected · browse its observed entities. " : "A → B compares observations across the selected captures. ";
  note += needsLoad.length ? "Metadata is available. Load evidence explicitly to inspect entity bodies; disk capacity is checked first." : "Selected evidence is available locally. Missing later observations are qualified by endpoint coverage.";
  if (!known && state.captures.length) note += " Additional remote captures may be absent from this timeline.";
  $("selection-note").textContent = state.captures.length ? note : known ? "No captures are registered for this repository." : "Remote metadata is unavailable or incomplete; capture availability is unknown.";
  $("timeline-caption").textContent = known ? state.captures.length + " captures · UTC · Shift-click to choose A" : state.captures.length + " registered · remote total unknown · UTC";
}
function qualificationText(result) {
  const value = result?.qualification;
  if (typeof value === "string") return value;
  if (value?.message) return value.message;
  if (value?.description) return value.description;
  if (Array.isArray(value)) return value.map(human).join(" · ");
  return "Changes describe what these captures observed. “Not observed later” does not establish deletion; endpoint coverage and capture lanes may differ.";
}
function comparableSummary(summary) {
  return Boolean(summary && loaded(selectedCapture("left")) && loaded(selectedCapture("right")) && summary.counts?.left !== null && summary.counts?.left !== undefined && summary.counts?.right !== null && summary.counts?.right !== undefined && !/coverage_unknown|capability_unavailable|lane_mismatch|not_loaded|disabled/.test(summary.status ?? ""));
}
async function compare() {
  if (!state.repo || !state.left || !state.right) return;
  const epoch = ++state.epoch;
  state.gitResult = null; state.gitSelection = null; state.gitPath = null;
  state.comparison = null; state.items = []; state.item = null; state.total = 0; state.comparisonKnown = false; state.comparisonLoading = true;
  renderChanges();
  replace("detail", empty("Loading comparison", "Reading " + categories[state.category] + " observations for the selected captures."));
  replace("qualification", el("span", "", "◌"), el("p", "", "Reading the selected capture comparison. Previous results have been cleared."));
  document.querySelectorAll("#category-tabs button").forEach((button) => {button.classList.toggle("active", button.dataset.category === state.category); button.querySelector("span").textContent = "";});
  busy("Comparing preserved observations…");
  try {
    const value = await api(query("/api/compare", {repo: key(state.repo), left: state.left, right: state.right, category: state.category, offset: state.offset, limit: 100}));
    if (epoch !== state.epoch) return;
    state.comparisonLoading = false;
    state.comparison = value; state.items = flattenItems(value); state.total = Number(value.total ?? state.items.length); state.item = null;
    const current = value.entity_types?.[state.category], breakdown = current?.change_breakdown;
    state.comparisonKnown = state.category === "git" ? value.git_refs?.comparison_available === true : comparableSummary(current);
    let qualification = qualificationText(value);
    if (breakdown && state.comparisonKnown) qualification += " Selected category: " + (breakdown.representation_changed ?? 0) + " edited representations; " + (breakdown.not_observed_left ?? 0) + " observed only in B; " + (breakdown.not_observed_right ?? 0) + " not observed in B.";
    else if (current) qualification += " Entity change counts are unknown until selected evidence and comparable endpoint observations are available.";
    replace("qualification", el("span", "", "◌"), el("p", "", qualification));
    document.querySelectorAll("#category-tabs button").forEach((button) => {
      button.classList.toggle("active", button.dataset.category === state.category);
      const summary = value.entity_types?.[button.dataset.category];
      const changes = list(summary?.changes);
      button.querySelector("span").textContent = summary ? comparableSummary(summary) ? summary.change_count ?? changes.length : "—" : "";
    });
    if (state.category === "coverage") renderCoverage();
    else { renderChanges(); const first = state.items[0]; if (first) chooseItem(first); else renderNoChanges(); }
  } catch (error) { if (epoch === state.epoch) {state.comparisonLoading = false; notice(error.message, true); renderEmpty("Comparison unavailable", "The selected evidence may need to be loaded, or its endpoint was not captured.");} }
  finally { if (epoch === state.epoch) busy(); }
}
function flattenItems(value) {
  if (state.category === "coverage") return [];
  if (Array.isArray(value.items)) return value.items;
  if (state.category === "git") {
    const refs = value.git_refs ?? {};
    return ["added", "moved", "not_advertised_now"].flatMap((kind) => list(refs[kind]).map((r, i) => ({id: r.ref ?? r.name ?? r.id ?? kind + i, title: r.ref ?? r.name ?? (typeof r === "string" ? r : "Git reference"), change: kind, before: r.left ?? r.before ?? r.old ?? (kind === "not_advertised_now" ? r : null), after: r.right ?? r.after ?? r.new ?? (kind === "added" ? r : null), fields: ["oid"], ref_record: r})));
  }
  const category = value.entity_types?.[state.category] ?? {};
  const changes = list(category.changes);
  const missing = list(category.not_observed_right).map((r) => ({id: r.id ?? r, change: "not_observed_later", before: r.entity ?? r.left ?? r}));
  return [...changes, ...missing];
}
function itemTitle(item) {return item.title ?? item.after?.title ?? item.before?.title ?? item.right?.title ?? item.left?.title ?? item.after?.name ?? item.before?.name ?? (state.category === "comments" ? "Comment " : human(state.category).replace(/s$/, "") + " ") + item.id;}
function itemChange(item) {return item.change ?? item.status ?? "observed";}
function fieldNames(item) {
  const fields = item.changed_fields ?? item.fields;
  if (Array.isArray(fields)) return fields.map((f) => typeof f === "string" ? f : f.name ?? f.field).filter(Boolean);
  return fields && typeof fields === "object" ? Object.keys(fields) : [];
}
function renderChanges() {
  if (state.category === "git" && state.gitResult) {renderGitFiles(); return;}
  $("changes-title").textContent = state.category === "git" ? "Reference observations" : "Observed changes";
  $("change-search").disabled = state.repoLoading || state.comparisonLoading;
  $("changes-count").textContent = state.comparisonKnown ? state.total : "—";
  const search = $("change-search").value.toLowerCase().trim();
  const filtered = state.items.filter((item) => [itemTitle(item), item.id, itemChange(item)].join(" ").toLowerCase().includes(search));
  const nodes = filtered.map((item) => {
    const button = el("button", "change-button" + (state.item === item ? " active" : ""));
    button.type = "button"; button.setAttribute("aria-pressed", String(state.item === item));
    const metadata = el("span", "change-metadata");
    const change = itemChange(item), count = item.field_count ?? fieldNames(item).length; metadata.append(badge(change, statusStyle(change)), el("span", "", count ? count + " fields" : ""));
    button.append(el("span", "change-title", itemTitle(item)), metadata);
    button.addEventListener("click", () => chooseItem(item)); return button;
  });
  replace("change-list", ...(nodes.length ? nodes : [empty(state.repoLoading || state.comparisonLoading ? "Loading observations" : !state.comparisonKnown && !search ? "Evidence unavailable" : "No matching observations", state.repoLoading || state.comparisonLoading ? "The previous results have been cleared." : search ? "Try a different filter." : !state.comparisonKnown ? "Load selected evidence or inspect coverage to see which observations are available." : "Coverage details explain which observations are available.", true)]));
  $("pagination").hidden = state.total <= 100;
  $("page-label").textContent = state.total ? (state.offset + 1) + "–" + Math.min(state.offset + 100, state.total) + " / " + state.total : "";
  $("previous-page").disabled = state.offset === 0; $("next-page").disabled = state.offset + 100 >= state.total;
}
function empty(title, message, compact = false) {const node = el("div", "empty-state" + (compact ? " compact" : "")); node.append(el("span", "empty-symbol", "◇"), el("h3", "", title), el("p", "", message)); return node;}
function renderEmpty(title, message) {state.items = []; state.item = null; state.total = 0; renderChanges(); replace("detail", empty(title, message));}
function renderNoChanges() {
  if (state.category === "git") {renderGitDetail(null); return;}
  if ([selectedCapture("left"), selectedCapture("right")].some((capture) => capture && !loaded(capture))) {replace("detail", empty("Load selected evidence", "Only capture metadata is available for at least one selected capture. Load its evidence to inspect entity changes; the change count is currently unknown.")); return;}
  const category = state.comparison?.entity_types?.[state.category];
  const status = category?.status ?? (state.category === "git" ? state.comparison?.git_refs?.comparison_available === false ? "unavailable" : "observed" : "unavailable");
  const missing = !/available|complete|observed|comparable|compared|ok|loaded/.test(status) || /unavailable|not_loaded|disabled/.test(status);
  let title = missing ? human(status) : "No observed changes";
  let message = missing ? "This category has no comparable entity data in the selected captures. Check Coverage & proofs for endpoint status, gaps and load state." : "No changes were found in the observations available for this category. Review coverage before interpreting an unchanged result.";
  if (status === "partial") {title = "No changed records in partial coverage"; message = "No changed representations were found in the available observations. Some endpoints or pages are incomplete; review Coverage & proofs before interpreting this result.";}
  replace("detail", empty(title, message));
}
function chooseItem(item) {state.item = item; state.tab = "fields"; renderChanges(); renderDetail();}
function itemSides(item) { return {before: item.before ?? item.left ?? null, after: item.after ?? item.right ?? null}; }
function renderDetail() {
  const item = state.item; if (!item) return;
  if (state.category === "git") {renderGitDetail(item); return;}
  const container = $("detail"); container.replaceChildren();
  const eyebrow = el("div", "detail-eyebrow"); eyebrow.append(el("span", "", categories[state.category]?.toUpperCase()), badge(itemChange(item), statusStyle(itemChange(item))), el("span", "", text(item.id, 130)));
  container.append(eyebrow, el("h2", "", itemTitle(item)), el("div", "detail-subtitle", "A: " + captureDate(selectedCapture("left")) + " UTC  →  B: " + captureDate(selectedCapture("right")) + " UTC"));
  const tabs = el("div", "detail-tabs");
  [["fields", "Fields"], ["body", "Body · side by side"], ["raw", "Entity JSON / diff"]].forEach(([value, label]) => {const button = el("button", state.tab === value ? "active" : "", label); button.addEventListener("click", () => {state.tab = value; renderDetail();}); tabs.append(button);});
  container.append(tabs);
  if (state.tab === "fields") {
    container.append(fieldTable(item));
    const {before, after} = itemSides(item), previews = [["A", before?._viewer_preview], ["B", after?._viewer_preview]].filter(([, preview]) => preview?.truncated);
    if (previews.length) container.append(el("p", "coverage-note", "Bounded entity preview · " + previews.map(([side, preview]) => side + ": " + (preview.omitted_key_count ?? 0) + " fields omitted, " + list(preview.truncated_keys).length + " fields shortened").join("; ") + ". Inspect the preserved response below for original captured data."));
  }
  else if (state.tab === "body") container.append(bodyComparison(item));
  else container.append(rawComparison(item));
  if (state.tab !== "fields" && item.display_qualification) container.append(el("p", "coverage-note", text(item.display_qualification, 2000)));
  const gaps = list(item.gaps);
  gaps.forEach((gap) => container.append(el("div", "coverage-gap", gapText(gap))));
  addRawSources(container, item);
}
function fieldTable(item) {
  const {before, after} = itemSides(item), changed = fieldNames(item);
  const declaredChanges = Array.isArray(item.changed_fields) || Array.isArray(item.fields);
  const primitiveField = state.category === "git" ? "object_id" : "value";
  const left = before && typeof before === "object" ? before : {[primitiveField]: before}, right = after && typeof after === "object" ? after : {[primitiveField]: after};
  const keys = [...new Set([...changed, ...Object.keys(left), ...Object.keys(right)])].filter((name) => !["body", "body_text", "body_html", "raw_refs", "_viewer_preview"].includes(name)).slice(0, 80);
  const table = el("table", "field-table"), head = el("thead"), row = el("tr"), body = el("tbody");
  ["FIELD", "A · EARLIER", "B · LATER"].forEach((label) => row.append(el("th", "", label))); head.append(row); table.append(head, body);
  keys.forEach((name) => {const tr = el("tr", changed.includes(name) || (!declaredChanges && JSON.stringify(left[name]) !== JSON.stringify(right[name])) ? "changed" : ""); tr.append(el("td", "", human(name))); [left, right].forEach((values, index) => {const td = el("td"), absent = (index === 0 ? before : after) === null, omitted = Number(values._viewer_preview?.omitted_key_count ?? 0) > 0; td.append(el("div", "field-value", absent ? "Not observed in " + (index === 0 ? "A" : "B") : name in values ? text(values[name]) : omitted ? "Not included in bounded preview" : "Field not present")); tr.append(td);}); body.append(tr);});
  if (!keys.length) {const tr = el("tr"), td = el("td", "", "No field values are available for this observation."); td.colSpan = 3; tr.append(td); body.append(tr);}
  return table;
}
function bodyComparison(item) {
  const {before, after} = itemSides(item), grid = el("div", "body-grid");
  [["A · EARLIER BODY", item.body_before ?? before?.body ?? before?.body_text], ["B · LATER BODY", item.body_after ?? after?.body ?? after?.body_text]].forEach(([label, value]) => {const column = el("section", "body-column"); column.append(el("h3", "", label), el("pre", "", value === undefined || value === null ? "Body not observed or not present in this entity." : text(value, 120000))); grid.append(column);});
  return grid;
}
function rawComparison(item) {
  const wrapper = el("div"), {before, after} = itemSides(item);
  wrapper.append(el("p", "coverage-note", "This is a bounded representation of the compared entity. Original response records are available below when preserved and loaded."));
  const pre = el("pre", "raw-view");
  const diff = item.raw_diff ?? ["--- A · earlier entity", "+++ B · later entity", ...text(before, 50000).split("\n").map((line) => "- " + line), ...text(after, 50000).split("\n").map((line) => "+ " + line)].join("\n");
  diff.split("\n").slice(0, 4000).forEach((line) => pre.append(el("span", "diff-line" + (line.startsWith("+") && !line.startsWith("+++") ? " add" : line.startsWith("-") && !line.startsWith("---") ? " remove" : ""), line)));
  wrapper.append(pre); return wrapper;
}
function gitCapability() {
  return state.comparison?.git_refs?.file_diff?.right ?? selectedCapture("right")?.git_file_diff ?? {status: "unavailable", reason: "Choose a loaded full Git capture in B to inspect file differences.", refs: []};
}
function renderGitDetail(item) {
  const container = $("detail"), capability = gitCapability(), refs = list(capability.refs);
  const distinctTips = new Set(refs.map((r) => r.oid)).size;
  const available = capability.status === "available_to_prepare" && distinctTips > 1;
  container.replaceChildren(el("div", "detail-eyebrow", "GIT EVIDENCE · CAPTURE B"), el("h2", "", "Reference tips & file differences"));
  container.append(el("p", "coverage-note", "Reference observations compare capture A with B. File diffs below compare two captured ref tips within the full Git bundle for B. Preparation is explicit and subject to the shared local disk budget."));
  const controls = el("section", "git-controls"), top = el("div", "git-controls-heading");
  top.append(el("strong", "", "Captured refs in B"), badge(available ? "available to prepare" : capability.status ?? "unavailable", available ? "success" : "warning")); controls.append(top);
  if (available) {
    const previous = state.gitSelection;
    const head = refs.find((r) => /^(HEAD|refs\/heads\/(main|master))$/.test(r.ref)) ?? refs[refs.length - 1];
    const base = refs.find((r) => r.oid !== head.oid) ?? refs[0];
    if (!previous || previous.capture !== state.right) state.gitSelection = {repo: key(state.repo), capture: state.right, base: base.oid, head: head.oid};
    const row = el("div", "git-ref-controls"), selects = {};
    for (const [side, label] of [["base", "BASE REF"], ["head", "HEAD REF"]]) {
      const wrap = el("label"), select = el("select"); select.setAttribute("aria-label", label.toLowerCase()); select.disabled = state.gitBusy;
      refs.forEach((r) => {const option = el("option", "", r.ref + " · " + r.oid.slice(0, 10)); option.value = r.oid; select.append(option);});
      select.value = state.gitSelection[side];
      wrap.append(el("span", "", label), select); row.append(wrap); selects[side] = select;
    }
    const button = el("button", "primary-button", state.gitBusy ? "Preparing file diff…" : "Compare files");
    const validity = () => {button.disabled = state.gitBusy || selects.base.value === selects.head.value;};
    Object.entries(selects).forEach(([side, select]) => select.addEventListener("change", () => {state.gitSelection[side] = select.value; validity();})); validity();
    button.addEventListener("click", () => requestGitDiff()); row.append(button); controls.append(row);
    controls.append(el("p", "selection-note", (capability.bundle_bytes ? "Captured bundle: " + (capability.bundle_bytes / 1e6).toFixed(1) + " MB. " : "") + (capability.refs_truncated ? "Showing " + refs.length + " of " + capability.refs_total + " captured refs. " : "") + "Only captured ref OIDs can be selected. No free-form Git revisions or paths are accepted."));
  } else controls.append(el("p", "coverage-gap", capability.status === "available_to_prepare" && distinctTips < 2 ? "At least two distinct captured ref OIDs are required to compare files." : capability.reason ?? "File differences require a loaded full Git bundle within the local budget. Delta, missing, and oversized bundles are unavailable."));
  container.append(controls);
  if (state.gitResult) {
    const result = state.gitResult, heading = el("div", "git-patch-heading");
    heading.append(el("h3", "", state.gitPath ?? "All changed files"));
    const back = el("button", "", "Back to reference observations"); back.disabled = state.gitBusy;
    back.addEventListener("click", () => {state.gitResult = null; state.gitPath = null; renderChanges(); renderGitDetail(state.item);}); heading.append(back); container.append(heading);
    container.append(el("p", "detail-subtitle", "Base " + result.base_oid + " → head " + result.head_oid));
    if (result.commits) {
      const metadata = el("details", "git-commit-metadata"); metadata.append(el("summary", "", "Captured commit metadata"));
      const cards = el("div", "coverage-grid");
      for (const side of ["base", "head"]) if (result.commits[side]) cards.append(definitionCard(side === "base" ? "Base commit" : "Head commit", result.commits[side]));
      metadata.append(cards); container.append(metadata);
    }
    const lines = String(result.patch ?? "").split("\n"), patch = el("pre", "raw-view git-patch");
    lines.slice(0, 4000).forEach((line) => patch.append(el("span", "diff-line" + (line.startsWith("+") && !line.startsWith("+++") ? " add" : line.startsWith("-") && !line.startsWith("---") ? " remove" : line.startsWith("@@") ? " hunk" : ""), line)));
    container.append(patch);
    if (result.truncated || lines.length > 4000) container.append(el("p", "coverage-gap", "This patch is a bounded excerpt." + (lines.length > 4000 ? " The browser displays the first 4,000 lines." : "") + " Large and binary changes may not have a complete text preview."));
    if (!result.patch) container.append(el("p", "coverage-note", "No text patch was returned. Choose a changed file or review the reported gaps below."));
    if (result.verification) {
      const verification = el("details", "git-commit-metadata"); verification.append(el("summary", "", "Bundle verification"), definitionCard("Local Git verification", result.verification)); container.append(verification);
    }
    if (result.qualification) container.append(el("p", "coverage-note", text(result.qualification, 3000)));
    list(result.gaps).forEach((gap) => container.append(el("p", "coverage-gap", gapText(gap))));
  } else if (item) {
    const line = el("div", "git-patch-heading"); line.append(el("h3", "git-ref", itemTitle(item)), badge(itemChange(item), statusStyle(itemChange(item)))); container.append(line, fieldTable(item));
    container.append(el("p", "coverage-note", "These OIDs are ref advertisements observed in separate intervals. A missing later advertisement does not establish a deleted ref."));
  } else container.append(empty("Explore a captured Git tree", "Select two captured refs above to prepare a bounded file diff, or choose a reference observation from the list."));
}
function renderGitFiles() {
  const files = list(state.gitResult?.files), search = $("change-search").value.toLowerCase().trim();
  const total = state.gitResult.files_total ?? files.length;
  $("changes-title").textContent = "Changed files"; $("changes-count").textContent = total > files.length ? files.length + " / " + total : files.length; $("pagination").hidden = true;
  const nodes = files.filter((f) => [f.path, f.old_path, f.status].join(" ").toLowerCase().includes(search)).map((file) => {
    const button = el("button", "change-button" + (state.gitPath === file.path ? " active" : "")); button.disabled = state.gitBusy;
    const meta = el("span", "change-metadata"), fileStatus = {M: "modified", A: "added", D: "removed in Git tree", R: "renamed", C: "copied", T: "type changed"}[String(file.status ?? "").slice(0, 1)] ?? file.status ?? "changed";
    meta.append(badge(fileStatus, fileStatus === "added" ? "success" : "blue"));
    if (file.old_path && file.old_path !== file.path) meta.append(el("span", "", "from " + file.old_path));
    button.append(el("span", "change-title git-ref", file.path), meta); button.addEventListener("click", () => requestGitDiff(file.path)); return button;
  });
  replace("change-list", ...(nodes.length ? nodes : [empty("No matching files", search ? "Try a different file filter." : "No changed files were returned for these captured refs.", true)]));
  if (total > files.length) $("change-list").append(el("p", "coverage-gap", "The file list is bounded to the first " + files.length + " of " + total + " changed paths."));
}
async function requestGitDiff(path) {
  if (state.gitBusy || !state.gitSelection) return;
  const selection = {...state.gitSelection}, epoch = state.epoch, priorFiles = state.gitResult?.files;
  state.gitBusy = true; renderCaptures(); renderGitDetail(state.item); renderChanges(); busy("Preparing bounded Git file diff…"); notice();
  try {
    const result = await api("/api/git-diff", path ? {...selection, path} : selection);
    if (epoch !== state.epoch || state.category !== "git") return;
    state.gitResult = path && priorFiles ? {...result, files: priorFiles} : result; state.gitPath = path ?? null;
    renderGitFiles(); renderGitDetail(state.item); await budget();
  } catch (error) {if (epoch === state.epoch) notice(error.message, true);}
  finally {state.gitBusy = false; renderCaptures(); if (epoch === state.epoch && state.category === "git") {renderChanges(); renderGitDetail(state.item);} busy();}
}
function addRawSources(container, item) {
  if (state.category === "git") return;
  const repoKey = key(state.repo), captureKeys = {left: state.left, right: state.right}, category = state.category;
  const details = el("details", "raw-source"), summary = el("summary", "", "Inspect preserved response records"); details.append(summary); container.append(details);
  let requested = false;
  details.addEventListener("toggle", async () => {
    if (!details.open || requested) return; requested = true;
    const note = el("p", "", "Locating raw evidence references…"); details.append(note);
    let count = 0;
    for (const side of ["left", "right"]) {
      try {
        const detail = await api(query("/api/entity", {repo: repoKey, capture: captureKeys[side], kind: category, id: String(item.id)}));
        for (const ref of list(detail.raw_refs).slice(0, 12)) {
          const refKey = typeof ref === "string" ? ref : ref.key ?? ref.id ?? ref.ref;
          if (!refKey) continue; count++;
          const button = el("button", "source-link", (side === "left" ? "A" : "B") + " · " + text(typeof ref === "object" ? ref.label ?? ref.purpose ?? ref.endpoint ?? refKey : refKey, 180));
          button.addEventListener("click", async () => {
            button.disabled = true;
            try {
              const raw = await api(query("/api/raw", {repo: repoKey, capture: captureKeys[side], ref: refKey}));
              const box = el("div");
              box.append(el("p", "", "Preserved response · " + human(raw.status) + (raw.sha256 ? " · SHA-256 " + raw.sha256 : "")), el("p", "", "Display encoding: " + human(raw.encoding ?? "metadata only") + (raw.bytes !== undefined ? " · Original response: " + raw.bytes + " bytes" : "") + (raw.truncated ? " · Server excerpt is truncated" : "")), el("pre", "raw-view", text(raw.text ?? raw.record ?? raw, 200000)));
              list(raw.gaps).forEach((gap) => box.append(el("p", "coverage-gap", gapText(gap))));
              if (raw.text !== undefined && raw.record) {const metadata = el("details"), label = el("summary", "", "Preserved response metadata"); metadata.append(label, el("pre", "raw-view", text(raw.record, 30000))); box.append(metadata);}
              button.after(box);
            } catch (error) {button.after(el("p", "coverage-gap", error.message)); button.disabled = false;}
          });
          details.append(button);
        }
      } catch (_) { /* A missing side is an expected comparison condition. */ }
    }
    note.textContent = count ? "Read-only excerpts from the preserved HTTP responses. Response headers, pagination and completeness belong to capture coverage." : "No preserved response reference is available for this entity in the selected captures.";
  });
}
function gapText(gap) {return typeof gap === "string" ? gap : gap.message ?? gap.reason ?? gap.description ?? text(gap, 1500);}
function definitionCard(title, values) {
  const card = el("section", "coverage-card"); card.append(el("h3", "", title));
  const dl = el("dl");
  Object.entries(values ?? {}).slice(0, 25).forEach(([name, value]) => {dl.append(el("dt", "", human(name)), el("dd", "", text(value, 1600)));}); card.append(dl); return card;
}
function renderCoverage() {
  $("changes-title").textContent = "Evidence coverage"; $("changes-count").textContent = "";
  $("pagination").hidden = true;
  replace("change-list", empty("Know the boundaries", "Capture coverage, preserved gaps, and timestamp evidence qualify every comparison.", true));
  const container = $("detail"); container.replaceChildren(el("h2", "", "Coverage & timestamp evidence"));
  container.append(el("p", "coverage-note", "Capture timestamps record when the collector observed data. A TSA verification result and a pending Bitcoin attestation are separate evidence states; neither is inferred from the recorded capture time."));
  const grid = el("div", "coverage-grid");
  for (const side of ["left", "right"]) {
    const c = selectedCapture(side), result = state.comparison?.[side] ?? c ?? {};
    grid.append(definitionCard((side === "left" ? "A · Earlier capture" : "B · Later capture"), {recorded_utc: captureDate(c, true), run_id: c?.run_id ?? c?.capture_id ?? key(c), capture_lane: c?.lane ?? c?.kind ?? "unavailable", mode: c?.mode ?? "unavailable", load_state: c?.load_state ?? "not loaded", capture_status: c?.status ?? "unavailable"}));
    grid.append(definitionCard((side === "left" ? "A" : "B") + " · Timestamp / proof state", result.proof ?? c?.proof ?? {status: "Not available in this metadata"}));
    grid.append(definitionCard((side === "left" ? "A" : "B") + " · Endpoint coverage", result.coverage ?? c?.coverage ?? {status: "Not loaded or unavailable"}));
    if (c?.source_lineage || c?.lane_intervals) grid.append(definitionCard((side === "left" ? "A" : "B") + " · Lineage / observation intervals", {source_lineage: c.source_lineage ?? "unavailable", lane_intervals: c.lane_intervals ?? "unavailable"}));
  }
  container.append(grid);
  const entityTypes = state.comparison?.entity_types ?? {};
  const typeGrid = el("div", "coverage-grid");
  Object.entries(entityTypes).forEach(([kind, summary]) => typeGrid.append(definitionCard(categories[kind] ?? human(kind), {status: summary.status ?? "unavailable", left_observed: summary.counts?.left ?? "unavailable", right_observed: summary.counts?.right ?? "unavailable", count_qualification: summary.count_qualification ?? "Counts describe observed query results.", ...(summary.gaps?.length ? {gaps: summary.gaps} : {})})));
  if (Object.keys(entityTypes).length) {container.append(el("p", "coverage-title", "Compared entity categories"), typeGrid);}
  const gaps = [...list(state.comparison?.gaps), ...list(selectedCapture("left")?.gaps), ...list(selectedCapture("right")?.gaps)];
  gaps.slice(0, 30).forEach((gap) => container.append(el("div", "coverage-gap", gapText(gap))));
  if (!gaps.length) container.append(el("p", "coverage-note", "No additional gaps are reported in the available metadata. This does not establish complete repository coverage."));
  container.append(el("p", "coverage-note", "Git reference observations describe captured OIDs. File differences require explicit preparation from a loaded, sufficiently small full Git bundle. Missing, incremental, oversized and unloaded bundles remain unavailable; large and binary patches may be excerpted. Disabled capture lanes and uncaptured endpoints remain unavailable."));
}
async function loadSelected() {
  if (state.loading || state.gitBusy) return;
  const captures = [...new Map([selectedCapture("left"), selectedCapture("right")].filter((c) => c && !loaded(c)).map((c) => [key(c), c])).values()];
  if (!captures.length) return;
  const repo = state.repo, repoKey = key(repo);
  state.loading = true; renderCaptures(); notice();
  let polling = false;
  const progressTimer = setInterval(async () => {
    if (polling || !state.loading) return;
    polling = true;
    try {
      const progress = await api("/api/repos/" + encodeURIComponent(repoKey));
      if (key(state.repo) !== repoKey || !state.loading) return;
      state.captures = list(progress.captures); renderCaptures();
      const active = state.captures.find((c) => c.load_state === "loading");
      if (active) busy("Loading selected capture · " + human(active.progress?.phase ?? "reading evidence") + (active.progress?.parts_complete ? " · " + active.progress.parts_complete + " parts read" : ""));
    } catch (_) { /* The explicit load response reports any failure. */ }
    finally {polling = false;}
  }, 2500);
  try {
    for (const capture of captures) {
      busy("Loading selected capture · " + captureDate(capture) + " UTC…");
      const result = await api("/api/load", {repo: repoKey, capture: key(capture)});
      if (result.status !== "loaded") throw new Error(result.message ?? result.reason ?? "This capture could not be loaded. Check its local configuration and budget.");
    }
    await budget(); await chooseRepo(repo, true);
    notice("Selected evidence is available. Capture loads and their temporary files remain subject to the local disk limit.");
  } catch (error) {notice(error.message, true);}
  finally {clearInterval(progressTimer); state.loading = false; renderCaptures(); busy();}
}
$("repo-search").addEventListener("input", renderRepos);
$("role-filter").addEventListener("change", renderRepos);
$("status-filter").addEventListener("change", renderRepos);
$("refresh").addEventListener("click", () => {if (!state.loading) refresh(true);});
["left", "right"].forEach((side) => $(side + "-capture").addEventListener("change", () => {state[side] = $(side + "-capture").value; state.offset = 0; renderCaptures(); compare();}));
$("swap-captures").addEventListener("click", () => {[state.left, state.right] = [state.right, state.left]; state.offset = 0; renderCaptures(); compare();});
$("load-captures").addEventListener("click", loadSelected);
document.querySelectorAll("#category-tabs button").forEach((button) => button.addEventListener("click", () => {state.category = button.dataset.category; state.offset = 0; $("change-search").value = ""; compare();}));
$("change-search").addEventListener("input", renderChanges);
$("previous-page").addEventListener("click", () => {state.offset = Math.max(0, state.offset - 100); compare();});
$("next-page").addEventListener("click", () => {state.offset += 100; compare();});
refresh();
