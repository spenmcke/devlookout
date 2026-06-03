const apiBase = window.location.protocol === "file:" ? "http://localhost:8080" : window.location.origin;
const state = {
  fault: "locale-expiry",
  context: null
};

const ids = {
  crumbTicket: "crumb-ticket",
  topPlan: "top-plan",
  ticketMeta: "ticket-meta",
  ticketTitle: "ticket-title",
  customerAccount: "customer-account",
  customerPlan: "customer-plan",
  customerArr: "customer-arr",
  customerCsm: "customer-csm",
  diagWhat: "diag-what",
  diagWho: "diag-who",
  diagWhen: "diag-when",
  diagRoot: "diag-root",
  jiraLink: "jira-link",
  jiraStatus: "jira-status",
  codeFile: "code-file",
  codeLines: "code-lines",
  assigneeInitials: "assignee-initials",
  assigneeName: "assignee-name",
  assigneeRole: "assignee-role",
  assigneeWhy: "assignee-why",
  fixSummary: "fix-summary",
  fixDiff: "fix-diff",
  fixScope: "fix-scope",
  sentryType: "sentry-type",
  sentryMessage: "sentry-message",
  sentryFirst: "sentry-first",
  sentryCount: "sentry-count",
  sentryRelease: "sentry-release"
};

window.addEventListener("DOMContentLoaded", async () => {
  bindActions();
  await loadCases();
  await loadContext(state.fault);
});

function bindActions() {
  document.getElementById("case-picker").addEventListener("change", async (event) => {
    const fault = event.target.value;
    if (fault) {
      await loadContext(fault);
    }
  });

  document.getElementById("draft-pr").addEventListener("click", openDraftPr);
}

async function loadCases() {
  const select = document.getElementById("case-picker");
  select.innerHTML = "";

  try {
    const data = await requestJson("/cases");
    for (const item of data.cases || []) {
      const option = document.createElement("option");
      option.value = item.key;
      option.textContent = cleanText(item.label);
      select.append(option);
    }
    select.value = state.fault;
  } catch (error) {
    showError(error);
  }
}

async function loadContext(fault) {
  state.fault = fault;
  markLoading();

  try {
    const context = await requestJson(`/context/latest?fault=${encodeURIComponent(fault)}`);
    state.context = context;
    renderFastSections(context);
    await delay(420);
    renderDiagnosis(context);
  } catch (error) {
    showError(error);
  }
}

function renderFastSections(context) {
  setText(ids.crumbTicket, context.ticket.id);
  setText(ids.topPlan, context.customer.plan.toLowerCase());
  setText(ids.ticketMeta, `${context.ticket.id} · escalated ${context.ticket.escalated_ago}`);
  setText(ids.ticketTitle, context.ticket.title);
  renderTags(context.ticket.priority, context.ticket.tags);

  setText(ids.customerAccount, context.customer.account);
  setText(ids.customerPlan, context.customer.plan);
  setText(ids.customerArr, formatArr(context.customer.arr_usd));
  setText(ids.customerCsm, context.customer.csm ? `${context.customer.csm} · managed` : "Unmanaged");

  renderRelated(context.related);
  setText(ids.codeFile, context.code_location.file);
  setText(ids.codeLines, context.code_location.lines);
  renderContacts(context.contacts);
  renderAssignee(context.assignee);
  renderSentry(context.sentry);
}

function renderDiagnosis(context) {
  document.getElementById("stale-note").hidden = !context.stale;
  setText(ids.diagWhat, context.diagnosis.what_is_happening);
  setText(ids.diagWho, context.diagnosis.who_is_affected);
  setText(ids.diagWhen, context.diagnosis.when_it_triggers);
  setText(ids.diagRoot, context.diagnosis.likely_root_cause);
  setText(ids.fixSummary, context.diagnosis.suggested_fix.summary);
  setText(ids.fixScope, context.diagnosis.suggested_fix.scope);
  renderDiff(context.diagnosis.suggested_fix.diff);
  document.getElementById("draft-pr").disabled = false;
}

function renderTags(priority, tags) {
  const row = document.getElementById("ticket-tags");
  row.innerHTML = "";
  row.append(tag(priority, "red"));
  for (const value of tags || []) {
    row.append(tag(value, value.toLowerCase().includes("region") ? "amber" : ""));
  }
}

function tag(value, tone) {
  const item = document.createElement("span");
  item.className = tone ? `tag ${tone}` : "tag";
  if (tone === "red") {
    const swatch = document.createElement("span");
    swatch.className = "sw";
    swatch.style.background = "var(--red)";
    item.append(swatch);
  }
  item.append(document.createTextNode(cleanText(value)));
  return item;
}

function renderRelated(related) {
  const link = document.getElementById(ids.jiraLink);
  const label = `${related.jira_key} · ${related.jira_summary}`;
  link.textContent = cleanText(label);
  clearLoading(link);
  link.href = related.jira_url || "#";
  link.removeAttribute("aria-disabled");
  if (!related.jira_url) {
    link.setAttribute("aria-disabled", "true");
  }
  setText(ids.jiraStatus, related.jira_status);
}

function renderContacts(contacts) {
  const wrap = document.getElementById("contacts");
  wrap.innerHTML = "";

  for (const contact of contacts || []) {
    const item = document.createElement("div");
    item.className = "ct";
    item.innerHTML = `
      <div class="av"></div>
      <div><div class="nm"></div><div class="ro"></div></div>
      <span class="em"></span>
      <span class="src"></span>
    `;
    item.querySelector(".av").textContent = initials(contact.name);
    item.querySelector(".nm").textContent = cleanText(contact.name);
    item.querySelector(".ro").textContent = cleanText(contact.role);
    item.querySelector(".em").textContent = cleanText(contact.email);
    item.querySelector(".src").textContent = cleanText(contact.source);
    wrap.append(item);
  }
}

function renderAssignee(assignee) {
  setText(ids.assigneeInitials, initials(assignee.name));
  setText(ids.assigneeName, assignee.name);
  setText(ids.assigneeRole, assignee.role);
  setText(ids.assigneeWhy, assignee.why);
}

function renderSentry(sentry) {
  setText(ids.sentryType, sentry.error_type);
  setText(ids.sentryMessage, sentry.message);
  setText(ids.sentryFirst, formatDate(sentry.first_seen));
  setText(ids.sentryCount, String(sentry.events_24h));
  setText(ids.sentryRelease, sentry.release);
  renderLog(sentry.log_lines || [], sentry.error_type);
}

function renderLog(lines, errorType) {
  const wrap = document.getElementById("sentry-log");
  wrap.innerHTML = "";

  lines.forEach((line, index) => {
    const row = document.createElement("div");
    const level = levelFor(line, errorType);
    row.className = level === "ERROR" ? "row mark" : "row";

    const gut = document.createElement("span");
    gut.className = "gut";
    gut.textContent = String(index + 1).padStart(2, "0");

    const levelEl = document.createElement("span");
    levelEl.className = level === "ERROR" ? "lv-e" : level === "WARN" ? "lv-w" : "lv-i";
    levelEl.textContent = `${level.padEnd(5, " ")} `;

    const msg = document.createElement("span");
    msg.className = "msg";
    msg.textContent = cleanText(line);

    row.append(gut, levelEl, msg);
    wrap.append(row);
  });
}

function renderDiff(diff) {
  const pre = document.getElementById(ids.fixDiff);
  pre.innerHTML = "";
  clearLoading(pre);

  for (const line of String(diff || "").split("\n")) {
    const span = document.createElement("span");
    span.className = line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "cx";
    span.textContent = cleanText(line);
    pre.append(span, document.createTextNode("\n"));
  }
}

async function openDraftPr() {
  const button = document.getElementById("draft-pr");
  button.disabled = true;
  button.textContent = "Requesting draft PR";

  try {
    const response = await requestJson("/pr/draft", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        fault: state.fault,
        diagnosis: state.context?.diagnosis
      })
    });
    button.textContent = "Draft PR link ready";
    window.open(response.url, "_blank", "noopener");
  } catch (error) {
    button.textContent = "Draft PR failed";
    showError(error);
  } finally {
    window.setTimeout(() => {
      button.disabled = false;
      button.textContent = "Open draft PR";
    }, 1800);
  }
}

function markLoading() {
  document.getElementById("stale-note").hidden = true;
  document.querySelectorAll("[data-loadable], [data-diagnosis]").forEach((el) => {
    el.textContent = "Loading";
    el.classList.add("skeleton");
  });
  document.getElementById("ticket-tags").innerHTML = "";
  document.getElementById("contacts").innerHTML = skeletonRows(2);
  document.getElementById("sentry-log").innerHTML = skeletonLog(9);
  document.getElementById("draft-pr").disabled = true;
}

function clearLoading(element) {
  element.classList.remove("skeleton");
}

function setText(id, value) {
  const element = document.getElementById(id);
  element.textContent = cleanText(value);
  clearLoading(element);
}

function showError(error) {
  const message = error instanceof Error ? error.message : String(error);
  setText(ids.ticketTitle, `Context load failed: ${message}`);
  setText(ids.ticketMeta, "Live context unavailable");
  document.getElementById("draft-pr").disabled = true;
}

async function requestJson(path, init) {
  const response = await fetch(`${apiBase}${path}`, init);
  const text = await response.text();
  if (!response.ok) {
    let detail = text;
    try {
      detail = JSON.parse(text).error?.message || text;
    } catch {
      detail = text;
    }
    throw new Error(detail || `${response.status} ${response.statusText}`);
  }
  return text ? JSON.parse(text) : {};
}

function formatArr(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount)) {
    return "Unknown";
  }
  if (amount >= 1000) {
    return `$${Math.round(amount / 1000)}k`;
  }
  return `$${amount}`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return cleanText(value);
  }
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function initials(name) {
  return String(name || "")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("") || "--";
}

function levelFor(line, errorType) {
  const upper = String(line).toUpperCase();
  if (upper.includes("ERROR") || upper.includes(String(errorType).toUpperCase())) {
    return "ERROR";
  }
  if (upper.includes("WARN")) {
    return "WARN";
  }
  return "INFO";
}

function cleanText(value) {
  return String(value ?? "").replace(/\u2014/g, "-");
}

function delay(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function skeletonRows(count) {
  return Array.from({ length: count }, () => (
    '<div class="ct"><div class="av skeleton"></div><div><div class="nm skeleton">Loading</div><div class="ro skeleton">Loading</div></div><span class="em skeleton">Loading</span><span class="src skeleton">Loading</span></div>'
  )).join("");
}

function skeletonLog(count) {
  return Array.from({ length: count }, (_, index) => (
    `<div class="row"><span class="gut">${String(index + 1).padStart(2, "0")}</span><span class="msg skeleton">Loading</span></div>`
  )).join("");
}
