const $ = (selector, parent = document) => parent.querySelector(selector);
const roles = { supervisor: "Supervisor", analyst: "Analista", reviewer: "Revisor", auditor: "Auditoría" };
const states = { new: "Nueva", assigned: "Asignada", analysis: "En análisis", escalated: "Escalada", closed: "Cerrada", reopened: "Reabierta" };
const priorities = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja" };
const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
const actionLabels = {
  assigned: "Asignada", started: "Análisis iniciado", escalated: "Escalada", closed: "Cerrada",
  approve_close: "Cierre aprobado", return: "Devuelta a análisis", reopened: "Reabierta",
  reassigned: "Reasignada",
  blocked: "Bloqueado por el sistema", created: "Alerta creada",
};
let currentUser = null;
let dashboard = null;
let selectedAlertId = null;
let analystUsers = [];
let toastTimer;

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = text;
  return element;
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  let payload = {};
  if (response.status !== 204) {
    try {
      payload = await response.json();
    } catch {
      payload = { error: "La respuesta del servidor no tiene un formato válido." };
    }
  }
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    throw new Error(payload.error || "No se pudo completar la solicitud.");
  }
  return payload;
}

function showLogin(message = "") {
  currentUser = null;
  $("#login-form").reset();
  $("#login-user").value = "";
  $("#login-password").value = "";
  $("#app").hidden = true;
  $("#login-screen").hidden = false;
  $("#login-error").hidden = !message;
  $("#login-error").textContent = message;
  $("#toast").hidden = true;
}

function showApp(user) {
  currentUser = user;
  $("#login-screen").hidden = true;
  $("#app").hidden = false;
  $("#user-name").textContent = user.username;
  $("#user-role").textContent = roles[user.role] || user.role;
  $("#user-avatar").textContent = user.username.charAt(0).toUpperCase();
  const auditTab = $('.tab[data-view="audit"]');
  auditTab.hidden = user.role !== "auditor";
  $("#exception-tab-count").hidden = user.role !== "auditor";
}

function formatTime(value) {
  return new Intl.DateTimeFormat("es", { dateStyle: "short", timeStyle: "short" })
    .format(new Date(value));
}

function formatAge(value) {
  const hours = Math.max(0, (Date.now() - new Date(value).getTime()) / 3600000);
  if (hours < 24) return `${Math.floor(hours)} h`;
  const days = Math.floor(hours / 24);
  return `${days} d`;
}

function isOverdue(alert) {
  return alert.status !== "closed" && new Date(alert.due_at).getTime() < Date.now();
}

function priorityChip(value) {
  return node("span", `priority priority-${value}`, priorities[value] || value);
}

function statusChip(value) {
  return node("span", "status-chip", states[value] || value);
}

function addMetric(parent, label, value, symbol, tone) {
  const metric = node("article", `metric metric-${tone}`);
  const text = node("div");
  text.append(node("span", "metric-label", label), node("strong", "metric-value", String(value)));
  metric.append(text, node("span", "metric-icon", symbol));
  parent.append(metric);
}

function renderMetrics(target, source) {
  target.replaceChildren();
  addMetric(target, "ABIERTAS", source.open, "◷", "danger");
  addMetric(target, "VENCIDAS", source.overdue, "!", "warn");
  addMetric(target, "REABIERTAS", source.reopened, "↺", "teal");
  addMetric(target, "EXCEPCIONES", source.exception_count, "◇", "blue");
}

function renderQueue() {
  if (!dashboard) return;
  const status = $("#status-filter").value;
  const priority = $("#priority-filter").value;
  const alerts = [...dashboard.alerts]
    .filter(alert => (status === "all" || alert.status === status) &&
      (priority === "all" || alert.priority === priority))
    .sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority] ||
      Number(isOverdue(b)) - Number(isOverdue(a)) ||
      new Date(a.created_at) - new Date(b.created_at));
  $("#alert-total").textContent = `${alerts.length} ${alerts.length === 1 ? "caso" : "casos"}`;
  const list = $("#alert-list");
  list.replaceChildren();
  if (!alerts.length) {
    list.append(node("p", "no-actions", "No hay alertas que coincidan con estos filtros."));
    return;
  }
  for (const alert of alerts) {
    const row = node("button", `alert-row${alert.id === selectedAlertId ? " selected" : ""}`);
    row.type = "button";
    row.setAttribute("aria-label", `${alert.id}, ${priorities[alert.priority]}, ${states[alert.status]}`);
    const main = node("span", "alert-row-main");
    const title = node("span", "alert-row-title");
    title.append(node("strong", "alert-id", alert.id), priorityChip(alert.priority));
    main.append(title, node("span", "alert-summary", alert.summary));
    const meta = node("span", "alert-row-meta");
    meta.append(node("span", "", formatAge(alert.created_at)), node("span", "", "·"),
      node("span", "", alert.assigned_to || "Sin asignar"));
    const end = node("span", "alert-row-end");
    end.append(statusChip(alert.status));
    if (isOverdue(alert)) end.append(node("span", "priority priority-high", "Vencida"));
    else end.append(node("span", "status-label", "SLA vigente"));
    row.append(main, end, meta);
    row.addEventListener("click", () => selectAlert(alert.id));
    list.append(row);
  }
}

function renderCharts() {
  const statesInOrder = ["new", "assigned", "analysis", "escalated", "closed", "reopened"];
  const chart = $("#status-chart");
  chart.replaceChildren();
  for (const status of statesInOrder) {
    const row = node("div", "bar-row");
    row.append(node("span", "", states[status]));
    const track = node("span", "bar-track");
    const fill = node("span", "bar-fill");
    fill.style.width = `${dashboard.alerts.length ? dashboard.counts[status] / dashboard.alerts.length * 100 : 0}%`;
    track.append(fill);
    row.append(track, node("strong", "bar-value", String(dashboard.counts[status])));
    chart.append(row);
  }
  const ages = [
    ["0–1 d", dashboard.age_buckets["0-1"]],
    ["2–3 d", dashboard.age_buckets["2-3"]],
    ["4–7 d", dashboard.age_buckets["4-7"]],
    ["> 7 d", dashboard.age_buckets[">7"]],
  ];
  const max = Math.max(1, ...ages.map(([, value]) => value));
  const ageChart = $("#age-chart");
  ageChart.replaceChildren();
  for (const [label, value] of ages) {
    const column = node("div", "age-column");
    const track = node("div", "age-track");
    const fill = node("span", "age-fill", String(value));
    fill.style.height = `${Math.max(value ? 10 : 5, value / max * 60)}px`;
    track.append(fill);
    column.append(track, node("span", "age-label", label));
    ageChart.append(column);
  }
}

function actionDefinitions(alert) {
  const { role, username } = currentUser;
  const mine = alert.assigned_to === username;
  const actions = [];
  if (role === "supervisor" && alert.status === "new")
    actions.push(["assign", "Asignar analista", "primary"]);
  if (role === "supervisor" && ["assigned", "analysis", "escalated", "reopened"].includes(alert.status))
    actions.push(["reassign", "Reasignar con motivo", "secondary"]);
  if (role === "analyst" && mine && ["assigned", "reopened"].includes(alert.status))
    actions.push(["start", "Iniciar análisis", "primary"]);
  if (role === "analyst" && mine && alert.status === "analysis" && alert.priority === "critical")
    actions.push(["escalate", "Escalar a segundo revisor", "primary"]);
  if (role === "analyst" && mine && alert.status === "analysis" && alert.priority !== "critical")
    actions.push(["close", "Cerrar con justificación", "primary"]);
  if (role === "analyst" && mine && alert.priority === "critical" && ["analysis", "escalated"].includes(alert.status))
    actions.push(["close", "Intentar cierre crítico (prueba de bloqueo)", "danger"]);
  if (role === "reviewer" && alert.status === "escalated" && !mine) {
    actions.push(["approve_close", "Aprobar y cerrar", "primary"]);
    actions.push(["return", "Devolver con motivo", "secondary"]);
  }
  if (role === "supervisor" && alert.status === "closed")
    actions.push(["reopen", "Reabrir con justificación", "secondary"]);
  return actions;
}

async function selectAlert(alertId) {
  selectedAlertId = alertId;
  renderQueue();
  try {
    const alert = await request(`/api/alerts/${encodeURIComponent(alertId)}`);
    renderDetail(alert);
  } catch (error) {
    showToast(error.message, true);
  }
}

function renderDetail(alert) {
  const container = $("#detail-content");
  container.className = "detail-content";
  container.replaceChildren();
  const top = node("div", "detail-top");
  const title = node("div");
  const idLine = node("div", "detail-id");
  idLine.append(node("span", "", alert.id), priorityChip(alert.priority));
  title.append(idLine, node("h2", "", alert.summary));
  top.append(title);
  const right = node("div", "detail-status");
  right.append(statusChip(alert.status));
  top.append(right);
  container.append(top);

  const facts = node("div", "detail-facts");
  const factEntries = [
    ["Asignado a", alert.assigned_to || "Sin asignar"],
    ["Antigüedad", formatAge(alert.created_at)],
    ["Creada", formatTime(alert.created_at)],
    ["Vence", formatTime(alert.due_at)],
    ["Identificador", alert.id],
    ["Plazo", isOverdue(alert) ? "Vencida" : "Dentro del SLA"],
  ];
  for (const [label, value] of factEntries) {
    const fact = node("div", "fact");
    fact.append(node("span", "fact-label", label), node("strong", "fact-value", value));
    facts.append(fact);
  }
  container.append(facts);
  if (alert.priority === "critical") {
    const notice = node("p", "alert-notice notice-critical",
      "Control reforzado: solo un revisor distinto del analista asignado puede aprobar el cierre de este caso crítico.");
    container.append(notice);
  } else if (isOverdue(alert)) {
    container.append(node("p", "alert-notice", "Alerta vencida según el SLA académico simulado. Priorice su revisión."));
  }

  const label = node("h3", "section-label");
  label.append(node("span", "", "Historial y evidencia"), node("small", "", `${alert.events.length} eventos · solo anexos sintéticos`));
  container.append(label);
  const timeline = node("div", "timeline");
  for (const event of alert.events) {
    const item = node("div", `timeline-item${event.event_type === "blocked" ? " timeline-blocked" : ""}`);
    const body = node("div");
    const head = node("div", "timeline-head");
    head.append(node("strong", "", `${event.actor} · ${actionLabels[event.event_type] || event.event_type}`),
      node("time", "timeline-time", formatTime(event.created_at)));
    body.append(head, node("p", "timeline-body", `${event.reason} · Evidencia: ${event.evidence}`));
    item.append(node("span", "timeline-dot"), body);
    timeline.append(item);
  }
  container.append(timeline);
  renderActions(container, alert);
}

async function renderActions(container, alert) {
  const area = node("div", "action-area");
  area.append(node("h3", "action-title", "Acciones disponibles para su rol"));
  const actions = actionDefinitions(alert);
  if (!actions.length) {
    area.append(node("p", "no-actions", currentUser.role === "auditor"
      ? "Acceso de auditoría: consulta de solo lectura."
      : "No hay acciones habilitadas para su rol en este estado."));
    container.append(area);
    return;
  }
  const grid = node("div", "action-grid");
  for (const [action, label, tone] of actions) {
    const button = node("button", `button action-button ${tone === "primary" ? "button-primary" : tone === "danger" ? "button-danger" : "button-secondary"}`, label);
    button.type = "button";
    button.addEventListener("click", () => {
      if (action === "close" && alert.priority === "critical") {
        submitAction(alert, action, {
          reason: "Intento de cierre crítico propio para comprobar el control de segregación.",
          evidence: "Regla de control SOC-01",
        });
      } else {
        showActionForm(area, alert, action, label);
      }
    });
    grid.append(button);
  }
  area.append(grid);
  container.append(area);
}

async function showActionForm(area, alert, action, label) {
  const oldForm = $(".action-form", area);
  if (oldForm) oldForm.remove();
  const form = node("form", "action-form");
  form.addEventListener("submit", event => {
    event.preventDefault();
    const reason = $("#action-reason", form).value.trim();
    const evidence = $("#action-evidence", form).value.trim();
    const payload = { action, reason, evidence };
    if (action === "assign" || action === "reassign") payload.assignee = $("#action-assignee", form).value;
    submitAction(alert, action, payload);
  });
  if (action === "assign" || action === "reassign") {
    if (!analystUsers.length) {
      try {
        const result = await request("/api/users");
        analystUsers = result.users;
      } catch (error) {
        showToast(error.message, true);
        return;
      }
    }
    const selectLabel = node("label", "", "Analista responsable");
    const select = node("select");
    select.id = "action-assignee";
    select.required = true;
    for (const user of analystUsers) {
      const option = node("option", "", user.username);
      option.value = user.username;
      select.append(option);
    }
    selectLabel.append(select);
    form.append(selectLabel);
  }
  const reasonLabel = node("label", "", "Motivo obligatorio");
  const reason = node("textarea");
  reason.id = "action-reason";
  reason.required = true;
  reason.maxLength = 500;
  reason.placeholder = `Justifique: ${label.toLowerCase()}`;
  reasonLabel.append(reason);
  const evidenceLabel = node("label", "", "Referencia de evidencia sintética");
  const evidence = node("input");
  evidence.id = "action-evidence";
  evidence.required = true;
  evidence.maxLength = 200;
  evidence.placeholder = "Ej.: EV-1 (no adjunte datos reales)";
  evidenceLabel.append(evidence);
  const buttons = node("div", "form-buttons");
  const cancel = node("button", "button button-secondary", "Cancelar");
  cancel.type = "button";
  cancel.addEventListener("click", () => form.remove());
  const submit = node("button", "button button-primary", "Confirmar acción");
  submit.type = "submit";
  buttons.append(cancel, submit);
  form.append(reasonLabel, evidenceLabel, buttons);
  area.append(form);
  reason.focus();
}

async function submitAction(alert, action, payload) {
  try {
    await request(`/api/alerts/${encodeURIComponent(alert.id)}/actions`, {
      method: "POST", body: JSON.stringify(payload),
    });
    showToast(action === "close" && alert.priority === "critical"
      ? "Bloqueo aplicado y registrado en la bitácora."
      : "Acción guardada con motivo y evidencia.");
    await refreshDashboard();
    await selectAlert(alert.id);
  } catch (error) {
    showToast(error.message, true);
    await selectAlert(alert.id);
  }
}

async function refreshDashboard() {
  dashboard = await request("/api/dashboard");
  renderMetrics($("#metrics"), dashboard);
  $("#exception-tab-count").textContent = String(dashboard.exception_count);
  $("#updated-at").textContent = new Intl.DateTimeFormat("es", { timeStyle: "short" }).format(new Date());
  renderQueue();
  renderCharts();
  if (selectedAlertId) {
    const found = dashboard.alerts.some(alert => alert.id === selectedAlertId);
    if (found) await selectAlert(selectedAlertId);
  }
}

async function renderAudit() {
  if (currentUser.role !== "auditor") return;
  const audit = await request("/api/audit");
  renderMetrics($("#audit-metrics"), dashboard);
  const exceptions = $("#exception-list");
  exceptions.replaceChildren();
  for (const entry of audit.exceptions) {
    const row = node("div", "exception-row");
    const text = node("div");
    text.append(node("strong", "exception-title", entry.title),
      node("span", "exception-detail", `${entry.detail} · Caso ${entry.alert_id}`));
    row.append(text, node("span", "exception-code", entry.code));
    exceptions.append(row);
  }
  if (!audit.exceptions.length) exceptions.append(node("p", "no-actions", "No hay excepciones registradas."));
  const overdue = $("#overdue-list");
  overdue.replaceChildren();
  for (const alert of audit.overdue) {
    const row = node("button", "overdue-row");
    row.type = "button";
    const text = node("span");
    text.append(node("strong", "overdue-id", alert.id),
      node("span", "overdue-summary", ` · ${alert.summary}`),
      node("small", "overdue-meta", `${priorities[alert.priority]} · ${formatAge(alert.created_at)} · Vencía ${formatTime(alert.due_at)}`));
    row.append(text, node("span", "priority priority-high", "VENCIDA"));
    row.addEventListener("click", () => {
      switchView("operation");
      selectAlert(alert.id);
    });
    overdue.append(row);
  }
  if (!audit.overdue.length) overdue.append(node("p", "no-actions", "No hay alertas vencidas."));
}

function switchView(view) {
  $("#operation-view").hidden = view !== "operation";
  $("#audit-view").hidden = view !== "audit";
  document.querySelectorAll(".tab").forEach(tab => tab.classList.toggle("active", tab.dataset.view === view));
  if (view === "audit") renderAudit().catch(error => showToast(error.message, true));
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 3600);
}

$("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const error = $("#login-error");
  error.hidden = true;
  const form = new FormData(event.currentTarget);
  try {
    const result = await request("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: form.get("username"),
        password: form.get("password"),
      }),
    });
    showApp(result.user);
    await refreshDashboard();
    selectedAlertId = "AL-0192";
    await selectAlert(selectedAlertId);
  } catch (err) {
    error.hidden = false;
    error.textContent = err.message;
  }
});

$("#logout-button").addEventListener("click", async () => {
  try { await request("/api/logout", { method: "POST", body: "{}" }); }
  finally { showLogin(); }
});

document.querySelectorAll(".tab").forEach(tab =>
  tab.addEventListener("click", () => switchView(tab.dataset.view)));
$("#status-filter").addEventListener("change", renderQueue);
$("#priority-filter").addEventListener("change", renderQueue);

(async function initializeUi() {
  try {
    const session = await request("/api/session");
    if (!session.user) return showLogin();
    showApp(session.user);
    await refreshDashboard();
    selectedAlertId = "AL-0192";
    await selectAlert(selectedAlertId);
  } catch (error) {
    showLogin("No se pudo conectar con el servidor local. Inícielo con python src/server.py.");
  }
})();
