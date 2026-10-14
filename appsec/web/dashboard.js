const input = document.querySelector("#source-files");
const button = document.querySelector("#scan-button");
const statusNode = document.querySelector("#status");
const findingsNode = document.querySelector("#findings");
const risksNode = document.querySelector("#dependency-risks");
const historyNode = document.querySelector("#history");
const historyStatus = document.querySelector("#history-status");
const projectSelect = document.querySelector("#project-select");

function authHeaders(json = false) {
  const headers = {};
  if (json) headers["Content-Type"] = "application/json";
  const token = document.querySelector("#api-token").value.trim();
  if (token) headers.Authorization = "Bearer " + token;
  return headers;
}

function textElement(tag, value, className) {
  const element = document.createElement(tag);
  element.textContent = String(value ?? "");
  if (className) element.className = className;
  return element;
}

function renderFindings(findings) {
  findingsNode.replaceChildren();
  if (!findings.length) {
    findingsNode.append(textElement("p", "No findings detected by the configured rules.", "muted"));
    return;
  }
  for (const finding of findings) {
    const card = document.createElement("article");
    card.className = "finding";
    const title = document.createElement("h3");
    title.append(textElement("span", finding.severity, "badge " + finding.severity));
    title.append(document.createTextNode(finding.title));
    card.append(title);
    card.append(textElement("p", finding.message));
    card.append(textElement("p", finding.path + ":" + finding.line + " · " + finding.rule_id, "meta"));
    findingsNode.append(card);
  }
}

function renderRisks(risks) {
  risksNode.replaceChildren();
  if (!risks.length) {
    risksNode.append(textElement("p", "No pinned Python dependencies found.", "muted"));
    return;
  }
  for (const risk of risks) {
    const card = document.createElement("article");
    card.className = "dependency";
    card.append(textElement("strong", risk.name + " · score " + risk.score + "/100"));
    card.append(textElement("p", risk.severity + " — " + risk.rationale, "meta"));
    risksNode.append(card);
  }
}

async function loadScan(scanId) {
  historyStatus.textContent = "Loading scan #" + scanId + "…";
  try {
    const response = await fetch("/history/" + encodeURIComponent(scanId), { headers: authHeaders() });
    const saved = await response.json();
    if (!response.ok) throw new Error(saved.error || "Could not load scan.");
    const result = saved.result;
    document.querySelector("#files-count").textContent = result.files_scanned;
    document.querySelector("#findings-count").textContent = result.findings.length;
    document.querySelector("#dependencies-count").textContent = result.dependencies.length;
    renderFindings(result.findings);
    renderRisks(result.dependency_risks);
    historyStatus.textContent = "Showing saved scan #" + scanId + " from " + saved.project + ".";
  } catch (error) {
    historyStatus.textContent = error instanceof Error ? error.message : "Could not load scan history.";
  }
}

async function refreshHistory() {
  try {
    const response = await fetch("/history?limit=20", { headers: authHeaders() });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "History is unavailable.");
    historyNode.replaceChildren();
    if (!data.scans.length) {
      historyNode.append(textElement("p", "No saved scans yet.", "muted"));
    }
    for (const scan of data.scans) {
      const card = document.createElement("article");
      card.className = "finding";
      card.append(textElement("h3", scan.project + " · Scan #" + scan.id));
      card.append(textElement(
        "p",
        scan.created_at + " · " + scan.files_scanned + " files · " +
          scan.finding_count + " findings · " + scan.dependency_count + " dependencies",
        "meta"
      ));
      const view = textElement("button", "View findings");
      view.type = "button";
      view.addEventListener("click", () => loadScan(scan.id));
      card.append(view);
      historyNode.append(card);
    }
    historyStatus.textContent = "Showing the 20 most recent saved scans.";
  } catch (error) {
    historyNode.replaceChildren();
    historyStatus.textContent = error instanceof Error
      ? error.message
      : "History is disabled. Set APPSEC_DB_PATH when starting the API.";
  }
}

async function refreshProjects() {
  try {
    const response = await fetch("/projects", { headers: authHeaders() });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Projects are unavailable.");
    const selected = projectSelect.value || "default";
    projectSelect.replaceChildren();
    if (data.is_admin || data.projects.length === 0) {
      const defaultOption = textElement("option", "default");
      defaultOption.value = "default";
      projectSelect.append(defaultOption);
    }
    for (const project of data.projects) {
      const option = textElement("option", project.name);
      option.value = project.name;
      projectSelect.append(option);
    }
    const available = [...projectSelect.options];
    projectSelect.value = available.some((option) => option.value === selected)
      ? selected
      : (available[0]?.value || "");
    projectSelect.disabled = available.length === 0;
  } catch {
    // A missing APPSEC_DB_PATH intentionally disables persistent project features.
  }
}

document.querySelector("#create-project").addEventListener("click", async () => {
  const name = document.querySelector("#project-name").value.trim();
  if (!name) {
    historyStatus.textContent = "Enter a project name first.";
    return;
  }
  try {
    const response = await fetch("/projects", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify({ name }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not create project.");
    document.querySelector("#project-name").value = "";
    await refreshProjects();
    projectSelect.value = data.project.name;
    historyStatus.textContent = "Created project " + data.project.name + ".";
  } catch (error) {
    historyStatus.textContent = error instanceof Error ? error.message : "Could not create project.";
  }
});

document.querySelector("#refresh-history").addEventListener("click", refreshHistory);

button.addEventListener("click", async () => {
  button.disabled = true;
  statusNode.textContent = "Scanning…";
  try {
    const payload = JSON.parse(input.value);
    if (projectSelect.value && projectSelect.value !== "default") {
      payload.project = projectSelect.value;
    }
    const response = await fetch("/scan", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Scan request failed.");
    document.querySelector("#files-count").textContent = result.files_scanned;
    document.querySelector("#findings-count").textContent = result.findings.length;
    document.querySelector("#dependencies-count").textContent = result.dependencies.length;
    renderFindings(result.findings);
    renderRisks(result.dependency_risks);
    statusNode.textContent = "Scan complete";
    await refreshProjects();
    await refreshHistory();
  } catch (error) {
    statusNode.textContent = error instanceof Error ? error.message : "Scan failed.";
  } finally {
    button.disabled = false;
  }
});

void refreshProjects();
void refreshHistory();


document.querySelector("#api-token").addEventListener("change", () => {
  void refreshProjects();
  void refreshHistory();
});
