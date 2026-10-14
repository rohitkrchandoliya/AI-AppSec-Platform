const input = document.querySelector("#source-files");
const button = document.querySelector("#scan-button");
const statusNode = document.querySelector("#status");
const findingsNode = document.querySelector("#findings");
const risksNode = document.querySelector("#dependency-risks");

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

button.addEventListener("click", async () => {
  button.disabled = true;
  statusNode.textContent = "Scanning…";
  try {
    const payload = JSON.parse(input.value);
    const response = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
  } catch (error) {
    statusNode.textContent = error instanceof Error ? error.message : "Scan failed.";
  } finally {
    button.disabled = false;
  }
});
