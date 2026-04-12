const backendStatus = document.getElementById("backend-status");
const latestVerdictBadge = document.getElementById("latest-verdict-badge");
const resultFile = document.getElementById("result-file");
const resultState = document.getElementById("result-state");
const metricConfidence = document.getElementById("metric-confidence");
const metricRuleScore = document.getElementById("metric-rule-score");
const resultRecommendation = document.getElementById("result-recommendation");
const recentScanList = document.getElementById("recent-scan-list");
const scanCurrentTabButton = document.getElementById("scan-current-tab");
const openDashboardButton = document.getElementById("open-dashboard");
const openSettingsButton = document.getElementById("open-settings");
const refreshRecentButton = document.getElementById("refresh-recent");

document.addEventListener("DOMContentLoaded", initializePopup);
scanCurrentTabButton.addEventListener("click", handleScanCurrentTab);
openDashboardButton.addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "openDashboard" });
});
openSettingsButton.addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "openOptionsPage" });
});
refreshRecentButton.addEventListener("click", initializePopup);

async function initializePopup() {
  setBusyState(true);
  const response = await sendMessage({ action: "getPopupState" });
  setBusyState(false);

  if (!response.ok) {
    renderFailedState(response.error || "Could not load popup state.");
    return;
  }

  renderBackendStatus(response.backendReachable);
  renderScanResult(response.latestScanResult);
  renderRecentScans(response.recentScans || []);
}

async function handleScanCurrentTab() {
  scanCurrentTabButton.disabled = true;
  scanCurrentTabButton.textContent = "Scanning...";

  const response = await sendMessage({ action: "scanCurrentTab" });

  scanCurrentTabButton.disabled = false;
  scanCurrentTabButton.textContent = "Scan Current PDF";

  if (!response.ok) {
    renderFailedState(response.error || "Scan request failed.");
    return;
  }

  renderBackendStatus(true);
  renderScanResult(response.result);
  await initializePopup();
}

function renderBackendStatus(isReachable) {
  const online = Boolean(isReachable);
  backendStatus.textContent = online ? "Online" : "Offline";
  backendStatus.className = online
    ? "status-pill status-pill-online"
    : "status-pill status-pill-offline";
}

function renderScanResult(result) {
  if (!result) {
    latestVerdictBadge.textContent = "No scans yet";
    latestVerdictBadge.className = "verdict-badge verdict-failed";
    resultFile.textContent = "Right-click a PDF link or PDF page to scan it.";
    resultState.textContent = "Idle";
    metricConfidence.textContent = "0.00";
    metricRuleScore.textContent = "0.00";
    resultRecommendation.textContent = "No scan result is currently stored in the extension.";
    return;
  }

  const verdictState = result.verdictState || mapVerdictState(result.final_label);
  latestVerdictBadge.textContent = formatVerdictLabel(result.final_label);
  latestVerdictBadge.className = `verdict-badge ${verdictClass(verdictState)}`;
  resultFile.textContent = result.file_name || result.source_url || "Scanned PDF";
  resultState.textContent = result.cached ? "Cached Result" : "Fresh Scan";
  metricConfidence.textContent = Number(result.final_confidence || 0).toFixed(2);
  metricRuleScore.textContent = Number(result.rule_score || 0).toFixed(2);
  resultRecommendation.textContent = result.recommendation || result.message || "No recommendation available.";
}

function renderRecentScans(recentScans) {
  recentScanList.innerHTML = "";

  if (!recentScans.length) {
    recentScanList.innerHTML = '<li class="empty-state">No recent scans available.</li>';
    return;
  }

  recentScans.forEach((item) => {
    const verdictState = item.verdictState || mapVerdictState(item.final_label);
    const listItem = document.createElement("li");
    listItem.className = "recent-item";
    listItem.innerHTML = `
      <div class="recent-title">${escapeHtml(item.file_name || "Scanned PDF")}</div>
      <div class="recent-meta">PDF</div>
      <div class="recent-meta">${escapeHtml(item.timestamp || "")}</div>
      <div class="recent-footer">
        <span class="verdict-badge ${verdictClass(verdictState)}">${escapeHtml(formatVerdictLabel(item.final_label))}</span>
        <span class="recent-score">Rule ${Number(item.rule_score || 0).toFixed(2)}</span>
      </div>
    `;
    recentScanList.appendChild(listItem);
  });
}

function renderFailedState(message) {
  renderBackendStatus(false);
  renderScanResult({
    final_label: "failed",
    verdictState: "failed",
    file_name: "Hosted PDF Scanner",
    file_type: "pdf",
    recommendation: message,
    final_confidence: 0,
    rule_score: 0
  });
}

function setBusyState(isBusy) {
  scanCurrentTabButton.disabled = isBusy;
  refreshRecentButton.disabled = isBusy;
}

function verdictClass(verdictState) {
  if (verdictState === "safe") {
    return "verdict-safe";
  }
  if (verdictState === "suspicious") {
    return "verdict-suspicious";
  }
  if (verdictState === "malicious") {
    return "verdict-malicious";
  }
  return "verdict-failed";
}

function mapVerdictState(label) {
  const normalizedLabel = String(label || "").toLowerCase();
  if (normalizedLabel === "benign" || normalizedLabel === "safe") {
    return "safe";
  }
  if (normalizedLabel === "suspicious") {
    return "suspicious";
  }
  if (normalizedLabel === "malicious") {
    return "malicious";
  }
  return "failed";
}

function formatVerdictLabel(label) {
  const normalizedLabel = String(label || "").toLowerCase();
  if (normalizedLabel === "benign") {
    return "Benign";
  }
  if (normalizedLabel === "suspicious") {
    return "Suspicious";
  }
  if (normalizedLabel === "malicious") {
    return "Malicious";
  }
  return "Failed";
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sendMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      resolve(response || { ok: false, error: "No response from background service." });
    });
  });
}
