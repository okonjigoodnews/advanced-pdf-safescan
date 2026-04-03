const DEFAULT_SETTINGS = {
  backendBaseUrl: "https://api.advanced-pdfsafescan.example",
  dashboardUrl: "https://dashboard.advanced-pdfsafescan.example",
  apiToken: "",
  autoScanDownloads: true,
  enableNotifications: true,
  warnOnSuspicious: true,
  autoOpenDashboardForMalicious: false
};

const form = document.getElementById("settings-form");
const resetDefaultsButton = document.getElementById("reset-defaults");
const saveStatus = document.getElementById("save-status");

document.addEventListener("DOMContentLoaded", loadSettings);
form.addEventListener("submit", saveSettings);
resetDefaultsButton.addEventListener("click", resetDefaults);

async function loadSettings() {
  const settings = await chrome.storage.sync.get(DEFAULT_SETTINGS);

  document.getElementById("backendBaseUrl").value = settings.backendBaseUrl || DEFAULT_SETTINGS.backendBaseUrl;
  document.getElementById("dashboardUrl").value = settings.dashboardUrl || DEFAULT_SETTINGS.dashboardUrl;
  document.getElementById("apiToken").value = settings.apiToken || DEFAULT_SETTINGS.apiToken;
  document.getElementById("autoScanDownloads").checked = Boolean(settings.autoScanDownloads);
  document.getElementById("enableNotifications").checked = Boolean(settings.enableNotifications);
  document.getElementById("warnOnSuspicious").checked = Boolean(settings.warnOnSuspicious);
  document.getElementById("autoOpenDashboardForMalicious").checked = Boolean(settings.autoOpenDashboardForMalicious);
}

async function saveSettings(event) {
  event.preventDefault();

  const settings = {
    backendBaseUrl: document.getElementById("backendBaseUrl").value.trim() || DEFAULT_SETTINGS.backendBaseUrl,
    dashboardUrl: document.getElementById("dashboardUrl").value.trim() || DEFAULT_SETTINGS.dashboardUrl,
    apiToken: document.getElementById("apiToken").value.trim(),
    autoScanDownloads: document.getElementById("autoScanDownloads").checked,
    enableNotifications: document.getElementById("enableNotifications").checked,
    warnOnSuspicious: document.getElementById("warnOnSuspicious").checked,
    autoOpenDashboardForMalicious: document.getElementById("autoOpenDashboardForMalicious").checked
  };

  await chrome.storage.sync.set(settings);
  saveStatus.textContent = "Settings saved.";
}

async function resetDefaults() {
  await chrome.storage.sync.set(DEFAULT_SETTINGS);
  await loadSettings();
  saveStatus.textContent = "Defaults restored.";
}
