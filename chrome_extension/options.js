const USER_PREFERENCE_DEFAULTS = {
  autoScanDownloads: true,
  enableNotifications: true,
  warnOnSuspicious: true,
  autoOpenDashboardForMalicious: false
};
const LEGACY_SENSITIVE_SETTING_KEYS = ["backendBaseUrl", "dashboardUrl", "apiToken"];

const form = document.getElementById("settings-form");
const resetDefaultsButton = document.getElementById("reset-defaults");
const saveStatus = document.getElementById("save-status");

document.addEventListener("DOMContentLoaded", loadSettings);
form.addEventListener("submit", saveSettings);
resetDefaultsButton.addEventListener("click", resetDefaults);

async function loadSettings() {
  const settings = await chrome.storage.sync.get(USER_PREFERENCE_DEFAULTS);

  document.getElementById("autoScanDownloads").checked = Boolean(settings.autoScanDownloads);
  document.getElementById("enableNotifications").checked = Boolean(settings.enableNotifications);
  document.getElementById("warnOnSuspicious").checked = Boolean(settings.warnOnSuspicious);
  document.getElementById("autoOpenDashboardForMalicious").checked = Boolean(settings.autoOpenDashboardForMalicious);
}

async function saveSettings(event) {
  event.preventDefault();

  const settings = {
    autoScanDownloads: document.getElementById("autoScanDownloads").checked,
    enableNotifications: document.getElementById("enableNotifications").checked,
    warnOnSuspicious: document.getElementById("warnOnSuspicious").checked,
    autoOpenDashboardForMalicious: document.getElementById("autoOpenDashboardForMalicious").checked
  };

  await chrome.storage.sync.set(settings);
  if (chrome.storage?.sync?.remove) {
    await chrome.storage.sync.remove(LEGACY_SENSITIVE_SETTING_KEYS);
  }
  saveStatus.textContent = "Preferences saved.";
}

async function resetDefaults() {
  await chrome.storage.sync.set(USER_PREFERENCE_DEFAULTS);
  if (chrome.storage?.sync?.remove) {
    await chrome.storage.sync.remove(LEGACY_SENSITIVE_SETTING_KEYS);
  }
  await loadSettings();
  saveStatus.textContent = "Default preferences restored.";
}
