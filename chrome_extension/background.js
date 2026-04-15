const PROTECTED_PRODUCTION_CONFIG = Object.freeze({
  backendBaseUrl: "https://advanced-pdf-safescan-api.onrender.com",
  dashboardUrl: "https://advanced-pdfsafescan-dashboard.onrender.com",
  apiToken: ""
});

const USER_PREFERENCE_DEFAULTS = Object.freeze({
  autoScanDownloads: true,
  enableNotifications: true,
  warnOnSuspicious: true,
  autoOpenDashboardForMalicious: false
});

const LEGACY_SENSITIVE_SETTING_KEYS = Object.freeze([
  "backendBaseUrl",
  "dashboardUrl",
  "apiToken"
]);

const ADMIN_OVERRIDE_ENABLED = false;
const ADMIN_OVERRIDE_CONFIG = Object.freeze({});

const DEFAULT_LOCAL_STATE = {
  latestScanResult: null,
  recentScans: []
};

const CONTEXT_MENU_SCAN_LINK = "advanced-pdfsafescan-scan-link";
const CONTEXT_MENU_SCAN_PAGE = "advanced-pdfsafescan-scan-page";
const MAX_RECENT_SCANS = 8;
const API_TOKEN_HEADER_NAME = "X-API-Token";
const CLIENT_ID_HEADER_NAME = "X-Client-ID";
const CLIENT_ID_STORAGE_KEY = "advanced_pdfsafescan_client_id";
const NOTIFICATION_ICON_URL = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(`
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
    <defs>
      <linearGradient id="shield" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#22d3ee"/>
        <stop offset="55%" stop-color="#2563eb"/>
        <stop offset="100%" stop-color="#8b5cf6"/>
      </linearGradient>
    </defs>
    <rect width="128" height="128" rx="28" fill="#04111f"/>
    <path d="M64 18 101 31v27c0 27-14 42-37 52C41 100 27 85 27 58V31l37-13Z" fill="url(#shield)"/>
    <path d="M64 31 88 39v19c0 18-8 29-24 38-16-9-24-20-24-38V39l24-8Z" fill="#081426"/>
    <path d="m52 64 8 8 18-21" fill="none" stroke="#dbeafe" stroke-linecap="round" stroke-linejoin="round" stroke-width="9"/>
  </svg>
`)}`;

const hasChromeApis =
  typeof chrome !== "undefined" &&
  chrome.runtime &&
  chrome.storage &&
  chrome.storage.local;

if (hasChromeApis && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener(async () => {
    await initializeSettings();
    await ensureContextMenus();
  });
}

if (hasChromeApis && chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(async () => {
    await initializeSettings();
    await ensureContextMenus();
  });
}

if (hasChromeApis && chrome.contextMenus && chrome.contextMenus.onClicked) {
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === CONTEXT_MENU_SCAN_LINK && info.linkUrl) {
      scanPdfUrl(info.linkUrl, { trigger: "context-link" });
      return;
    }
    if (info.menuItemId === CONTEXT_MENU_SCAN_PAGE && tab?.url) {
      scanPdfUrl(tab.url, { trigger: "context-page" });
    }
  });
}

if (hasChromeApis && chrome.downloads && chrome.downloads.onChanged) {
  chrome.downloads.onChanged.addListener((delta) => {
    if (delta.state?.current !== "complete") {
      return;
    }
    handleCompletedDownload(delta.id);
  });
}

if (hasChromeApis && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    (async () => {
      if (message?.action === "getPopupState") {
        const settings = await getSettings();
        const backendHealth = await checkBackendHealth(settings);
        const storageState = await chrome.storage.local.get(DEFAULT_LOCAL_STATE);
        const backendRecentScans = await fetchRecentScans(settings);
        const recentScans = backendRecentScans.length ? backendRecentScans : storageState.recentScans;

        if (backendRecentScans.length) {
          await chrome.storage.local.set({ recentScans: backendRecentScans });
        }

        sendResponse({
          ok: true,
          backendReachable: backendHealth.reachable,
          backendMessage: backendHealth.message,
          latestScanResult: storageState.latestScanResult,
          recentScans
        });
        return;
      }

      if (message?.action === "scanCurrentTab") {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url || !isPdfUrl(tab.url)) {
          throw new Error("The current tab does not appear to be a supported PDF page.");
        }
        const result = await scanPdfUrl(tab.url, { trigger: "popup-current-tab" });
        sendResponse({ ok: true, result });
        return;
      }

      if (message?.action === "openDashboard") {
        const settings = await getSettings();
        const clientId = await getOrCreateClientId();
        await openUrl(buildDashboardUrl(settings.dashboardUrl, clientId));
        sendResponse({ ok: true });
        return;
      }

      if (message?.action === "openOptionsPage") {
        await chrome.runtime.openOptionsPage();
        sendResponse({ ok: true });
        return;
      }

      sendResponse({ ok: false, error: "Unknown extension action." });
    })().catch((error) => {
      sendResponse({ ok: false, error: error.message || String(error) });
    });

    return true;
  });
}

async function initializeSettings() {
  const storedSettings = await chrome.storage.sync.get(USER_PREFERENCE_DEFAULTS);
  await chrome.storage.sync.set(sanitizeUserPreferences(storedSettings));
  if (chrome.storage?.sync?.remove) {
    await chrome.storage.sync.remove([...LEGACY_SENSITIVE_SETTING_KEYS]);
  }
  await getOrCreateClientId();
}

async function ensureContextMenus() {
  await chrome.contextMenus.removeAll();

  chrome.contextMenus.create({
    id: CONTEXT_MENU_SCAN_LINK,
    title: "Scan PDF with Advanced PDFSafeScan",
    contexts: ["link"],
    targetUrlPatterns: [
      "*://*/*.pdf",
      "*://*/*.pdf?*"
    ]
  });

  chrome.contextMenus.create({
    id: CONTEXT_MENU_SCAN_PAGE,
    title: "Scan Current PDF with Advanced PDFSafeScan",
    contexts: ["page"],
    documentUrlPatterns: [
      "*://*/*.pdf",
      "*://*/*.pdf?*"
    ]
  });
}

function getProtectedRuntimeConfig() {
  if (!ADMIN_OVERRIDE_ENABLED) {
    return { ...PROTECTED_PRODUCTION_CONFIG };
  }
  return {
    ...PROTECTED_PRODUCTION_CONFIG,
    ...ADMIN_OVERRIDE_CONFIG
  };
}

function sanitizeUserPreferences(storedSettings = {}) {
  return {
    autoScanDownloads:
      storedSettings.autoScanDownloads ?? USER_PREFERENCE_DEFAULTS.autoScanDownloads,
    enableNotifications:
      storedSettings.enableNotifications ?? USER_PREFERENCE_DEFAULTS.enableNotifications,
    warnOnSuspicious:
      storedSettings.warnOnSuspicious ?? USER_PREFERENCE_DEFAULTS.warnOnSuspicious,
    autoOpenDashboardForMalicious:
      storedSettings.autoOpenDashboardForMalicious ??
      USER_PREFERENCE_DEFAULTS.autoOpenDashboardForMalicious
  };
}

function buildEffectiveSettings(storedSettings = {}) {
  return {
    ...getProtectedRuntimeConfig(),
    ...sanitizeUserPreferences(storedSettings)
  };
}

async function getSettings() {
  const storedSettings = await chrome.storage.sync.get(USER_PREFERENCE_DEFAULTS);
  return buildEffectiveSettings(storedSettings);
}

async function getOrCreateClientId() {
  const storedValue = await chrome.storage.local.get(CLIENT_ID_STORAGE_KEY);
  const existingClientId = normalizeStoredClientId(storedValue?.[CLIENT_ID_STORAGE_KEY]);
  if (existingClientId) {
    return existingClientId;
  }

  const clientId = generateClientId();
  await chrome.storage.local.set({ [CLIENT_ID_STORAGE_KEY]: clientId });
  return clientId;
}

function normalizeStoredClientId(value) {
  return String(value || "").trim();
}

function generateClientId() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }

  const randomBytes = new Uint8Array(16);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(randomBytes);
  } else {
    for (let index = 0; index < randomBytes.length; index += 1) {
      randomBytes[index] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(randomBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function handleCompletedDownload(downloadId) {
  const settings = await getSettings();
  if (!settings.autoScanDownloads) {
    return;
  }

  const [downloadItem] = await chrome.downloads.search({ id: downloadId });
  if (!downloadItem || !isLikelyPdfDownload(downloadItem)) {
    return;
  }

  const sourceUrl = getDownloadSourceUrl(downloadItem);
  if (!sourceUrl) {
    const unavailableResult = buildUnavailableDownloadResult(downloadItem);
    await rememberScanResult(unavailableResult);
    await maybeNotify(unavailableResult, settings, { trigger: "download-unavailable" });
    return;
  }

  await scanPdfUrl(sourceUrl, {
    trigger: "download-complete",
    downloadedFilename: downloadItem.filename || ""
  });
}

async function scanPdfUrl(url, context = {}) {
  const settings = await getSettings();
  const clientId = await getOrCreateClientId();

  try {
    const response = await fetch(normalizeBaseUrl(settings.backendBaseUrl) + "/api/scan/url", {
      method: "POST",
      headers: buildApiHeaders(settings, clientId, { includeJsonContentType: true }),
      body: JSON.stringify({ url })
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.status === "error") {
      throw new Error(payload.message || "Hosted API request failed.");
    }

    const normalizedResult = normalizeScanResult(payload, url, context);
    await rememberScanResult(normalizedResult);
    await maybeNotify(normalizedResult, settings, context);
    return normalizedResult;
  } catch (error) {
    const failedResult = buildFailedResult(url, error, context);
    await rememberScanResult(failedResult);
    await maybeNotify(failedResult, settings, context);
    return failedResult;
  }
}

async function fetchRecentScans(settings) {
  const clientId = await getOrCreateClientId();

  try {
    const response = await fetch(
      normalizeBaseUrl(settings.backendBaseUrl) + `/api/scan/recent?limit=${MAX_RECENT_SCANS}`,
      {
        headers: buildApiHeaders(settings, clientId)
      }
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.status === "error" || !Array.isArray(payload.items)) {
      return [];
    }
    return payload.items.map((item) => normalizeRecentItem(item));
  } catch (error) {
    return [];
  }
}

async function checkBackendHealth(settings) {
  const clientId = await getOrCreateClientId();

  try {
    const response = await fetch(normalizeBaseUrl(settings.backendBaseUrl) + "/api/health", {
      headers: buildApiHeaders(settings, clientId)
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.status !== "ok") {
      return { reachable: false, message: payload.message || "Hosted API did not return a healthy status." };
    }
    return { reachable: true, message: payload.mode || "ok" };
  } catch (error) {
    return { reachable: false, message: error.message || String(error) };
  }
}

async function rememberScanResult(result) {
  const localState = await chrome.storage.local.get(DEFAULT_LOCAL_STATE);
  const recentScans = [normalizeRecentItem(result), ...localState.recentScans]
    .filter((item, index, items) => {
      return index === items.findIndex((candidate) => {
        return candidate.timestamp === item.timestamp && candidate.file_name === item.file_name;
      });
    })
    .slice(0, MAX_RECENT_SCANS);

  await chrome.storage.local.set({
    latestScanResult: result,
    recentScans
  });
}

async function maybeNotify(result, settings, context) {
  if (!settings.enableNotifications) {
    return;
  }

  const fromDownload = String(context.trigger || "").startsWith("download");
  if (result.verdictState === "suspicious" && !settings.warnOnSuspicious) {
    return;
  }

  if (!fromDownload && !["suspicious", "malicious", "failed"].includes(result.verdictState)) {
    return;
  }

  const title = notificationTitle(result, fromDownload);
  const message = notificationMessage(result, fromDownload);

  chrome.notifications.create({
    type: "basic",
    iconUrl: NOTIFICATION_ICON_URL,
    title,
    message,
    priority: result.verdictState === "malicious" ? 2 : 0
  });

  if (result.verdictState === "malicious" && settings.autoOpenDashboardForMalicious) {
    const clientId = await getOrCreateClientId();
    await openUrl(buildDashboardUrl(settings.dashboardUrl, clientId));
  }
}

function buildApiHeaders(settings, clientId, { includeJsonContentType = false } = {}) {
  const headers = {};
  if (includeJsonContentType) {
    headers["Content-Type"] = "application/json";
  }
  if (settings.apiToken) {
    headers[API_TOKEN_HEADER_NAME] = settings.apiToken;
    headers["Authorization"] = `Bearer ${settings.apiToken}`;
  }
  if (normalizeStoredClientId(clientId)) {
    headers[CLIENT_ID_HEADER_NAME] = normalizeStoredClientId(clientId);
  }
  return headers;
}

function buildDashboardUrl(dashboardUrl, clientId) {
  const normalizedDashboardUrl = String(dashboardUrl || PROTECTED_PRODUCTION_CONFIG.dashboardUrl).trim();
  const normalizedClientId = normalizeStoredClientId(clientId);
  if (!normalizedClientId) {
    return normalizedDashboardUrl;
  }

  try {
    const url = new URL(normalizedDashboardUrl);
    url.searchParams.set("client_id", normalizedClientId);
    return url.toString();
  } catch (error) {
    const separator = normalizedDashboardUrl.includes("?") ? "&" : "?";
    return `${normalizedDashboardUrl}${separator}client_id=${encodeURIComponent(normalizedClientId)}`;
  }
}

function normalizeScanResult(payload, sourceUrl, context = {}) {
  const fileName = context.downloadedFilename || payload.file_name || sourceUrl || "Scanned PDF";
  return {
    ...payload,
    source_url: payload.source_url || sourceUrl,
    file_type: "pdf",
    file_name: fileName,
    verdictState: mapVerdictState(payload.final_label),
    final_confidence: Number(payload.final_confidence || 0),
    rule_score: Number(payload.rule_score || 0),
    ml_confidence: Number(payload.ml_confidence || 0)
  };
}

function normalizeRecentItem(item) {
  return {
    timestamp: item.timestamp || new Date().toISOString(),
    file_type: "pdf",
    file_name: item.file_name || item.source_url || "Scanned PDF",
    final_label: item.final_label || "unknown",
    final_confidence: Number(item.final_confidence || 0),
    rule_score: Number(item.rule_score || 0),
    recommendation: item.recommendation || "",
    review_status: item.review_status || "New",
    priority: item.priority || "Medium",
    disposition: item.disposition || "",
    source_url: item.source_url || "",
    verdictState: item.verdictState || mapVerdictState(item.final_label)
  };
}

function buildFailedResult(url, error, context = {}) {
  return {
    status: "error",
    timestamp: new Date().toISOString(),
    file_type: "pdf",
    file_name: context.downloadedFilename || url || "Scanned PDF",
    source_url: url,
    final_label: "failed",
    final_confidence: 0,
    rule_score: 0,
    recommendation: "The secure hosted PDF scanner could not complete the scan. Contact your administrator if this persists.",
    review_status: "New",
    priority: "Medium",
    disposition: "",
    message: error.message || String(error),
    verdictState: "failed"
  };
}

function buildUnavailableDownloadResult(downloadItem) {
  return {
    status: "error",
    timestamp: new Date().toISOString(),
    file_type: "pdf",
    file_name: downloadItem.filename || "Downloaded PDF",
    source_url: "",
    final_label: "failed",
    final_confidence: 0,
    rule_score: 0,
    recommendation: "Downloaded PDF detected, but the browser did not expose a reusable download URL for automatic scanning.",
    review_status: "New",
    priority: "Medium",
    disposition: "",
    message: "No reusable download URL was available for this PDF.",
    verdictState: "failed"
  };
}

function notificationTitle(result, fromDownload) {
  if (fromDownload) {
    if (result.verdictState === "malicious") {
      return "Alert: Downloaded PDF appears malicious";
    }
    if (result.verdictState === "suspicious") {
      return "Warning: Downloaded PDF appears suspicious";
    }
    if (result.verdictState === "safe") {
      return "Downloaded PDF scanned: Benign";
    }
    return "Downloaded PDF scan could not complete";
  }

  if (result.verdictState === "malicious") {
    return "Advanced PDFSafeScan: Malicious PDF Detected";
  }
  if (result.verdictState === "suspicious") {
    return "Advanced PDFSafeScan: Suspicious PDF Warning";
  }
  return "Advanced PDFSafeScan: Scan Failed";
}

function notificationMessage(result, fromDownload) {
  if (result.verdictState === "failed") {
    return result.message || "The hosted API server could not complete the scan.";
  }

  return `${result.file_name}\nVerdict: ${formatVerdictLabel(result.final_label)} | Confidence: ${result.final_confidence.toFixed(2)} | Rule score: ${result.rule_score.toFixed(2)}`;
}

function isLikelyPdfDownload(downloadItem) {
  const filename = String(downloadItem.filename || "").toLowerCase();
  const mime = String(downloadItem.mime || "").toLowerCase();
  const url = String(downloadItem.finalUrl || downloadItem.url || "").toLowerCase();

  return filename.endsWith(".pdf") || mime.includes("pdf") || isPdfUrl(url);
}

function getDownloadSourceUrl(downloadItem) {
  const candidateUrl = String(downloadItem.finalUrl || downloadItem.url || "").trim();
  if (!candidateUrl) {
    return "";
  }

  if (candidateUrl.startsWith("http://") || candidateUrl.startsWith("https://")) {
    return candidateUrl;
  }

  return "";
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

function isPdfUrl(url) {
  return /\.pdf(?:$|[?#])/i.test(String(url || ""));
}

function isScannableUrl(url) {
  return isPdfUrl(url);
}

function normalizeBaseUrl(url) {
  return String(url || PROTECTED_PRODUCTION_CONFIG.backendBaseUrl).replace(/\/$/, "");
}

async function openUrl(url) {
  await chrome.tabs.create({ url });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    ADMIN_OVERRIDE_ENABLED,
    API_TOKEN_HEADER_NAME,
    buildApiHeaders,
    buildDashboardUrl,
    buildEffectiveSettings,
    CLIENT_ID_HEADER_NAME,
    CLIENT_ID_STORAGE_KEY,
    generateClientId,
    getOrCreateClientId,
    getProtectedRuntimeConfig,
    initializeSettings,
    isLikelyPdfDownload,
    isPdfUrl,
    isScannableUrl,
    normalizeStoredClientId,
    PROTECTED_PRODUCTION_CONFIG,
    sanitizeUserPreferences,
    USER_PREFERENCE_DEFAULTS
  };
}
