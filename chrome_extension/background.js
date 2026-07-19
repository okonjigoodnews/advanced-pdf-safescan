const PROTECTED_PRODUCTION_CONFIG = Object.freeze({
  backendBaseUrl: "https://advanced-pdf-safescan-api.onrender.com",
  dashboardUrl: "https://advanced-pdf-safescan-dashboard.onrender.com",
  apiToken: ""
});

const USER_PREFERENCE_DEFAULTS = Object.freeze({
  autoScanDownloads: true,
  autoScanOpenedPdfs: true,
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

// Toolbar badge. The badge gives the verdict at a glance without the user
// opening the popup, which matters most for downloads scanned automatically
// in the background.
const BADGE_STYLES = Object.freeze({
  safe: { text: "OK", color: "#16A34A" },
  benign: { text: "OK", color: "#16A34A" },
  suspicious: { text: "!", color: "#D97706" },
  malicious: { text: "!", color: "#DC2626" },
  failed: { text: "?", color: "#64748B" },
  scanning: { text: "...", color: "#2563EB" }
});

// A hosted API on a free tier can sleep and take up to a minute to wake, so a
// single short request is not enough. The first attempt usually wakes it and
// the retry succeeds.
const SCAN_REQUEST_TIMEOUT_MS = 45000;
const SCAN_RETRY_ATTEMPTS = 2;
const SCAN_RETRY_DELAY_MS = 2000;
const KEEP_ALIVE_INTERVAL_MS = 20000;
const OPENED_PDF_RESCAN_WINDOW_MS = 60000;
const API_TOKEN_HEADER_NAME = "X-API-Token";
const CLIENT_ID_HEADER_NAME = "X-Client-ID";
const CLIENT_ID_STORAGE_KEY = "advanced_pdfsafescan_client_id";
// Chrome's notification API only accepts raster images. An inline SVG data
// URI silently fails with "Unable to download all specified images", so the
// packaged PNG icon is used instead.
function getNotificationIconUrl() {
  if (hasChromeApis && chrome.runtime?.getURL) {
    try {
      return chrome.runtime.getURL("icon128.png");
    } catch (error) {
      return "icon128.png";
    }
  }
  return "icon128.png";
}

const hasChromeApis =
  typeof chrome !== "undefined" &&
  chrome.runtime &&
  chrome.storage &&
  chrome.storage.local;

if (hasChromeApis && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener(async () => {
    await initializeSettings();
    await ensureContextMenus();
    await restoreBadgeFromStoredResult();
  });
}

if (hasChromeApis && chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(async () => {
    await initializeSettings();
    await ensureContextMenus();
    await restoreBadgeFromStoredResult();
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

// A PDF opened directly in the browser never becomes a download, so the
// downloads listener alone would miss it. Watching tab navigation covers the
// far more common case of clicking a PDF link and having Chrome render it
// in its built-in viewer.
if (hasChromeApis && chrome.tabs && chrome.tabs.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete") {
      return;
    }
    handleOpenedPdfTab(tab?.url || "");
  });
}

// Remembers URLs scanned in this worker session so that a reload, or Chrome
// firing the event more than once, does not trigger repeat scans.
const recentlyScannedTabUrls = new Map();

async function handleOpenedPdfTab(url) {
  const settings = await getSettings();
  if (!settings.autoScanOpenedPdfs) {
    return;
  }

  const candidateUrl = String(url || "").trim();
  if (!candidateUrl.startsWith("http://") && !candidateUrl.startsWith("https://")) {
    return;
  }
  if (!isPdfUrl(candidateUrl)) {
    return;
  }

  const now = Date.now();
  const lastScannedAt = recentlyScannedTabUrls.get(candidateUrl);
  if (lastScannedAt && now - lastScannedAt < OPENED_PDF_RESCAN_WINDOW_MS) {
    return;
  }
  recentlyScannedTabUrls.set(candidateUrl, now);

  // Keep the map small; it only exists to suppress duplicates.
  if (recentlyScannedTabUrls.size > 40) {
    const oldestKey = recentlyScannedTabUrls.keys().next().value;
    recentlyScannedTabUrls.delete(oldestKey);
  }

  await scanPdfUrl(candidateUrl, { trigger: "pdf-opened-in-tab" });
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
    autoScanOpenedPdfs:
      storedSettings.autoScanOpenedPdfs ?? USER_PREFERENCE_DEFAULTS.autoScanOpenedPdfs,
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
    console.log("[PDFSafeScan] auto-scan is switched off in settings");
    return;
  }

  const [downloadItem] = await chrome.downloads.search({ id: downloadId });
  if (!downloadItem) {
    return;
  }
  if (!isLikelyPdfDownload(downloadItem)) {
    return;
  }

  const sourceUrl = getDownloadSourceUrl(downloadItem);
  if (!sourceUrl) {
    console.log("[PDFSafeScan] no usable http(s) URL for this download");
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

  showScanningBadge();

  // Manifest V3 shuts the service worker down after roughly 30 seconds of
  // inactivity. A hosted API that has gone to sleep can take longer than that
  // to wake, so a plain fetch dies with the worker and the scan disappears
  // without success or failure. A keepalive holds the worker open while the
  // request is in flight, and the request itself is bounded and retried.
  const keepAlive = startServiceWorkerKeepAlive();

  try {
    const payload = await requestUrlScanWithRetry(settings, clientId, url);
    const normalizedResult = normalizeScanResult(payload, url, context);
    await rememberScanResult(normalizedResult);
    await maybeNotify(normalizedResult, settings, context);
    return normalizedResult;
  } catch (error) {
    console.warn("[PDFSafeScan] scan failed:", error.message || error, "url:", url);
    const failedResult = buildFailedResult(url, error, context);
    await rememberScanResult(failedResult);
    await maybeNotify(failedResult, settings, context);
    return failedResult;
  } finally {
    stopServiceWorkerKeepAlive(keepAlive);
  }
}

async function requestUrlScanWithRetry(settings, clientId, url) {
  let lastError = null;

  for (let attempt = 1; attempt <= SCAN_RETRY_ATTEMPTS; attempt += 1) {
    try {
      const response = await fetchWithTimeout(
        normalizeBaseUrl(settings.backendBaseUrl) + "/api/scan/url",
        {
          method: "POST",
          headers: buildApiHeaders(settings, clientId, { includeJsonContentType: true }),
          body: JSON.stringify({ url })
        },
        SCAN_REQUEST_TIMEOUT_MS
      );

      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.status === "error") {
        throw new Error(payload.message || "Hosted API request failed.");
      }
      return payload;
    } catch (error) {
      lastError = error;
      if (attempt < SCAN_RETRY_ATTEMPTS) {
        console.log(
          `[PDFSafeScan] attempt ${attempt} did not complete (${error.message || error}). ` +
          "The scanner may be waking up. Retrying."
        );
        await delay(SCAN_RETRY_DELAY_MS);
      }
    }
  }

  throw lastError || new Error("Hosted API request failed.");
}

async function fetchWithTimeout(resource, options, timeoutMs) {
  if (typeof AbortController === "undefined") {
    return fetch(resource, options);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(resource, { ...options, signal: controller.signal });
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(`The scanner did not respond within ${Math.round(timeoutMs / 1000)} seconds.`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function startServiceWorkerKeepAlive() {
  if (!hasChromeApis || !chrome.runtime?.getPlatformInfo) {
    return null;
  }
  // A periodic trivial API call resets the worker's idle timer.
  return setInterval(() => {
    try {
      chrome.runtime.getPlatformInfo(() => void chrome.runtime.lastError);
    } catch (error) {
      // ignore
    }
  }, KEEP_ALIVE_INTERVAL_MS);
}

function stopServiceWorkerKeepAlive(handle) {
  if (handle !== null && handle !== undefined) {
    clearInterval(handle);
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

  updateBadgeForVerdict(result.verdictState);
}

function updateBadgeForVerdict(verdictState) {
  if (!hasChromeApis || !chrome.action) {
    return;
  }

  const style = BADGE_STYLES[String(verdictState || "").toLowerCase()] || BADGE_STYLES.failed;

  try {
    chrome.action.setBadgeText({ text: style.text });
    if (chrome.action.setBadgeBackgroundColor) {
      chrome.action.setBadgeBackgroundColor({ color: style.color });
    }
    if (chrome.action.setBadgeTextColor) {
      chrome.action.setBadgeTextColor({ color: "#FFFFFF" });
    }
  } catch (error) {
    // A badge is cosmetic. Never let it break a scan.
  }
}

function showScanningBadge() {
  updateBadgeForVerdict("scanning");
}

function clearBadge() {
  if (!hasChromeApis || !chrome.action || !chrome.action.setBadgeText) {
    return;
  }
  try {
    chrome.action.setBadgeText({ text: "" });
  } catch (error) {
    // ignore
  }
}

async function restoreBadgeFromStoredResult() {
  if (!hasChromeApis || !chrome.storage?.local) {
    return;
  }
  try {
    const localState = await chrome.storage.local.get(DEFAULT_LOCAL_STATE);
    if (localState.latestScanResult?.verdictState) {
      updateBadgeForVerdict(localState.latestScanResult.verdictState);
    } else {
      clearBadge();
    }
  } catch (error) {
    // ignore
  }
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
    iconUrl: getNotificationIconUrl(),
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
