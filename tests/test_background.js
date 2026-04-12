const assert = require("node:assert/strict");

const syncState = {
  backendBaseUrl: "https://evil.example.com",
  dashboardUrl: "https://evil-dashboard.example.com",
  apiToken: "user-supplied-token",
  autoScanDownloads: false,
  enableNotifications: true,
  warnOnSuspicious: false,
  autoOpenDashboardForMalicious: true
};
const localState = {};

global.crypto = {
  randomUUID() {
    return "client-test-id";
  }
};

global.chrome = {
  storage: {
    sync: {
      async get(defaults) {
        return { ...defaults, ...syncState };
      },
      async set(values) {
        Object.assign(syncState, values);
      },
      async remove(keys) {
        for (const key of keys) {
          delete syncState[key];
        }
      }
    },
    local: {
      async get(keyOrDefaults) {
        if (typeof keyOrDefaults === "string") {
          return { [keyOrDefaults]: localState[keyOrDefaults] };
        }
        return { ...keyOrDefaults, ...localState };
      },
      async set(values) {
        Object.assign(localState, values);
      }
    }
  },
  runtime: {
    onInstalled: { addListener() {} },
    onStartup: { addListener() {} },
    onMessage: { addListener() {} }
  },
  contextMenus: {
    onClicked: { addListener() {} },
    async removeAll() {},
    create() {}
  },
  downloads: {
    onChanged: { addListener() {} },
    async search() {
      return [];
    }
  },
  notifications: {
    create() {}
  },
  tabs: {
    async create() {},
    async query() {
      return [];
    }
  }
};

const {
  ADMIN_OVERRIDE_ENABLED,
  API_TOKEN_HEADER_NAME,
  buildApiHeaders,
  buildDashboardUrl,
  buildEffectiveSettings,
  CLIENT_ID_HEADER_NAME,
  CLIENT_ID_STORAGE_KEY,
  getOrCreateClientId,
  getProtectedRuntimeConfig,
  initializeSettings,
  isLikelyPdfDownload,
  isPdfUrl,
  isScannableUrl,
  PROTECTED_PRODUCTION_CONFIG,
  sanitizeUserPreferences,
  USER_PREFERENCE_DEFAULTS
} = require("../chrome_extension/background.js");

async function run() {
  const firstClientId = await getOrCreateClientId();
  const secondClientId = await getOrCreateClientId();

  assert.equal(firstClientId, "client-test-id");
  assert.equal(secondClientId, "client-test-id");
  assert.equal(localState[CLIENT_ID_STORAGE_KEY], "client-test-id");

  assert.equal(ADMIN_OVERRIDE_ENABLED, false);
  assert.deepEqual(getProtectedRuntimeConfig(), PROTECTED_PRODUCTION_CONFIG);

  await initializeSettings();
  assert.equal("backendBaseUrl" in syncState, false);
  assert.equal("dashboardUrl" in syncState, false);
  assert.equal("apiToken" in syncState, false);

  assert.deepEqual(
    sanitizeUserPreferences({
      autoScanDownloads: false,
      enableNotifications: false,
      warnOnSuspicious: true,
      autoOpenDashboardForMalicious: true,
      backendBaseUrl: "https://evil.example.com",
      apiToken: "should-not-be-kept"
    }),
    {
      autoScanDownloads: false,
      enableNotifications: false,
      warnOnSuspicious: true,
      autoOpenDashboardForMalicious: true
    }
  );

  const effectiveSettings = buildEffectiveSettings(syncState);
  assert.equal(effectiveSettings.backendBaseUrl, PROTECTED_PRODUCTION_CONFIG.backendBaseUrl);
  assert.equal(effectiveSettings.dashboardUrl, PROTECTED_PRODUCTION_CONFIG.dashboardUrl);
  assert.equal(effectiveSettings.apiToken, PROTECTED_PRODUCTION_CONFIG.apiToken);
  assert.equal(effectiveSettings.autoScanDownloads, false);
  assert.equal(effectiveSettings.enableNotifications, true);
  assert.equal(effectiveSettings.warnOnSuspicious, false);
  assert.equal(effectiveSettings.autoOpenDashboardForMalicious, true);

  const headers = buildApiHeaders(
    { ...PROTECTED_PRODUCTION_CONFIG, apiToken: "secure-token" },
    "client-test-id",
    { includeJsonContentType: true }
  );
  assert.equal(headers["Content-Type"], "application/json");
  assert.equal(headers[API_TOKEN_HEADER_NAME], "secure-token");
  assert.equal(headers["Authorization"], "Bearer secure-token");
  assert.equal(headers[CLIENT_ID_HEADER_NAME], "client-test-id");

  assert.equal(
    buildDashboardUrl("https://dashboard.example.com", "client-test-id"),
    "https://dashboard.example.com/?client_id=client-test-id"
  );

  assert.equal(isPdfUrl("https://example.com/sample.pdf"), true);
  assert.equal(isScannableUrl("https://example.com/sample.pdf"), true);
  assert.equal(isScannableUrl("https://example.com/phish.png"), false);
  assert.equal(
    isLikelyPdfDownload({ filename: "report.pdf", mime: "application/pdf", url: "" }),
    true
  );
  assert.equal(
    isLikelyPdfDownload({ filename: "capture.jpg", mime: "image/jpeg", url: "" }),
    false
  );

  assert.deepEqual(USER_PREFERENCE_DEFAULTS, {
    autoScanDownloads: true,
    enableNotifications: true,
    warnOnSuspicious: true,
    autoOpenDashboardForMalicious: false
  });
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
