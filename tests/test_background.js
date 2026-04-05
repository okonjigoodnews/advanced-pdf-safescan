const assert = require("node:assert/strict");

const storageState = {};

Object.defineProperty(globalThis, "crypto", {
  value: {
    randomUUID() {
      return "client-test-id";
    }
  },
  configurable: true
});

global.chrome = {
  storage: {
    sync: {
      async get(defaults) {
        return defaults;
      },
      async set() {}
    },
    local: {
      async get(keyOrDefaults) {
        if (typeof keyOrDefaults === "string") {
          return { [keyOrDefaults]: storageState[keyOrDefaults] };
        }
        return { ...keyOrDefaults, ...storageState };
      },
      async set(values) {
        Object.assign(storageState, values);
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
  buildApiHeaders,
  buildDashboardUrl,
  CLIENT_ID_HEADER_NAME,
  CLIENT_ID_STORAGE_KEY,
  getOrCreateClientId
} = require("../chrome_extension/background.js");

async function run() {
  const firstClientId = await getOrCreateClientId();
  const secondClientId = await getOrCreateClientId();

  assert.equal(firstClientId, "client-test-id");
  assert.equal(secondClientId, "client-test-id");
  assert.equal(storageState[CLIENT_ID_STORAGE_KEY], "client-test-id");

  const headers = buildApiHeaders(
    { apiToken: "secret-token" },
    "client-test-id",
    { includeJsonContentType: true }
  );
  assert.equal(headers["Content-Type"], "application/json");
  assert.equal(headers["X-API-Token"], "secret-token");
  assert.equal(headers["Authorization"], "Bearer secret-token");
  assert.equal(headers[CLIENT_ID_HEADER_NAME], "client-test-id");

  assert.equal(
    buildDashboardUrl("https://dashboard.example.com", "client-test-id"),
    "https://dashboard.example.com/?client_id=client-test-id"
  );
  assert.equal(
    buildDashboardUrl("https://dashboard.example.com/view?tab=history", "client-test-id"),
    "https://dashboard.example.com/view?tab=history&client_id=client-test-id"
  );
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
