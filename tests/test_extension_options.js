const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const optionsHtmlPath = path.join(__dirname, "..", "chrome_extension", "options.html");
const optionsHtml = fs.readFileSync(optionsHtmlPath, "utf8");

assert.equal(optionsHtml.includes('id="backendBaseUrl"'), false);
assert.equal(optionsHtml.includes('id="dashboardUrl"'), false);
assert.equal(optionsHtml.includes('id="apiToken"'), false);

assert.equal(optionsHtml.includes('id="autoScanDownloads"'), true);
assert.equal(optionsHtml.includes('id="enableNotifications"'), true);
assert.equal(optionsHtml.includes('id="warnOnSuspicious"'), true);
assert.equal(optionsHtml.includes('id="autoOpenDashboardForMalicious"'), true);
