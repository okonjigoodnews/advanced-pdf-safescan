# Privacy Policy — Advanced PDFSafeScan

**Last updated:** 19 July 2026

Advanced PDFSafeScan is a browser extension that checks PDF files for signs of malicious content. This policy explains what data the extension handles, why, and what happens to it.

The extension was developed as part of an MSc Cyber Security research project at De Montfort University.

---

## What the extension sends

To analyse a PDF, the extension sends the **web address (URL) of that PDF** to the Advanced PDFSafeScan service. The service retrieves the file at that address, inspects its structure, and returns a verdict.

A **randomly generated identifier** is sent alongside the request. This is created by the extension on first use, is not linked to any account, and exists only so that your own scan results can be grouped together and shown back to you.

**The extension does not send:** your name, your email address, your browsing history, the contents of pages you visit, cookies, form data, or any information that identifies you personally. No account is required and none is created.

## When scanning happens

A PDF is scanned in three situations:

1. **Automatically when you download a PDF.** This can be switched off in the extension's options.
2. **Automatically when a PDF opens in a browser tab.** This can also be switched off in the extension's options.
3. **On request**, when you right-click a PDF link or press Scan in the extension popup.

Pages that are not PDFs are ignored. The extension does not monitor, record, or transmit your general browsing.

## What is stored

The Advanced PDFSafeScan service records the following for each scan:

- the address of the scanned PDF and its file name
- a SHA-256 checksum of the file
- the verdict, confidence score, and which detection rules were triggered
- the time of the scan and the randomly generated identifier described above

This is stored so that results can be displayed in the dashboard and so that a file already scanned can return a cached result rather than being analysed twice.

The extension also stores data **locally in your browser**, using Chrome's storage:

- your preferences, such as whether automatic scanning is enabled
- your most recent scan results, so the popup can display them
- the randomly generated identifier

Local data stays on your device and is removed when you uninstall the extension.

## How long data is kept

The service runs on a free hosting tier where stored scan history is **not permanent**. It is cleared whenever the service is redeployed or restarts after a period of inactivity. There is no long-term archive of scan records.

## Who the data is shared with

Scan data is **not sold, rented, or shared with third parties**. It is not used for advertising, profiling, or tracking. It is used solely to produce and display the result of a scan.

The service is hosted on Render, which processes the data only as an infrastructure provider.

## Third-party PDF sources

When the service retrieves a PDF, that request goes to whichever website hosts the file. That website may see the request in its own logs, as it would for any other visitor. Advanced PDFSafeScan has no control over the privacy practices of third-party websites.

## Permissions and why they are needed

- **Downloads** — to detect when a PDF has finished downloading so it can be scanned.
- **Storage** — to save your preferences and recent results.
- **Notifications** — to warn you when a scan finds something suspicious or malicious.
- **Context menus** — to add the right-click "Scan PDF" option.
- **Active tab and site access** — to read the address of a page when it turns out to be a PDF. PDFs can be hosted on any website, which is why access is not limited to a fixed list of sites. Page content is not read or transmitted.

## Your choices

You can:

- turn off automatic scanning of downloads, automatic scanning of PDFs opened in tabs, or both, in the extension's options
- turn off notifications
- remove all locally stored data by uninstalling the extension

## Limitations

Advanced PDFSafeScan inspects a PDF's structure and reports what it finds. It is an aid to judgement, not a guarantee of safety, and should be used alongside normal security precautions.

## Contact

Questions about this policy or about data handling can be raised through the project's repository:

https://github.com/okonjigoodnews/advanced-pdf-safescan

## Changes to this policy

If the extension's data handling changes, this policy will be updated and the date at the top revised.
