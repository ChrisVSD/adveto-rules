# Vetoly Privacy Policy

Last updated: 2026-10-02

Vetoly is a browser content blocker published by ChrisVSD. Questions or privacy requests can be sent through the [project issue tracker](https://github.com/ChrisVSD/adveto-rules/issues).

## Data Vetoly handles

Vetoly stores protection preferences, cached filter rules, the last successful update time, and the page-counter reset time in Chrome local extension storage. This information stays on the device and is removed when the extension's local data is cleared or the extension is uninstalled. Vetoly does not create accounts, sell data, run analytics, or send browsing history, page contents, or blocked URLs to its developer.

When the user opens the popup, Vetoly uses Chrome's temporary `activeTab` access to count block-rule matches for the current tab from the last five minutes. The match records are processed locally to display a count; Vetoly does not read or store the page URL from this API, and the count is not sent to Vetoly. The Reset button starts a new local counting window.

The image classifier is off by default and requires an explicit opt-in in the extension popup. If enabled, it checks only large third-party images linked to a different site when they approach the viewport. The extension requests those images from their existing hosts without cookies and classifies them locally. Image bytes and classification results are not sent to Vetoly; temporary results are kept only in memory for the current page.

## Network requests and third parties

Vetoly periodically downloads public filter-rule JSON from GitHub. GitHub may process standard connection information, such as the request IP address and time, under its own privacy policy. When the optional image classifier is enabled, an image host receives the ordinary request needed to serve that image; Vetoly does not send that host the page URL or the classification result.

## User controls

Protection and the image classifier can be disabled in the popup. The blocked-request count can be reset there. Uninstalling Vetoly removes its local extension storage.

## Changes

This policy will be updated if Vetoly's data handling changes. The Chrome Web Store listing should link to this policy.
