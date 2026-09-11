# Contributing

Portal is intentionally narrow: local transport, progressive disclosure and native desktop concepts. Please discuss changes that add dependencies, background privileges, WAN exposure, arbitrary commands, persistent content or app-specific scraping before implementation.

```bash
git clone https://github.com/3EYE3Y3/omarchy-portal.git
cd omarchy-portal
./scripts/quality
```

Tests must cover security boundaries and failure paths, not only happy paths. Never include real tokens, Inbox files, clipboard data or URLs in fixtures/logs. Keep subprocess calls argument-based (`shell=False`), preserve optional-capability degradation, and validate QML against the installed Omarchy API.

Use conventional, focused commits. Security issues belong in private vulnerability reporting, not public issues.

