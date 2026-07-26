# The published unclecode/crawl4ai:latest ships without the Playwright browser binary, so it
# crash-loops on boot ("Executable doesn't exist… run playwright install"). This thin layer installs
# the headless-shell + chromium into appuser's cache where the server expects them.
FROM unclecode/crawl4ai:latest
RUN playwright install chromium-headless-shell chromium
