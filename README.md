# UAPICodex
This repository contains automation scripts using Playwright.

## Setup
Install Node dependencies and Playwright browsers:
```bash
npm install
npx playwright install
```

## Running tests
Execute all tests with:
```bash
npm test
```

Environment variables `UAPI_URL`, `UAPI_USERNAME`, and `UAPI_PASSWORD` can override the defaults used in the tests. The default URL is `https://qc.uapi.sa/login`.

The suite covers login page behaviour, invalid credentials, successful login, and basic navigation after login. Installation or test execution may fail in environments where network access to the site or Playwright downloads is restricted.
