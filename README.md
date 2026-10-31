## personal-ai-steward

Local-first personal steward for one Windows PC and one Android phone. This increment keeps the current Chrome page body only for an approved, focused, ordinary window, stores that raw text on the PC for seven days, and leaves the activity record in place after the text expires.

---

### Key Features

* Approve or revoke a site, and pause observation, from `Steward`.
* Ordinary unapproved pages keep a title and domain. Incognito windows keep unlabelled Chrome time.
* Raw bodies live under `bodies/` and are omitted from export, phone sync, and the default backup.

---

### Setup and Installation (PowerShell)

```powershell
python -m pip install pytest mypy
python -m pytest
python -m mypy
```

`tests/test_chrome_cdp.py` starts Google Chrome on a virtual display, so Chrome and Xvfb need to be installed. The other tests do not.

### Run the capture boundary

```powershell
python
```

```text
from datetime import datetime, timezone
from pathlib import Path
from steward.app import Steward
from steward.clock import ManualClock
```

→ `Steward` starts stopped. Call `start_observation` before any page is eligible.
→ `approve_site` accepts a hostname or an http(s) URL and stores only the hostname.
→ `read_body` returns the page text until seven days from capture, then returns no text.

### Project structure

```text
src/steward/
  app.py          # capture session, expiry, export, and backup exclusion
  policy.py       # hostname approval and what each page may retain
  chrome_cdp.py   # focused Chrome page read through the debugging port
  clock.py        # timestamps used for the seven-day deadline
  models.py       # focused-page input and body read result
tests/
  test_chrome_capture.py
  test_chrome_cdp.py
```
