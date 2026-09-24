# Fit3 Flasher

Unofficial, static firmware installer for Samsung Galaxy Fit3 (SM-R390) on R390XXU0AZA3. Not affiliated with Samsung.

The page runs entirely in the browser. A firmware file selected by a visitor stays on that visitor's computer and is transferred directly to the watch through Web Serial; there is no upload endpoint or server-side code. The included stock AZA3 package is downloaded by the browser only when selected.

## Use

Open the GitHub Pages site in a current desktop Chrome or Edge browser over HTTPS. Pair the watch with the computer, connect on the page, select a firmware file, read and accept the warnings, and follow the separate transfer and installation steps.

Only packages passing the built-in AZA3 compatibility and integrity checks are accepted. These checks cannot guarantee that modified firmware will work. A failed flash may require recovery outside this tool. If other OTA packages may remain on the watch, do not start installation: the watch could choose a different package.

## Published files

`index.html`, `style.css`, `layout.css`, `app.js`, `validation-worker.js`, and `donate-qr.svg` are the static site. `firmware/stock-aza3.bin` is the 18,265,369-byte stock-component package. Its SHA-256 is `25e692badec82afe111c517c19c5dbdb1d28c8558c2b027143c43f5c8d05998a` and is pinned in the installer.

No server credentials or private keys are required or included.
