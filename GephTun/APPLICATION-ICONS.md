# GephTun application icons

This is the `application-icons-1` derivative of `identity-safeguards-verifier-repair-3`. It adds a tunnel-and-arrow badge using the existing navy, blue, and tray status colors. The earlier candidate, evidence, and handoffs remain in their original folders.

The main window, taskbar, and protection window use `assets/GephTun.ico`. The main UI sets the Windows application identity to `GephTun.Desktop`, so its window can have its own taskbar group. All five tray states use the same badge with their existing gray, blue, green, amber, or red status color. Status text and menu behavior are unchanged.

Each ICO contains 16, 20, 24, 32, 40, 48, 64, 96, 128, and 256 pixel images. Its 32-bit bitmap frames retain transparency and work with Windows PowerShell 5.1's .NET Framework. `GephTun.svg` is the editable design; `GephTun.png` is a 512 pixel preview. Run `python tools/build_icons.py` to regenerate them. Pillow is needed only to rebuild the assets, not to run GephTun.

Open the `GephTun.lnk` shortcut in the NewGEPHTUN project folder to launch this copy. It uses the custom icon and the existing launch script with the Show action. It does not automatically connect. Shortcuts contain absolute paths: after moving or extracting the app, run `Create-GephTunShortcut.ps1` to create a new shortcut beside the GephTun folder. That helper refuses to overwrite an existing file or put a shortcut inside the sealed package.

This application has no first-party executable or browser interface. The bundled tunnel executable and driver are pinned third-party dependencies; their bytes are unchanged. There is no favicon surface to update.

The package's qualification fields remain conservative. Windows icon-resource decoding and read-only PowerShell parsing are separate from running the application. The existing verifier script was blocked by Windows PowerShell's execution policy on this host; no policy override was used for validation. The full application, UAC flow, taskbar display, tray display, and network behavior were not exercised. See the receipts beside this source folder for the checks actually run.
