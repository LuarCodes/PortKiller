# PortKiller

See which program is using which network port, and kill it with one click.

## Features
- Lists every TCP/UDP port (IPv4 + IPv6) with the **process name and PID**
- **Filter** by port, process name or PID (e.g. type `3000`)
- "Listening only" toggle to hide normal connections
- **Kill** the selected process (Del key or right-click), with confirmation
- Click column headers to sort, F5 to refresh

> Run it **as administrator** to be able to kill system/service processes.

## Download
Grab `PortKiller.exe` from the [Releases](../../releases) page and run it. No install needed. Windows 10/11.

## Build from source
Double-click **`build.bat`**. It works with either:
- **MinGW-w64** (`winget install BrechtSanders.WinLibs.POSIX.UCRT`), or
- **Visual Studio** (run `build.bat` from the *Developer Command Prompt*).

Pure Win32 + C++17, no external dependencies.

## License
[MIT](LICENSE) © 2026 _.luarx
