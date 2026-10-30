// PortKiller - see which program uses which port, and kill it.
// (c) 2026 _.luarx - MIT License
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cwctype>

#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

enum { IDC_FILTER = 101, IDC_LISTEN, IDC_REFRESH, IDC_KILL, IDC_LIST, IDC_STATUS, IDC_LABEL };

struct Entry {
    std::wstring proto, localAddr, remote, state, process;
    DWORD port = 0, pid = 0;
};

static HWND gMain, gList, gFilter, gListen, gStatus, gLabel, gBtnRefresh, gBtnKill;
static HFONT gFont;
static int gDpi = 96;
static std::vector<Entry> gAll, gShown;
static int gSortCol = 1;
static bool gSortAsc = true;
static bool gAdmin = false;

static int S(int v) { return MulDiv(v, gDpi, 96); }

static bool IsElevated() {
    HANDLE tok = nullptr; TOKEN_ELEVATION e{}; DWORD n = 0; bool r = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &n)) r = e.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

static std::wstring Lower(std::wstring s) { for (auto& c : s) c = (wchar_t)towlower(c); return s; }

static const wchar_t* TcpState(DWORD s) {
    static const wchar_t* n[] = { L"?", L"CLOSED", L"LISTEN", L"SYN_SENT", L"SYN_RCVD", L"ESTABLISHED",
        L"FIN_WAIT1", L"FIN_WAIT2", L"CLOSE_WAIT", L"CLOSING", L"LAST_ACK", L"TIME_WAIT", L"DELETE_TCB" };
    return s < 13 ? n[s] : L"?";
}

static std::wstring Ip4(DWORD addr) {
    wchar_t b[64] = L""; IN_ADDR a; a.S_un.S_addr = addr;
    InetNtopW(AF_INET, &a, b, 64); return b;
}
static std::wstring Ip6(const UCHAR* addr) {
    wchar_t b[96] = L""; IN6_ADDR a; memcpy(&a, addr, 16);
    InetNtopW(AF_INET6, &a, b, 96); return std::wstring(L"[") + b + L"]";
}

static std::map<DWORD, std::wstring> ProcessNames() {
    std::map<DWORD, std::wstring> m;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return m;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) do { m[pe.th32ProcessID] = pe.szExeFile; } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    m[0] = L"System Idle Process";
    return m;
}

static std::vector<BYTE> TcpTable(ULONG af) {
    std::vector<BYTE> buf(1); DWORD size = 0;
    for (int tries = 0; tries < 5; ++tries) {
        DWORD r = GetExtendedTcpTable(buf.data(), &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if (r == NO_ERROR) return buf;
        if (r != ERROR_INSUFFICIENT_BUFFER) break;
        buf.resize(size + 4096); size = (DWORD)buf.size();
    }
    return {};
}
static std::vector<BYTE> UdpTable(ULONG af) {
    std::vector<BYTE> buf(1); DWORD size = 0;
    for (int tries = 0; tries < 5; ++tries) {
        DWORD r = GetExtendedUdpTable(buf.data(), &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
        if (r == NO_ERROR) return buf;
        if (r != ERROR_INSUFFICIENT_BUFFER) break;
        buf.resize(size + 4096); size = (DWORD)buf.size();
    }
    return {};
}

static void Collect() {
    gAll.clear();
    auto names = ProcessNames();
    auto pname = [&](DWORD pid) { auto it = names.find(pid); return it != names.end() ? it->second : std::wstring(L"?"); };

    auto t4 = TcpTable(AF_INET);
    if (!t4.empty()) {
        auto t = (PMIB_TCPTABLE_OWNER_PID)t4.data();
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            auto& r = t->table[i]; Entry e;
            e.proto = L"TCP"; e.port = ntohs((u_short)r.dwLocalPort); e.localAddr = Ip4(r.dwLocalAddr);
            e.remote = r.dwState == MIB_TCP_STATE_LISTEN ? L"" : Ip4(r.dwRemoteAddr) + L":" + std::to_wstring(ntohs((u_short)r.dwRemotePort));
            e.state = TcpState(r.dwState); e.pid = r.dwOwningPid; e.process = pname(e.pid);
            gAll.push_back(e);
        }
    }
    auto t6 = TcpTable(AF_INET6);
    if (!t6.empty()) {
        auto t = (PMIB_TCP6TABLE_OWNER_PID)t6.data();
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            auto& r = t->table[i]; Entry e;
            e.proto = L"TCPv6"; e.port = ntohs((u_short)r.dwLocalPort); e.localAddr = Ip6(r.ucLocalAddr);
            e.remote = r.dwState == MIB_TCP_STATE_LISTEN ? L"" : Ip6(r.ucRemoteAddr) + L":" + std::to_wstring(ntohs((u_short)r.dwRemotePort));
            e.state = TcpState(r.dwState); e.pid = r.dwOwningPid; e.process = pname(e.pid);
            gAll.push_back(e);
        }
    }
    auto u4 = UdpTable(AF_INET);
    if (!u4.empty()) {
        auto t = (PMIB_UDPTABLE_OWNER_PID)u4.data();
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            auto& r = t->table[i]; Entry e;
            e.proto = L"UDP"; e.port = ntohs((u_short)r.dwLocalPort); e.localAddr = Ip4(r.dwLocalAddr);
            e.state = L"(udp)"; e.pid = r.dwOwningPid; e.process = pname(e.pid);
            gAll.push_back(e);
        }
    }
    auto u6 = UdpTable(AF_INET6);
    if (!u6.empty()) {
        auto t = (PMIB_UDP6TABLE_OWNER_PID)u6.data();
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            auto& r = t->table[i]; Entry e;
            e.proto = L"UDPv6"; e.port = ntohs((u_short)r.dwLocalPort); e.localAddr = Ip6(r.ucLocalAddr);
            e.state = L"(udp)"; e.pid = r.dwOwningPid; e.process = pname(e.pid);
            gAll.push_back(e);
        }
    }
}

static int Cmp(const Entry& a, const Entry& b, int col) {
    switch (col) {
    case 0: return a.proto.compare(b.proto);
    case 1: return (a.port > b.port) - (a.port < b.port);
    case 2: return a.localAddr.compare(b.localAddr);
    case 3: return a.remote.compare(b.remote);
    case 4: return a.state.compare(b.state);
    case 5: return (a.pid > b.pid) - (a.pid < b.pid);
    default: return _wcsicmp(a.process.c_str(), b.process.c_str());
    }
}

static void Populate() {
    wchar_t fbuf[256]; GetWindowTextW(gFilter, fbuf, 256);
    std::wstring f = Lower(fbuf);
    bool listenOnly = SendMessageW(gListen, BM_GETCHECK, 0, 0) == BST_CHECKED;

    gShown.clear();
    for (auto& e : gAll) {
        if (listenOnly && e.state != L"LISTEN" && e.state != L"(udp)") continue;
        if (!f.empty()) {
            std::wstring hay = Lower(std::to_wstring(e.port) + L" " + e.process + L" " + std::to_wstring(e.pid) + L" " + e.proto + L" " + e.state + L" " + e.localAddr + L" " + e.remote);
            if (hay.find(f) == std::wstring::npos) continue;
        }
        gShown.push_back(e);
    }
    std::stable_sort(gShown.begin(), gShown.end(), [](const Entry& a, const Entry& b) {
        int c = Cmp(a, b, gSortCol); if (c == 0) c = Cmp(a, b, 1);
        return gSortAsc ? c < 0 : c > 0;
    });

    SendMessageW(gList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(gList);
    for (size_t i = 0; i < gShown.size(); ++i) {
        auto& e = gShown[i];
        std::wstring port = std::to_wstring(e.port), pid = std::to_wstring(e.pid);
        LVITEMW it{}; it.mask = LVIF_TEXT | LVIF_PARAM; it.iItem = (int)i; it.lParam = (LPARAM)i;
        it.pszText = (LPWSTR)e.proto.c_str();
        int row = (int)SendMessageW(gList, LVM_INSERTITEMW, 0, (LPARAM)&it);
        const std::wstring* cols[] = { &port, &e.localAddr, &e.remote, &e.state, &pid, &e.process };
        for (int c = 0; c < 6; ++c) {
            LVITEMW s{}; s.iSubItem = c + 1; s.pszText = (LPWSTR)cols[c]->c_str();
            SendMessageW(gList, LVM_SETITEMTEXTW, row, (LPARAM)&s);
        }
    }
    SendMessageW(gList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(gList, nullptr, TRUE);

    std::wstring st = L"  " + std::to_wstring(gShown.size()) + L" of " + std::to_wstring(gAll.size()) + L" connections";
    st += gAdmin ? L"   |   Running as admin" : L"   |   Not admin: some processes can't be killed (right-click > Run as administrator)";
    SendMessageW(gStatus, SB_SETTEXTW, 0, (LPARAM)st.c_str());
}

static void Refresh() { Collect(); Populate(); }

static void KillSelected() {
    std::map<DWORD, std::wstring> targets;
    int i = -1;
    while ((i = ListView_GetNextItem(gList, i, LVNI_SELECTED)) != -1) {
        LVITEMW it{}; it.mask = LVIF_PARAM; it.iItem = i;
        SendMessageW(gList, LVM_GETITEMW, 0, (LPARAM)&it);
        auto& e = gShown[(size_t)it.lParam];
        if (e.pid > 4) targets[e.pid] = e.process;
    }
    if (targets.empty()) { MessageBoxW(gMain, L"Select one or more rows first (system processes can't be killed).", L"PortKiller", MB_ICONINFORMATION); return; }

    std::wstring msg = L"Kill these processes?\n\n";
    for (auto& t : targets) msg += L"  " + t.second + L"  (PID " + std::to_wstring(t.first) + L")\n";
    msg += L"\nUnsaved work in them will be lost.";
    if (MessageBoxW(gMain, msg.c_str(), L"PortKiller", MB_YESNO | MB_ICONWARNING) != IDYES) return;

    std::wstring failed;
    for (auto& t : targets) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, t.first);
        bool ok = h && TerminateProcess(h, 1);
        DWORD err = GetLastError();
        if (h) CloseHandle(h);
        if (!ok) failed += L"  " + t.second + L" (PID " + std::to_wstring(t.first) + L")" + (err == ERROR_ACCESS_DENIED ? L" - access denied" : L"") + L"\n";
    }
    Sleep(300);
    Refresh();
    if (!failed.empty()) {
        std::wstring m = L"Could not kill:\n\n" + failed;
        if (!gAdmin) m += L"\nTry running PortKiller as administrator.";
        MessageBoxW(gMain, m.c_str(), L"PortKiller", MB_ICONERROR);
    }
}

static void Layout() {
    RECT rc; GetClientRect(gMain, &rc);
    SendMessageW(gStatus, WM_SIZE, 0, 0);
    RECT sr; GetWindowRect(gStatus, &sr); int sh = sr.bottom - sr.top;
    int m = S(8), h = S(26), x = m, y = m;
    MoveWindow(gLabel, x, y + S(5), S(40), S(18), TRUE); x += S(42);
    MoveWindow(gFilter, x, y, S(220), h, TRUE); x += S(230);
    MoveWindow(gListen, x, y, S(120), h, TRUE);
    MoveWindow(gBtnKill, rc.right - m - S(120), y, S(120), h, TRUE);
    MoveWindow(gBtnRefresh, rc.right - m - S(120) - S(8) - S(100), y, S(100), h, TRUE);
    int ly = y + h + m;
    MoveWindow(gList, m, ly, rc.right - 2 * m, rc.bottom - ly - sh - S(4), TRUE);
}

static HWND Ctl(const wchar_t* cls, const wchar_t* text, DWORD style, int id, DWORD ex = 0) {
    HWND h = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, gMain, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(h, WM_SETFONT, (WPARAM)gFont, TRUE);
    return h;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        gMain = hwnd;
        gLabel = Ctl(L"STATIC", L"Filter:", 0, IDC_LABEL);
        gFilter = Ctl(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, IDC_FILTER, WS_EX_CLIENTEDGE);
        SendMessageW(gFilter, EM_SETCUEBANNER, TRUE, (LPARAM)L"port, process or PID...");
        gListen = Ctl(L"BUTTON", L"Listening only", WS_TABSTOP | BS_AUTOCHECKBOX, IDC_LISTEN);
        SendMessageW(gListen, BM_SETCHECK, BST_CHECKED, 0);
        gBtnRefresh = Ctl(L"BUTTON", L"Refresh (F5)", WS_TABSTOP, IDC_REFRESH);
        gBtnKill = Ctl(L"BUTTON", L"Kill process (Del)", WS_TABSTOP, IDC_KILL);
        gList = Ctl(WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS, IDC_LIST, WS_EX_CLIENTEDGE);
        ListView_SetExtendedListViewStyle(gList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        const wchar_t* cols[] = { L"Proto", L"Port", L"Local address", L"Remote", L"State", L"PID", L"Process" };
        int widths[] = { 60, 70, 150, 200, 100, 70, 220 };
        for (int i = 0; i < 7; ++i) {
            LVCOLUMNW c{}; c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; c.pszText = (LPWSTR)cols[i]; c.cx = S(widths[i]);
            c.fmt = (i == 1 || i == 5) ? LVCFMT_RIGHT : LVCFMT_LEFT;
            SendMessageW(gList, LVM_INSERTCOLUMNW, i, (LPARAM)&c);
        }
        gStatus = CreateWindowExW(0, STATUSCLASSNAMEW, L"", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(gStatus, WM_SETFONT, (WPARAM)gFont, TRUE);
        Layout();
        Refresh();
        SetFocus(gFilter);
        return 0;
    }
    case WM_SIZE: Layout(); return 0;
    case WM_GETMINMAXINFO: ((MINMAXINFO*)lp)->ptMinTrackSize = { S(640), S(300) }; return 0;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_FILTER: if (HIWORD(wp) == EN_CHANGE) Populate(); break;
        case IDC_LISTEN: Populate(); break;
        case IDC_REFRESH: Refresh(); break;
        case IDC_KILL: KillSelected(); break;
        }
        return 0;
    case WM_NOTIFY: {
        auto nm = (LPNMHDR)lp;
        if (nm->idFrom == IDC_LIST && nm->code == LVN_COLUMNCLICK) {
            int col = ((LPNMLISTVIEW)lp)->iSubItem;
            if (col == gSortCol) gSortAsc = !gSortAsc; else { gSortCol = col; gSortAsc = true; }
            Populate();
        }
        if (nm->idFrom == IDC_LIST && nm->code == NM_RCLICK) {
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, IDC_KILL, L"Kill process");
            AppendMenuW(m, MF_STRING, IDC_REFRESH, L"Refresh");
            POINT p; GetCursorPos(&p);
            TrackPopupMenu(m, TPM_RIGHTBUTTON, p.x, p.y, 0, hwnd, nullptr);
            DestroyMenu(m);
        }
        return 0;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    gAdmin = IsElevated();
    HDC dc = GetDC(nullptr); gDpi = GetDeviceCaps(dc, LOGPIXELSY); ReleaseDC(nullptr, dc);
    gFont = CreateFontW(-MulDiv(9, gDpi, 72), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.lpszClassName = L"PortKillerWnd";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(101)); if (!wc.hIcon) wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    std::wstring title = gAdmin ? L"PortKiller (Administrator)" : L"PortKiller";
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, title.c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, S(900), S(560), nullptr, nullptr, hInst, nullptr);
    ShowWindow(hwnd, nShow);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0)) {
        if (m.message == WM_KEYDOWN && m.wParam == VK_F5) { Refresh(); continue; }
        if (m.message == WM_KEYDOWN && m.wParam == VK_DELETE && m.hwnd == gList) { KillSelected(); continue; }
        if (IsDialogMessageW(hwnd, &m)) continue;
        TranslateMessage(&m); DispatchMessageW(&m);
    }
    WSACleanup();
    return 0;
}
