//go:build windows

package cli

// F7 — real Windows system tray, hand-rolled on Win32 with no GUI
// toolkit dependency. Pieces:
//
//   - A hidden top-level window (RegisterClassExW + CreateWindowExW,
//     never shown) owns the tray icon and receives its messages.
//   - The icon itself is Shell_NotifyIconW (shell32) with
//     NOTIFYICON_VERSION_4 semantics: the callback message is
//     wmTrayCallback (WM_USER+1), lParam carries the mouse event,
//     wParam the icon id.
//   - Right-click shows a TrackPopupMenu menu (created fresh each
//     time so Start/Stop can be grayed from live pid-file state);
//     the user's pick comes back as WM_COMMAND with the item id in
//     LOWORD(wParam) and is dispatched in the window procedure.
//   - Double-click opens the dashboard. "TaskbarCreated" is handled
//     so the icon is re-added when Explorer restarts.
//   - GetMessageW/TranslateMessage/DispatchMessageW drive the loop
//     on an OS-thread-locked goroutine (window messages are delivered
//     to the thread that created the window).
//   - Quit (and any exit path) removes the icon with NIM_DELETE and
//     destroys the window/icon handles.
//
// Start/Stop/Open deliberately reuse the CLI's existing pid-file
// machinery (cmdStart/cmdStop/cmdOpen in server.go) instead of a
// second process model, exactly like the JS tray menu did.
//
// Icon: v1 generates a 32×32 ICO in code — a stdlib-PNG-encoded
// flat indigo rounded square with a white dot — written to a temp
// file and loaded with LoadImageW(LR_LOADFROMFILE). Replace
// trayIconICO with real artwork later without touching the tray
// plumbing.
//
// CAVEAT: this file is compile- and vet-verified only. It has never
// run on a real Windows desktop (no GUI available in the build
// environment), so the shell interactions follow the documented
// Win32 contracts but are not live-verified.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── Win32 entry points (lazy, resolved on first use) ──────────────

var (
	trayUser32   = windows.NewLazySystemDLL("user32.dll")
	trayShell32  = windows.NewLazySystemDLL("shell32.dll")
	trayKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procTrayRegisterClassExW    = trayUser32.NewProc("RegisterClassExW")
	procTrayCreateWindowExW     = trayUser32.NewProc("CreateWindowExW")
	procTrayDefWindowProcW      = trayUser32.NewProc("DefWindowProcW")
	procTrayGetMessageW         = trayUser32.NewProc("GetMessageW")
	procTrayTranslateMessage    = trayUser32.NewProc("TranslateMessage")
	procTrayDispatchMessageW    = trayUser32.NewProc("DispatchMessageW")
	procTrayDestroyWindow       = trayUser32.NewProc("DestroyWindow")
	procTrayPostQuitMessage     = trayUser32.NewProc("PostQuitMessage")
	procTrayPostMessageW        = trayUser32.NewProc("PostMessageW")
	procTrayCreatePopupMenu     = trayUser32.NewProc("CreatePopupMenu")
	procTrayAppendMenuW         = trayUser32.NewProc("AppendMenuW")
	procTrayDestroyMenu         = trayUser32.NewProc("DestroyMenu")
	procTrayTrackPopupMenu      = trayUser32.NewProc("TrackPopupMenu")
	procTrayGetCursorPos        = trayUser32.NewProc("GetCursorPos")
	procTraySetForegroundWindow = trayUser32.NewProc("SetForegroundWindow")
	procTrayLoadImageW          = trayUser32.NewProc("LoadImageW")
	procTrayDestroyIcon         = trayUser32.NewProc("DestroyIcon")
	procTrayRegisterWindowMsgW  = trayUser32.NewProc("RegisterWindowMessageW")
	procTrayShellNotifyIconW    = trayShell32.NewProc("Shell_NotifyIconW")
	procTrayGetModuleHandleW    = trayKernel32.NewProc("GetModuleHandleW")
)

// ─── Win32 constants ───────────────────────────────────────────────

const (
	wmNull           = 0x0000
	wmDestroy        = 0x0002
	wmCommand        = 0x0111
	wmUser           = 0x0400
	wmLButtonDblClk  = 0x0203
	wmRButtonUp      = 0x0205
	wmContextMenu    = 0x007B
	wmTrayCallback   = wmUser + 1 // NOTIFYICONDATA.uCallbackMessage
	nimAdd           = 0x0000
	nimModify        = 0x0001
	nimDelete        = 0x0002
	nimSetVersion    = 0x0004
	nifMessage       = 0x0001
	nifIcon          = 0x0002
	nifTip           = 0x0004
	notifyIconVer4   = 4 // NOTIFYICON_VERSION_4
	mfString         = 0x0000
	mfDisabled       = 0x0002
	mfGrayed         = 0x0001
	mfSeparator      = 0x0800
	tpmLeftAlign     = 0x0000
	tpmBottomAlign   = 0x0020
	tpmRightButton   = 0x0002
	imageIcon        = 1 // IMAGE_ICON for LoadImageW
	lrLoadFromFile   = 0x0010
	lrDefaultSize    = 0x0040
	trayWindowClass  = "ProxyGoTrayWindow"
	trayMenuOpenID   = 1001
	trayMenuStartID  = 1002
	trayMenuStopID   = 1003
	trayMenuQuitID   = 1004
	trayIconUID      = 1
	menuDebounceTime = 400 * time.Millisecond
)

// ─── Win32 structs (layouts mirror the C headers on amd64/arm64) ───

// wndClassEx mirrors WNDCLASSEXW (winuser.h).
type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

// trayPoint mirrors POINT (windef.h).
type trayPoint struct {
	x, y int32
}

// trayMsg mirrors MSG (winuser.h).
type trayMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      trayPoint
	priv    uint32 // lPrivate
}

// notifyIconData mirrors NOTIFYICONDATAW (shellapi.h, Vista+ form).
type notifyIconData struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32 // union: uTimeout / uVersion
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte // GUID
	hBalloonIcon     uintptr
}

// ─── Tray application state ────────────────────────────────────────

// trayApp is the single tray instance. All Win32 members are touched
// only from the message-loop thread (the locked goroutine running
// runTray and, through DispatchMessageW, trayWndProc); the
// start/stop goroutines confine themselves to the pid-file machinery
// and the atomic busy flag.
type trayApp struct {
	opts   options
	stdout io.Writer
	stderr io.Writer

	hwnd           uintptr // hidden owner window
	hicon          uintptr // HICON loaded from the generated ICO
	taskbarCreated uint32  // registered "TaskbarCreated" message id, 0 if none

	busy     int32 // atomic: a Start/Stop is in flight
	lastMenu time.Time
}

// tray is the live instance the window procedure dispatches to
// (a window proc is a plain C callback — it cannot capture state).
var tray *trayApp

// trayWndProcPtr keeps the Go callback reachable for the lifetime of
// the process (syscall.NewCallback requires the func value to stay
// alive while Windows may call it).
var trayWndProcPtr = syscall.NewCallback(trayWndProc)

// runTray is the Windows implementation of the `tray` command and
// the -t/--tray flag: start the server detached (same as the JS tray
// flow), then show the tray icon and pump messages until Quit.
func runTray(opts options, stdout, stderr io.Writer) int {
	// Window messages are delivered to the thread that created the
	// window; pin this goroutine so the loop, the window and the
	// callback all stay on one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fmt.Fprintln(stdout, "🔔 Tray mode: starting the server in the background; a ProxyGo icon appears in the system tray.")
	fmt.Fprintln(stdout, "   Right-click the tray icon for Open Dashboard / Start Server / Stop Server / Quit.")

	// JS tray mode does not pop a browser; the menu's Open Dashboard
	// (or a double-click) is the way in.
	opts.NoBrowser = true
	startCode := cmdStart(opts, stdout, stderr)

	t := &trayApp{opts: opts, stdout: stdout, stderr: stderr}
	tray = t
	defer func() { tray = nil }()

	if err := t.setup(); err != nil {
		fmt.Fprintf(stderr, "Tray icon unavailable: %v\n", err)
		fmt.Fprintln(stderr, "The server was left as-is; manage it with `proxygo-cli status`, `proxygo-cli open` and `proxygo-cli stop`.")
		if startCode != 0 {
			return startCode
		}
		return 1
	}
	defer t.teardown()

	t.messageLoop()
	return 0
}

// setup registers the window class, creates the hidden owner window,
// loads the icon and adds it to the notification area.
func (t *trayApp) setup() error {
	className, err := windows.UTF16PtrFromString(trayWindowClass)
	if err != nil {
		return err
	}
	hInstance, _, _ := procTrayGetModuleHandleW.Call(0)

	wc := wndClassEx{
		lpfnWndProc:   trayWndProcPtr,
		hInstance:     hInstance,
		lpszClassName: className,
	}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	// A zero ATOM means failure, but ERROR_CLASS_ALREADY_EXISTS on a
	// repeat registration is harmless — CreateWindowExW below is the
	// real success check.
	_, _, _ = procTrayRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	title, err := windows.UTF16PtrFromString("ProxyGo")
	if err != nil {
		return err
	}
	hwnd, _, callErr := procTrayCreateWindowExW.Call(
		0, // dwExStyle
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		0,          // dwStyle: no WS_VISIBLE — the window is never shown
		0, 0, 0, 0, // x, y, w, h (irrelevant for a hidden window)
		0, 0, hInstance, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW: %v", callErr)
	}
	t.hwnd = hwnd

	hicon, err := loadTrayIcon()
	if err != nil {
		return err
	}
	t.hicon = hicon

	if !t.notify(nimAdd) {
		return fmt.Errorf("Shell_NotifyIconW(NIM_ADD) failed")
	}
	// Opt into modern callback semantics; failure is non-fatal (the
	// legacy layout delivers the same events for our purposes).
	t.notify(nimSetVersion)

	// Explorer restart notification: re-add the icon when the
	// taskbar is recreated.
	if name, err := windows.UTF16PtrFromString("TaskbarCreated"); err == nil {
		id, _, _ := procTrayRegisterWindowMsgW.Call(uintptr(unsafe.Pointer(name)))
		t.taskbarCreated = uint32(id)
	}
	return nil
}

// teardown removes the tray icon and releases the window/icon.
func (t *trayApp) teardown() {
	if t.hwnd != 0 {
		t.notify(nimDelete) // harmless if Quit already removed it
	}
	if t.hicon != 0 {
		procTrayDestroyIcon.Call(t.hicon)
		t.hicon = 0
	}
	if t.hwnd != 0 {
		procTrayDestroyWindow.Call(t.hwnd)
		t.hwnd = 0
	}
}

// messageLoop is the classic GetMessageW pump; it returns when
// WM_QUIT arrives (posted from WM_DESTROY on Quit).
func (t *trayApp) messageLoop() {
	var m trayMsg
	for {
		ret, _, _ := procTrayGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if ret == 0 || ret == ^uintptr(0) { // WM_QUIT or -1 error
			return
		}
		procTrayTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procTrayDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// notify issues one Shell_NotifyIconW operation with a NOTIFYICONDATA
// shaped for that operation.
func (t *trayApp) notify(action uintptr) bool {
	var nid notifyIconData
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = t.hwnd
	nid.uID = trayIconUID
	switch action {
	case nimAdd:
		nid.uFlags = nifMessage | nifIcon | nifTip
		nid.uCallbackMessage = wmTrayCallback
		nid.hIcon = t.hicon
		copyUTF16(nid.szTip[:], t.tipText())
	case nimModify:
		nid.uFlags = nifIcon | nifTip
		nid.hIcon = t.hicon
		copyUTF16(nid.szTip[:], t.tipText())
	case nimSetVersion:
		nid.uVersion = notifyIconVer4
	case nimDelete:
		// cbSize/hWnd/uID are all the shell needs.
	}
	r, _, _ := procTrayShellNotifyIconW.Call(action, uintptr(unsafe.Pointer(&nid)))
	return r != 0
}

// tipText is the icon tooltip, refreshed from live pid-file state.
func (t *trayApp) tipText() string {
	if st, ok := readPidState(); ok && processAlive(st.PID) {
		return fmt.Sprintf("ProxyGo — running on port %d", st.Port)
	}
	return "ProxyGo — stopped"
}

func copyUTF16(dst []uint16, s string) {
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return
	}
	if len(u) > len(dst) {
		u = u[:len(dst)]
	}
	copy(dst, u)
}

// ─── Window procedure ──────────────────────────────────────────────

// trayWndProc dispatches tray callbacks and menu commands; everything
// else falls through to DefWindowProcW.
func trayWndProc(hwnd, message, wParam, lParam uintptr) uintptr {
	t := tray
	if t == nil {
		r, _, _ := procTrayDefWindowProcW.Call(hwnd, message, wParam, lParam)
		return r
	}
	switch message {
	case wmTrayCallback:
		// NOTIFYICON_VERSION_4 semantics: lParam carries the mouse
		// or keyboard event, wParam the icon id.
		switch lParam {
		case wmLButtonDblClk:
			t.doOpen()
		case wmRButtonUp, wmContextMenu:
			t.showMenu()
		}
		return 0
	case wmCommand:
		// Menu picks arrive here with the item id in LOWORD(wParam).
		switch wParam & 0xFFFF {
		case trayMenuOpenID:
			t.doOpen()
		case trayMenuStartID:
			t.doStart()
		case trayMenuStopID:
			t.doStop()
		case trayMenuQuitID:
			t.doQuit()
		}
		return 0
	case wmDestroy:
		procTrayPostQuitMessage.Call(0)
		return 0
	default:
		if t.taskbarCreated != 0 && message == uintptr(t.taskbarCreated) {
			// Explorer restarted and rebuilt the notification
			// area: put the icon back.
			t.notify(nimAdd)
			t.notify(nimSetVersion)
			return 0
		}
	}
	r, _, _ := procTrayDefWindowProcW.Call(hwnd, message, wParam, lParam)
	return r
}

// ─── Menu + actions ────────────────────────────────────────────────

// showMenu builds a fresh popup (so Start/Stop graying reflects the
// live server state), tracks it at the cursor, and destroys it. The
// chosen item is delivered back to trayWndProc as WM_COMMAND.
func (t *trayApp) showMenu() {
	// A single right-click can surface as both WM_RBUTTONUP and
	// WM_CONTEXTMENU depending on shell version; collapse bursts.
	if time.Since(t.lastMenu) < menuDebounceTime {
		return
	}
	t.lastMenu = time.Now()

	t.notify(nimModify) // refresh tooltip with live state

	menu, _, _ := procTrayCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procTrayDestroyMenu.Call(menu)

	running := serverRunning()
	appendItem(menu, trayMenuOpenID, "Open Dashboard", false)
	appendItem(menu, trayMenuStartID, "Start Server", running)
	appendItem(menu, trayMenuStopID, "Stop Server", !running)
	procTrayAppendMenuW.Call(menu, mfSeparator, 0, 0)
	appendItem(menu, trayMenuQuitID, "Quit", false)

	var pt trayPoint
	procTrayGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// SetForegroundWindow + a posted WM_NULL afterwards are the
	// documented workaround so the menu also dismisses correctly
	// when the user clicks outside it.
	procTraySetForegroundWindow.Call(t.hwnd)
	procTrayTrackPopupMenu.Call(menu,
		tpmLeftAlign|tpmBottomAlign|tpmRightButton,
		uintptr(int64(pt.x)), uintptr(int64(pt.y)),
		0, t.hwnd, 0)
	procTrayPostMessageW.Call(t.hwnd, wmNull, 0, 0)
}

func appendItem(menu, id uintptr, text string, disabled bool) {
	flags := uintptr(mfString)
	if disabled {
		flags |= mfDisabled | mfGrayed
	}
	p, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	procTrayAppendMenuW.Call(menu, flags, id, uintptr(unsafe.Pointer(p)))
}

// serverRunning reports whether the CLI-started server is alive,
// from the pid file — the same source cmdStatus uses.
func serverRunning() bool {
	st, ok := readPidState()
	return ok && processAlive(st.PID)
}

// doOpen is the Open Dashboard action (menu + double-click): cmdOpen
// already prefers the pid-file port/host and falls back to printing
// the URL when no browser can be launched.
func (t *trayApp) doOpen() {
	_ = cmdOpen(t.opts, t.stdout, t.stderr)
}

// doStart runs cmdStart off the message thread: it can block for a
// few seconds waiting for the server to become ready, and the menu
// must stay responsive meanwhile.
func (t *trayApp) doStart() {
	if !atomic.CompareAndSwapInt32(&t.busy, 0, 1) {
		return
	}
	go func() {
		defer atomic.StoreInt32(&t.busy, 0)
		_ = cmdStart(t.opts, t.stdout, t.stderr)
	}()
}

// doStop runs cmdStop off the message thread (it waits for process
// exit before returning).
func (t *trayApp) doStop() {
	if !atomic.CompareAndSwapInt32(&t.busy, 0, 1) {
		return
	}
	go func() {
		defer atomic.StoreInt32(&t.busy, 0)
		_ = cmdStop(t.stdout, t.stderr)
	}()
}

// doQuit removes the icon and destroys the owner window; the
// resulting WM_DESTROY posts WM_QUIT, ending the message loop.
// Teardown in runTray repeats both removals defensively (both are
// harmless no-ops the second time).
func (t *trayApp) doQuit() {
	t.notify(nimDelete)
	procTrayDestroyWindow.Call(t.hwnd)
}

// ─── Icon ──────────────────────────────────────────────────────────

// loadTrayIcon materialises trayIconICO to a temp file and loads it
// with LoadImageW(LR_LOADFROMFILE|LR_DEFAULTSIZE). The file is
// removed right after the load: LoadImageW has fully read it by
// then and the returned HICON is independent of it.
func loadTrayIcon() (uintptr, error) {
	f, err := os.CreateTemp("", "proxygo-tray-*.ico")
	if err != nil {
		return 0, err
	}
	path := f.Name()
	if _, err := f.Write(trayIconICO()); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return 0, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return 0, err
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		_ = os.Remove(path)
		return 0, err
	}
	h, _, callErr := procTrayLoadImageW.Call(
		0, uintptr(unsafe.Pointer(pathPtr)),
		imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize,
	)
	_ = os.Remove(path)
	if h == 0 {
		return 0, fmt.Errorf("LoadImageW: %v", callErr)
	}
	return h, nil
}

// trayIconICO builds the v1 icon: a 32×32 PNG (flat indigo rounded
// square, white center dot) wrapped in an ICO container
// (ICONDIR + one ICONDIRENTRY + PNG payload, the Vista+ form).
func trayIconICO() []byte {
	const size = 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	bg := color.RGBA{0x4F, 0x46, 0xE5, 0xFF} // indigo-600
	fg := color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			px, py := float64(x)+0.5, float64(y)+0.5
			if inRoundedRect(px, py, 1, 1, size-2, size-2, 8) {
				img.Set(x, y, bg)
			}
			dx, dy := px-size/2, py-size/2
			if dx*dx+dy*dy <= 25 { // radius-5 white dot
				img.Set(x, y, fg)
			}
		}
	}
	var pngBuf bytes.Buffer
	_ = png.Encode(&pngBuf, img)
	pngBytes := pngBuf.Bytes()

	var ico bytes.Buffer
	// ICONDIR: reserved=0, type=1 (icon), count=1.
	_ = binary.Write(&ico, binary.LittleEndian, []uint16{0, 1, 1})
	// ICONDIRENTRY: 32×32, no palette, 1 plane, 32bpp, payload
	// follows the 6-byte header + 16-byte entry.
	ico.WriteByte(size)
	ico.WriteByte(size)
	ico.WriteByte(0)
	ico.WriteByte(0)
	_ = binary.Write(&ico, binary.LittleEndian, []uint16{1, 32})
	_ = binary.Write(&ico, binary.LittleEndian, uint32(len(pngBytes)))
	_ = binary.Write(&ico, binary.LittleEndian, uint32(6+16))
	ico.Write(pngBytes)
	return ico.Bytes()
}

// inRoundedRect reports whether point (px,py) lies inside the
// rounded rectangle at (x,y) with size w×h and corner radius r.
func inRoundedRect(px, py, x, y, w, h, r float64) bool {
	if px < x || px >= x+w || py < y || py >= y+h {
		return false
	}
	cx := math.Max(x+r, math.Min(px, x+w-r))
	cy := math.Max(y+r, math.Min(py, y+h-r))
	dx, dy := px-cx, py-cy
	return dx*dx+dy*dy <= r*r
}
