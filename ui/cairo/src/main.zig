// Sinty Recovery - Cairo UI.
//
// KMS-direct like singularity-boot-splash: owns a DRM CRTC and renders with Cairo
// through the shared C-ABI loginui. Syscalls go through @cImport of the C
// headers (a hosted libc binary), not std.posix.
// RECOVERY_PNG=1 renders each screen to a file for hardware-less review.
const std = @import("std");
const api = @import("api.zig");
const c = @cImport({
    @cUndef("_FORTIFY_SOURCE");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("stdlib.h");
    @cInclude("sys/mman.h");
    @cInclude("poll.h");
    @cInclude("cairo/cairo.h");
    @cInclude("xf86drm.h");
    @cInclude("xf86drmMode.h");
    @cInclude("linux/input.h");
    @cInclude("loginui.h");
});

var W: c_int = 1600;
var H: c_int = 900;

const bg = [3]f64{ 0.05, 0.06, 0.09 };
const fg = [3]f64{ 0.92, 0.94, 0.98 };
const dim = [3]f64{ 0.55, 0.58, 0.66 };
const acc = [3]f64{ 0.30, 0.55, 0.95 };
const warn = [3]f64{ 0.90, 0.35, 0.30 };

fn fw() f64 {
    return @floatFromInt(W);
}
fn fh() f64 {
    return @floatFromInt(H);
}
fn fill(cr: ?*c.cairo_t, x: f64, y: f64, w: f64, h: f64, col: [3]f64, a: f64) void {
    c.loginui_rounded_rect(cr, x, y, w, h, 10);
    c.cairo_set_source_rgba(cr, col[0], col[1], col[2], a);
    c.cairo_fill(cr);
}
fn text(cr: ?*c.cairo_t, font: [*:0]const u8, s: [*:0]const u8, x: f64, y: f64, al: c_int, col: [3]f64) void {
    c.loginui_text(cr, font, s, x, y, al, col[0], col[1], col[2]);
}
// loginui_text takes the TOP of the text, so a box needs its height measured to centre in it.
fn textMid(cr: ?*c.cairo_t, font: [*:0]const u8, s: [*:0]const u8, x: f64, box_y: f64, box_h: f64, al: c_int, col: [3]f64) void {
    var tw: c_int = 0;
    var th: c_int = 0;
    c.loginui_text_size(cr, font, s, &tw, &th);
    text(cr, font, s, x, box_y + (box_h - @as(f64, @floatFromInt(th))) / 2, al, col);
}
fn textAbove(cr: ?*c.cairo_t, font: [*:0]const u8, s: [*:0]const u8, x: f64, bottom: f64, al: c_int, col: [3]f64) void {
    var tw: c_int = 0;
    var th: c_int = 0;
    c.loginui_text_size(cr, font, s, &tw, &th);
    text(cr, font, s, x, bottom - @as(f64, @floatFromInt(th)), al, col);
}
fn cstr(b: []const u8) [*:0]const u8 {
    return @ptrCast(b.ptr);
}
fn setz(dst: []u8, src: []const u8) void {
    const n = @min(dst.len - 1, src.len);
    @memcpy(dst[0..n], src[0..n]);
    dst[n] = 0;
}

// ── state ──

const Screen = enum { menu, wifi, password, progress, unlock_warn, unlock_pin, unlock_confirm, unlock_blocked, sdb_pair };
var screen: Screen = .menu;

const menu_items = [_][*:0]const u8{ "Reinstall Sinty", "Repair", "Unlock bootloader" };
var menu_sel: usize = 0;

var nets: [64]api.Network = undefined;
var net_n: usize = 0;
var net_sel: usize = 0;

var psk: [128]u8 = std.mem.zeroes([128]u8);
var psk_len: usize = 0;
var sel_ssid: [64]u8 = std.mem.zeroes([64]u8);

const unlock_word = "UNLOCK";
var unlock_txt: [32]u8 = std.mem.zeroes([32]u8);
var unlock_len: usize = 0;
var unlock_pin: [257]u8 = std.mem.zeroes([257]u8);
var unlock_pin_len: usize = 0;
var lock: api.LockState = .{};
var lock_read = false;
var block_reason: [160]u8 = std.mem.zeroes([160]u8);

var pair: api.PairingState = .{};
var pair_read = false;
var pair_note: [160]u8 = std.mem.zeroes([160]u8);

fn pairShowsCode() bool {
    return pair_read and pair.active and !pair.locked() and pair.code[0] != 0;
}

fn unlockMatches() bool {
    return std.mem.eql(u8, std.mem.sliceTo(&unlock_txt, 0), unlock_word);
}

const osk_rows = [_][]const u8{ "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm" };
var osk_r: usize = 0;
var osk_c: usize = 0;
var osk_shift = false;

var status: api.Status = .{};
var toast: [160]u8 = std.mem.zeroes([160]u8);

fn header(cr: ?*c.cairo_t, title: [*:0]const u8) void {
    c.cairo_set_source_rgb(cr, bg[0], bg[1], bg[2]);
    c.cairo_paint(cr);
    text(cr, "bold 34", "Sinty Recovery", fw() / 2, 84, 1, fg);
    text(cr, "20", title, fw() / 2, 150, 1, dim);
    if (status.current[0] != 0) text(cr, "14", cstr(&status.current), fw() / 2, fh() - 26, 1, dim);
    if (toast[0] != 0) text(cr, "16", cstr(&toast), fw() / 2, fh() - 54, 1, acc);
}

fn drawMenu(cr: ?*c.cairo_t) void {
    header(cr, if (status.online) "Connected. Choose an action." else "Not connected. Reinstall needs wifi.");
    const bw: f64 = 520;
    const bh: f64 = 64;
    const x = (fw() - bw) / 2;
    var y = fh() / 2 - 120;
    var i: usize = 0;
    while (i < menu_items.len) : (i += 1) {
        const on = i == menu_sel;
        fill(cr, x, y, bw, bh, if (on) acc else fg, if (on) 0.22 else 0.06);
        if (on) {
            c.loginui_rounded_rect(cr, x, y, bw, bh, 10);
            c.cairo_set_source_rgba(cr, acc[0], acc[1], acc[2], 0.9);
            c.cairo_set_line_width(cr, 2);
            c.cairo_stroke(cr);
        }
        textMid(cr, "22", menu_items[i], x + 28, y, bh, 0, fg);
        y += bh + 18;
    }
    const lock_line: [*:0]const u8 = if (!lock_read)
        "Bootloader state unavailable."
    else if (lock.locked)
        "Bootloader: locked. Verified boot is on."
    else
        "Bootloader: unlocked. Verified boot is off.";
    text(cr, "16", lock_line, fw() / 2, y + 16, 1, if (lock_read and !lock.locked) warn else dim);
}

fn drawWifi(cr: ?*c.cairo_t) void {
    header(cr, if (net_n > 0) "Pick a network." else "Scanning for networks...");
    const bw: f64 = 560;
    const rh: f64 = 46;
    const x = (fw() - bw) / 2;
    var y: f64 = 210;
    var i: usize = 0;
    while (i < net_n and i < 9) : (i += 1) {
        const on = i == net_sel;
        fill(cr, x, y, bw, rh, if (on) acc else fg, if (on) 0.22 else 0.05);
        textMid(cr, "19", cstr(&nets[i].ssid), x + 22, y, rh, 0, fg);
        var meta: [32]u8 = undefined;
        const m = std.fmt.bufPrintZ(&meta, "{s} {d}", .{ if (nets[i].secure) "lock" else "open", nets[i].signal }) catch "";
        textMid(cr, "14", m.ptr, x + bw - 22, y, rh, 2, dim);
        y += rh + 8;
    }
    text(cr, "14", "Enter select   Esc back", fw() / 2, fh() - 88, 1, dim);
}

fn drawEntry(cr: ?*c.cairo_t, shown: [*:0]const u8, field_y: f64, hint: [*:0]const u8) void {
    const fwd: f64 = 520;
    const x = (fw() - fwd) / 2;
    const fh_field: f64 = 52;
    fill(cr, x, field_y, fwd, fh_field, fg, 0.08);
    textMid(cr, "22", shown, x + 20, field_y, fh_field, 0, fg);

    var ky: f64 = field_y + 90;
    const kh: f64 = 52;
    const kw: f64 = 52;
    const gap: f64 = 8;
    for (osk_rows, 0..) |row, r| {
        const len: f64 = @floatFromInt(row.len);
        const roww = len * (kw + gap) - gap;
        var kx = (fw() - roww) / 2;
        for (row, 0..) |ch, cc| {
            const on = r == osk_r and cc == osk_c;
            fill(cr, kx, ky, kw, kh, if (on) acc else fg, if (on) 0.30 else 0.07);
            var s = [2]u8{ ch, 0 };
            if (osk_shift and ch >= 'a' and ch <= 'z') s[0] = ch - 32;
            textMid(cr, "22", @ptrCast(&s), kx + kw / 2, ky, kh, 1, fg);
            kx += kw + gap;
        }
        ky += kh + gap;
    }
    text(cr, "14", hint, fw() / 2, fh() - 92, 1, dim);
}

fn drawPassword(cr: ?*c.cairo_t) void {
    var t: [128]u8 = undefined;
    const title = std.fmt.bufPrintZ(&t, "Password for {s}", .{std.mem.sliceTo(&sel_ssid, 0)}) catch "Password";
    header(cr, title.ptr);
    var mask: [130]u8 = undefined;
    var k: usize = 0;
    while (k < psk_len and k < 128) : (k += 1) mask[k] = '*';
    mask[k] = 0;
    drawEntry(cr, @ptrCast(&mask), 210, "arrows move   Enter type   Tab shift   F2 connect   Backspace del   Esc back");
}

fn drawUnlockWarn(cr: ?*c.cairo_t) void {
    header(cr, "Unlock bootloader");
    const bw: f64 = 900;
    const x = (fw() - bw) / 2;
    const y: f64 = 210;
    fill(cr, x, y, bw, 300, warn, 0.12);
    text(cr, "bold 24", "Unlocking the bootloader erases all user data.", x + 36, y + 34, 0, warn);
    const lines = [_][*:0]const u8{
        "Every account, file and setting on this device is deleted and cannot be recovered.",
        "Verified boot is disabled. The system will no longer check that its software is genuine.",
        "This device will show an unlocked-state warning at every boot from now on.",
        "Locking the bootloader again also erases all user data.",
    };
    var ly = y + 92;
    for (lines) |ln| {
        text(cr, "19", ln, x + 36, ly, 0, fg);
        ly += 42;
    }
    text(cr, "16", "Esc cancels and returns to the menu. Enter continues to the confirmation step.", fw() / 2, y + 350, 1, dim);
}

fn drawUnlockBlocked(cr: ?*c.cairo_t) void {
    header(cr, "Unlock bootloader");
    const bw: f64 = 900;
    const x = (fw() - bw) / 2;
    const y: f64 = 210;
    fill(cr, x, y, bw, 260, warn, 0.12);
    text(cr, "bold 24", "This device does not allow unlocking.", x + 36, y + 34, 0, warn);
    const lines = [_][*:0]const u8{
        "Unlocking must first be allowed by the owner, from the running system.",
        "Open Settings, go to System, and turn on \"Allow bootloader unlock\".",
        "Recovery cannot grant this by itself. A lost or seized device stays protected.",
    };
    var ly = y + 92;
    for (lines) |ln| {
        text(cr, "19", ln, x + 36, ly, 0, fg);
        ly += 42;
    }
    if (block_reason[0] != 0) text(cr, "16", cstr(&block_reason), x + 36, ly + 6, 0, dim);
    text(cr, "16", "Esc returns to the menu.", fw() / 2, y + 310, 1, dim);
}

fn drawUnlockConfirm(cr: ?*c.cairo_t) void {
    header(cr, "Type UNLOCK to confirm");
    var shown: [34]u8 = undefined;
    setz(&shown, std.mem.sliceTo(&unlock_txt, 0));
    const ok = unlockMatches();
    drawEntry(cr, @ptrCast(&shown), 200, "arrows move   Enter type   Tab shift   Backspace del   Esc back");
    const msg: [*:0]const u8 = if (ok)
        "Press F2 to unlock the bootloader and erase this device."
    else
        "Type the word UNLOCK exactly. Nothing happens until it matches.";
    text(cr, "18", msg, fw() / 2, fh() - 130, 1, if (ok) warn else dim);
}

fn drawUnlockPIN(cr: ?*c.cairo_t) void {
    header(cr, "Confirm ownership");
    var mask: [258]u8 = undefined;
    var i: usize = 0;
    while (i < unlock_pin_len and i + 1 < mask.len) : (i += 1) mask[i] = '*';
    mask[i] = 0;
    drawEntry(cr, @ptrCast(&mask), 200, "Enter PIN   F2 continue   Backspace del   Esc cancel");
    text(cr, "16", "The PIN is checked again before any data is erased.", fw() / 2, fh() - 130, 1, dim);
}

fn drawSdbPair(cr: ?*c.cairo_t) void {
    header(cr, "Debug bridge");
    const bw: f64 = 1060;
    const x = (fw() - bw) / 2;
    const y: f64 = 210;

    if (!pair_read) {
        fill(cr, x, y, bw, 240, warn, 0.12);
        text(cr, "bold 24", "The pairing state could not be read.", x + 36, y + 34, 0, warn);
        const lines = [_][*:0]const u8{
            "No pairing code is shown and no machine can pair with this device right now.",
            "Recovery refuses rather than display a code it cannot vouch for.",
        };
        var ly = y + 92;
        for (lines) |ln| {
            text(cr, "19", ln, x + 36, ly, 0, fg);
            ly += 42;
        }
        if (pair_note[0] != 0) text(cr, "16", cstr(&pair_note), x + 36, ly + 6, 0, dim);
        text(cr, "16", "Esc returns to the menu.", fw() / 2, y + 290, 1, dim);
        return;
    }

    if (pair.locked()) {
        fill(cr, x, y, bw, 240, warn, 0.12);
        text(cr, "bold 24", "Pairing is locked after too many wrong attempts.", x + 36, y + 34, 0, warn);
        var lb: [96]u8 = undefined;
        const ls = std.fmt.bufPrintZ(&lb, "No code is shown for another {d} s.", .{pair.locked_for}) catch "";
        const lines = [_][*:0]const u8{
            ls.ptr,
            "A code shown now would only be refused, so none is shown.",
            "Esc and start again once the wait is over.",
        };
        var ly = y + 92;
        for (lines) |ln| {
            text(cr, "19", ln, x + 36, ly, 0, fg);
            ly += 42;
        }
        text(cr, "16", "Esc returns to the menu.", fw() / 2, y + 290, 1, dim);
        return;
    }

    if (!pairShowsCode()) {
        fill(cr, x, y, bw, 240, fg, 0.06);
        text(cr, "bold 24", "No pairing code is open.", x + 36, y + 34, 0, fg);
        const lines = [_][*:0]const u8{
            "The code has expired, or the session was closed. Nothing is on offer right now.",
            "A code lives for a couple of minutes only, and is never shown once it is spent.",
            "Pairing in recovery lasts for this session only and is never remembered.",
        };
        var ly = y + 92;
        for (lines) |ln| {
            text(cr, "19", ln, x + 36, ly, 0, dim);
            ly += 42;
        }
        text(cr, "16", "Esc returns to the menu. Open the debug bridge again for a new code.", fw() / 2, y + 290, 1, dim);
        return;
    }

    fill(cr, x, y, bw, 150, acc, 0.14);
    text(cr, "18", "On the development machine, run the pairing command and type this code there.", x + 36, y + 24, 0, dim);
    textMid(cr, "bold 64", cstr(&pair.code), fw() / 2, y + 46, 96, 1, fg);

    var meta: [96]u8 = undefined;
    const ms = std.fmt.bufPrintZ(&meta, "Expires in {d} s   Wrong attempts so far {d}", .{ pair.expires_in, pair.attempts }) catch "";
    text(cr, "18", ms.ptr, fw() / 2, y + 168, 1, if (pair.expires_in <= 20) warn else dim);

    const fy = y + 210;
    fill(cr, x, fy, bw, 118, fg, 0.06);
    if (pair.hasRequest()) {
        text(cr, "16", "Key fingerprint of the machine asking. Check it matches the one it shows.", x + 36, fy + 20, 0, dim);
        text(cr, "20", cstr(&pair.fingerprint), x + 36, fy + 54, 0, fg);
        if (pair.label[0] != 0) text(cr, "16", cstr(&pair.label), x + 36, fy + 88, 0, dim);
    } else {
        text(cr, "16", "No machine has presented a key yet.", x + 36, fy + 20, 0, dim);
        text(cr, "19", "Its fingerprint appears here as soon as one does. Check it before typing the code.", x + 36, fy + 54, 0, dim);
    }

    text(cr, "bold 19", "Anyone who can read this code can connect to this device.", fw() / 2, fy + 152, 1, warn);
    text(cr, "16", "Esc cancels pairing and returns to the menu. Cancelling is safe and grants nothing.", fw() / 2, fy + 188, 1, dim);
}

fn drawProgress(cr: ?*c.cairo_t) void {
    header(cr, "Working");
    const bw: f64 = 560;
    const x = (fw() - bw) / 2;
    const y = fh() / 2;
    const msg = if (status.message[0] != 0) cstr(&status.message) else "Please wait...";
    textAbove(cr, "22", msg, fw() / 2, y - 14, 1, fg);
    fill(cr, x, y, bw, 20, fg, 0.10);
    const pct: i32 = if (status.progress < 0) 0 else status.progress;
    const p: f64 = @floatFromInt(pct);
    c.loginui_rounded_rect(cr, x, y, bw * p / 100.0, 20, 10);
    c.cairo_set_source_rgb(cr, acc[0], acc[1], acc[2]);
    c.cairo_fill(cr);
    var pb: [16]u8 = undefined;
    const ps = std.fmt.bufPrintZ(&pb, "{d}%", .{pct}) catch "";
    text(cr, "16", ps.ptr, fw() / 2, y + 50, 1, dim);
    if (status.state == .done) text(cr, "18", "Done. Reboot to finish.  (F12 to reboot)", fw() / 2, y + 90, 1, acc);
    if (status.state == .failed) text(cr, "18", "Failed.  Esc to go back.", fw() / 2, y + 90, 1, warn);
}

fn render(cr: ?*c.cairo_t) void {
    switch (screen) {
        .menu => drawMenu(cr),
        .wifi => drawWifi(cr),
        .password => drawPassword(cr),
        .progress => drawProgress(cr),
        .unlock_warn => drawUnlockWarn(cr),
        .unlock_pin => drawUnlockPIN(cr),
        .unlock_confirm => drawUnlockConfirm(cr),
        .unlock_blocked => drawUnlockBlocked(cr),
        .sdb_pair => drawSdbPair(cr),
    }
}

// ── input (evdev via @cImport C) ──

const Ev = enum { none, up, down, left, right, enter, back, char, del, connectk, shift, quit };
var in_fds: [16]c_int = undefined;
var in_n: usize = 0;
var shift_held = false;
var ev_char: u8 = 0;

fn inputOpen() void {
    var idx: usize = 0;
    while (idx < 32 and in_n < in_fds.len) : (idx += 1) {
        var pbuf: [64]u8 = undefined;
        const p = std.fmt.bufPrintZ(&pbuf, "/dev/input/event{d}", .{idx}) catch continue;
        const fd = c.open(p.ptr, c.O_RDONLY | c.O_NONBLOCK | c.O_CLOEXEC);
        if (fd < 0) continue;
        in_fds[in_n] = fd;
        in_n += 1;
    }
}

fn keyChar(code: c_int, shift: bool) u8 {
    const lo = "\x00\x00" ++ "1234567890-=" ++ "\x00\x00" ++ "qwertyuiop[]" ++ "\x00\x00" ++ "asdfghjkl;'`" ++ "\x00\\" ++ "zxcvbnm,./";
    const up = "\x00\x00" ++ "!@#$%^&*()_+" ++ "\x00\x00" ++ "QWERTYUIOP{}" ++ "\x00\x00" ++ "ASDFGHJKL:\"~" ++ "\x00|" ++ "ZXCVBNM<>?";
    if (code == c.KEY_SPACE) return ' ';
    if (code >= c.KEY_1 and code <= c.KEY_SLASH) {
        const idx: usize = @intCast(code - c.KEY_1 + 2);
        const m = if (shift) up else lo;
        if (idx < m.len) return m[idx];
    }
    return 0;
}

fn inputPoll(timeout_ms: c_int) Ev {
    var pfds: [16]c.struct_pollfd = undefined;
    var i: usize = 0;
    while (i < in_n) : (i += 1) pfds[i] = .{ .fd = in_fds[i], .events = c.POLLIN, .revents = 0 };
    if (c.poll(&pfds, @intCast(in_n), timeout_ms) <= 0) return .none;
    i = 0;
    while (i < in_n) : (i += 1) {
        if (pfds[i].revents & c.POLLIN == 0) continue;
        var ie: c.struct_input_event = undefined;
        while (c.read(in_fds[i], &ie, @sizeOf(c.struct_input_event)) == @sizeOf(c.struct_input_event)) {
            if (ie.type != c.EV_KEY) continue;
            const code: c_int = ie.code;
            if (code == c.KEY_LEFTSHIFT or code == c.KEY_RIGHTSHIFT) {
                shift_held = ie.value != 0;
                continue;
            }
            if (ie.value != 1 and ie.value != 2) continue;
            switch (code) {
                c.KEY_UP => return .up,
                c.KEY_DOWN => return .down,
                c.KEY_LEFT => return .left,
                c.KEY_RIGHT => return .right,
                c.KEY_ENTER, c.KEY_KPENTER => return .enter,
                c.KEY_ESC => return .back,
                c.KEY_BACKSPACE => return .del,
                c.KEY_F2 => return .connectk,
                c.KEY_TAB => return .shift,
                c.KEY_F12 => return .quit,
                else => {
                    const ch = keyChar(code, shift_held);
                    if (ch != 0) {
                        ev_char = ch;
                        return .char;
                    }
                },
            }
        }
    }
    return .none;
}

// ── flow ──

fn goWifi() void {
    screen = .wifi;
    net_n = api.scan(&nets);
    net_sel = 0;
    toast[0] = 0;
}
fn pairRefresh() void {
    pair_read = api.getPairingState(&pair);
    if (!pair_read) {
        pair = .{};
        if (pair_note[0] == 0) setz(&pair_note, "The pairing state could not be read, so no code is shown.");
    } else pair_note[0] = 0;
}

fn goPairing() void {
    toast[0] = 0;
    pair_note[0] = 0;
    pair = .{};
    screen = .sdb_pair;
    pairRefresh();
    if (pair_read and !pair.locked() and !pair.active) {
        if (api.pairingStart()) pairRefresh() else {
            pair_read = false;
            pair = .{};
            setz(&pair_note, "The debug bridge did not accept a pairing session, so no code is shown.");
        }
    }
}

const Entry = struct { buf: []u8, len: *usize };

fn entry() Entry {
    return if (screen == .unlock_confirm)
        .{ .buf = &unlock_txt, .len = &unlock_len }
    else if (screen == .unlock_pin)
        .{ .buf = &unlock_pin, .len = &unlock_pin_len }
    else
        .{ .buf = &psk, .len = &psk_len };
}
fn entryPut(ch: u8) void {
    const e = entry();
    if (e.len.* < e.buf.len - 1) {
        e.buf[e.len.*] = ch;
        e.len.* += 1;
        e.buf[e.len.*] = 0;
    }
}
fn entryDel() void {
    const e = entry();
    if (e.len.* > 0) {
        e.len.* -= 1;
        e.buf[e.len.*] = 0;
    }
}
fn oskType() void {
    var ch = osk_rows[osk_r][osk_c];
    if (osk_shift and ch >= 'a' and ch <= 'z') ch -= 32;
    entryPut(ch);
}
fn oskMove(e: Ev) void {
    if (e == .up) osk_r = (osk_r + 3) % 4;
    if (e == .down) osk_r = (osk_r + 1) % 4;
    if (e == .left) osk_c = (osk_c + osk_rows[osk_r].len - 1) % osk_rows[osk_r].len;
    if (e == .right) osk_c = (osk_c + 1) % osk_rows[osk_r].len;
    if (osk_c >= osk_rows[osk_r].len) osk_c = osk_rows[osk_r].len - 1;
    if (e == .enter) oskType();
    if (e == .shift) osk_shift = !osk_shift;
    if (e == .del) entryDel();
    if (e == .char) entryPut(ev_char);
}

fn handle(e: Ev) void {
    switch (screen) {
        .menu => {
            if (e == .up) menu_sel = (menu_sel + menu_items.len - 1) % menu_items.len;
            if (e == .down) menu_sel = (menu_sel + 1) % menu_items.len;
            if (e == .enter) {
                if (menu_sel == 0) {
                    if (status.online) {
                        if (api.reinstall()) screen = .progress;
                    } else goWifi();
                } else if (menu_sel == 1) {
                    if (api.repair()) screen = .progress else setz(&toast, "Nothing to repair to; a reinstall is needed.");
                } else if (menu_sel == 2) {
                    unlock_len = 0;
                    unlock_txt[0] = 0;
                    std.crypto.secureZero(u8, unlock_pin[0..]);
                    unlock_pin_len = 0;
                    toast[0] = 0;
                    block_reason[0] = 0;
                    lock_read = api.getLockState(&lock);
                    if (!lock_read) {
                        lock = .{};
                        setz(&block_reason, "The lock state could not be read, so unlocking is refused.");
                        screen = .unlock_blocked;
                    } else if (!lock.locked) {
                        setz(&toast, "This device is already unlocked.");
                    } else if (!lock.unlock_armed) {
                        screen = .unlock_blocked;
                    } else {
                        screen = .unlock_warn;
                    }
                }
            }
        },
        .sdb_pair => {
            if (e == .back) {
                _ = api.pairingCancel();
                pair = .{};
                pair_read = false;
                pair_note[0] = 0;
                screen = .menu;
            }
        },
        .wifi => {
            const m = if (net_n > 0) net_n else 1;
            if (e == .up) net_sel = (net_sel + m - 1) % m;
            if (e == .down) net_sel = (net_sel + 1) % m;
            if (e == .back) screen = .menu;
            if (e == .enter and net_n > 0) {
                setz(&sel_ssid, std.mem.sliceTo(&nets[net_sel].ssid, 0));
                if (nets[net_sel].secure) {
                    psk_len = 0;
                    psk[0] = 0;
                    screen = .password;
                    osk_r = 0;
                    osk_c = 0;
                } else {
                    _ = api.connect(std.mem.sliceTo(&sel_ssid, 0), "");
                    screen = .menu;
                    setz(&toast, "Connecting...");
                }
            }
        },
        .password => {
            if (e == .back) screen = .wifi;
            oskMove(e);
            if (e == .connectk) {
                setz(&toast, "Connecting...");
                _ = api.connect(std.mem.sliceTo(&sel_ssid, 0), std.mem.sliceTo(&psk, 0));
                screen = .menu;
            }
        },
        .progress => {
            if (e == .back and (status.state == .failed or status.state == .done)) screen = .menu;
        },
        .unlock_warn => {
            if (e == .back) {
                var msg: [160]u8 = std.mem.zeroes([160]u8);
                if (api.disarmUnlock(&msg)) {
                    screen = .menu;
                } else if (msg[0] != 0) {
                    setz(&toast, std.mem.sliceTo(&msg, 0));
                } else {
                    setz(&toast, "The unlock transaction could not be cancelled.");
                }
            }
            if (e == .enter) {
                unlock_len = 0;
                unlock_txt[0] = 0;
                osk_r = 0;
                osk_c = 0;
                osk_shift = false;
                screen = .unlock_pin;
            }
        },
        .unlock_pin => {
            if (e == .back) {
                std.crypto.secureZero(u8, unlock_pin[0..]);
                unlock_pin_len = 0;
                screen = .unlock_warn;
                return;
            }
            oskMove(e);
            if (e == .connectk) {
                if (unlock_pin_len < 4) {
                    setz(&toast, "Enter the owner's PIN before continuing.");
                    return;
                }
                unlock_len = 0;
                unlock_txt[0] = 0;
                osk_shift = true;
                screen = .unlock_confirm;
            }
        },
        .unlock_confirm => {
            if (e == .back) {
                unlock_len = 0;
                unlock_txt[0] = 0;
                screen = .unlock_pin;
                return;
            }
            oskMove(e);
            if (e == .connectk) {
                if (!unlockMatches()) {
                    setz(&toast, "Confirmation text does not match. Bootloader not unlocked.");
                    return;
                }
                lock_read = api.getLockState(&lock);
                if (!lock_read) lock = .{};
                if (!lock_read or !lock.locked or !lock.unlock_armed) {
                    unlock_len = 0;
                    unlock_txt[0] = 0;
                    std.crypto.secureZero(u8, unlock_pin[0..]);
                    unlock_pin_len = 0;
                    setz(&block_reason, "The lock state changed. Unlocking is refused.");
                    screen = .unlock_blocked;
                    return;
                }
                var msg: [160]u8 = std.mem.zeroes([160]u8);
                const ok = api.unlockBootloader(std.mem.sliceTo(&unlock_txt, 0), std.mem.sliceTo(&unlock_pin, 0), &msg);
                unlock_len = 0;
                unlock_txt[0] = 0;
                std.crypto.secureZero(u8, unlock_pin[0..]);
                unlock_pin_len = 0;
                if (ok) {
                    screen = .progress;
                } else {
                    if (msg[0] != 0) setz(&toast, std.mem.sliceTo(&msg, 0)) else setz(&toast, "The device refused the unlock request. Nothing was changed.");
                    screen = .unlock_pin;
                }
            }
        },
        .unlock_blocked => {
            if (e == .back or e == .enter) screen = .menu;
        },
    }
}

// ── DRM (drmMode helpers + @cImport mmap) ──

const Fb = struct {
    fb_id: u32 = 0,
    handle: u32 = 0,
    pitch: u32 = 0,
    surface: ?*c.cairo_surface_t = null,
};

var drm_fd: c_int = -1;
var crtc_id: u32 = 0;
var connector_id: u32 = 0;
var mode: c.drmModeModeInfo = undefined;
var fbs: [2]Fb = .{ .{}, .{} };

fn createFb(f: *Fb, w: u32, h: u32) bool {
    var hdl: u32 = 0;
    var pch: u32 = 0;
    var sz: u64 = 0;
    if (c.drmModeCreateDumbBuffer(drm_fd, w, h, 32, 0, &hdl, &pch, &sz) != 0) return false;
    f.handle = hdl;
    f.pitch = pch;
    if (c.drmModeAddFB(drm_fd, w, h, 24, 32, pch, hdl, &f.fb_id) != 0) return false;
    var offset: u64 = 0;
    if (c.drmModeMapDumbBuffer(drm_fd, hdl, &offset) != 0) return false;
    const m = c.mmap(null, sz, c.PROT_READ | c.PROT_WRITE, c.MAP_SHARED, drm_fd, @intCast(offset));
    if (m == c.MAP_FAILED) return false;
    f.surface = c.cairo_image_surface_create_for_data(@ptrCast(m), c.CAIRO_FORMAT_RGB24, @intCast(w), @intCast(h), @intCast(pch));
    return true;
}

fn drmSetup() bool {
    const cands = [_][*:0]const u8{ "/dev/dri/card0", "/dev/dri/card1", "/dev/dri/card2" };
    for (cands) |cd| {
        drm_fd = c.open(cd, c.O_RDWR | c.O_CLOEXEC);
        if (drm_fd >= 0) break;
    }
    if (drm_fd < 0) return false;
    const res = c.drmModeGetResources(drm_fd);
    if (res == null) return false;
    var i: usize = 0;
    while (i < @as(usize, @intCast(res.*.count_connectors))) : (i += 1) {
        const conn = c.drmModeGetConnector(drm_fd, res.*.connectors[i]);
        if (conn == null) continue;
        if (conn.*.connection == c.DRM_MODE_CONNECTED and conn.*.count_modes > 0) {
            connector_id = conn.*.connector_id;
            mode = conn.*.modes[0];
            if (conn.*.encoder_id != 0) {
                const enc = c.drmModeGetEncoder(drm_fd, conn.*.encoder_id);
                if (enc != null) {
                    crtc_id = enc.*.crtc_id;
                    c.drmModeFreeEncoder(enc);
                }
            }
            if (crtc_id == 0 and res.*.count_crtcs > 0) crtc_id = res.*.crtcs[0];
            c.drmModeFreeConnector(conn);
            break;
        }
        c.drmModeFreeConnector(conn);
    }
    c.drmModeFreeResources(res);
    if (crtc_id == 0 or connector_id == 0) return false;
    W = mode.hdisplay;
    H = mode.vdisplay;
    if (!createFb(&fbs[0], mode.hdisplay, mode.vdisplay)) return false;
    if (!createFb(&fbs[1], mode.hdisplay, mode.vdisplay)) return false;
    return true;
}

fn present(f: *Fb) void {
    c.cairo_surface_flush(f.surface);
    _ = c.drmModeSetCrtc(drm_fd, crtc_id, f.fb_id, 0, 0, &connector_id, 1, &mode);
}

// ── preview + main ──

fn png(path: [*:0]const u8) void {
    const surf = c.cairo_image_surface_create(c.CAIRO_FORMAT_RGB24, W, H);
    const cr = c.cairo_create(surf);
    render(cr);
    c.cairo_destroy(cr);
    _ = c.cairo_surface_write_to_png(surf, path);
    c.cairo_surface_destroy(surf);
}

fn preview() void {
    setz(&status.current, "slotA@a1b2c3");
    status.online = true;
    net_n = api.scan(&nets);
    setz(&sel_ssid, std.mem.sliceTo(&nets[0].ssid, 0));
    psk_len = 8;
    osk_r = 1;
    osk_c = 3;
    status.state = .working;
    status.progress = 46;
    setz(&status.message, "Verifying signature...");
    const screens = [_]struct { s: Screen, f: [*:0]const u8 }{
        .{ .s = .menu, .f = "/tmp/rc-zig-1-menu.png" },
        .{ .s = .wifi, .f = "/tmp/rc-zig-2-wifi.png" },
        .{ .s = .password, .f = "/tmp/rc-zig-3-password.png" },
        .{ .s = .progress, .f = "/tmp/rc-zig-4-progress.png" },
        .{ .s = .unlock_warn, .f = "/tmp/rc-zig-5-unlock-warn.png" },
        .{ .s = .unlock_pin, .f = "/tmp/rc-zig-6-unlock-pin.png" },
        .{ .s = .unlock_confirm, .f = "/tmp/rc-zig-7-unlock-confirm.png" },
        .{ .s = .unlock_blocked, .f = "/tmp/rc-zig-8-unlock-blocked.png" },
    };
    setz(&unlock_txt, unlock_word);
    unlock_len = unlock_word.len;
    setz(&unlock_pin, "1234");
    unlock_pin_len = 4;
    lock_read = api.getLockState(&lock);
    if (!lock_read) lock = .{};
    setz(&block_reason, "Unlocking is not allowed on this device.");
    for (screens) |sc| {
        screen = sc.s;
        png(sc.f);
    }

    screen = .sdb_pair;
    pair_read = true;
    pair = .{ .active = true, .expires_in = 96 };
    setz(&pair.code, "706816");
    png("/tmp/rc-zig-8-sdb-code-waiting.png");
    setz(&pair.fingerprint, "9F4C 1AB2 07E5 D386 0BC7 4F21 A9E0 D5C8");
    setz(&pair.label, "workstation");
    pair.attempts = 1;
    png("/tmp/rc-zig-9-sdb-code-key-presented.png");
    pair = .{};
    png("/tmp/rc-zig-10-sdb-no-code.png");
    pair = .{ .locked_for = 42, .attempts = 5 };
    png("/tmp/rc-zig-11-sdb-locked.png");
    pair_read = false;
    pair = .{};
    setz(&pair_note, "The pairing state could not be read, so no code is shown.");
    png("/tmp/rc-zig-12-sdb-unreadable.png");

    std.debug.print("wrote {d} Zig-rendered recovery screens to /tmp/rc-zig-*.png\n", .{screens.len + 5});
}

// ── tests: drive the real handle() with scripted events ──

const testing = std.testing;

fn tMock(armed: bool) void {
    _ = c.setenv("RECOVERY_MOCK", "1", 1);
    _ = c.setenv("RECOVERY_MOCK_UNLOCK_ARMED", if (armed) "1" else "0", 1);
    api.open(null);
}
fn tNoAgent() void {
    _ = c.setenv("RECOVERY_MOCK", "0", 1);
    api.open(null);
}
fn tMockSdb(pending: bool) void {
    _ = c.setenv("RECOVERY_MOCK", "1", 1);
    _ = c.setenv("RECOVERY_MOCK_SDB_PENDING", if (pending) "1" else "0", 1);
    api.open(null);
}
fn tResetSdb() void {
    screen = .menu;
    menu_sel = 0;
    toast[0] = 0;
    pair = .{};
    pair_read = false;
    pair_note[0] = 0;
    api.pair_begin_count = 0;
    api.pair_cancel_count = 0;
}
fn tReset() void {
    screen = .menu;
    menu_sel = 2;
    toast[0] = 0;
    block_reason[0] = 0;
    unlock_len = 0;
    unlock_txt[0] = 0;
    unlock_pin_len = 0;
    unlock_pin[0] = 0;
    lock = .{};
    lock_read = false;
    api.unlock_call_count = 0;
    api.disarm_call_count = 0;
}
fn tReachConfirm() void {
    handle(.enter);
    handle(.enter);
    tType("1234");
    handle(.connectk);
}
fn tType(s: []const u8) void {
    for (s) |ch| {
        ev_char = ch;
        handle(.char);
    }
}

test "not armed: unlock from menu is refused and never reaches confirm" {
    tMock(false);
    tReset();
    handle(.enter);
    try testing.expectEqual(Screen.unlock_blocked, screen);
    try testing.expectEqual(@as(usize, 0), api.unlock_call_count);
    handle(.back);
    try testing.expectEqual(Screen.menu, screen);
}

test "lock state unreadable: unlock from menu is refused" {
    tNoAgent();
    tReset();
    handle(.enter);
    try testing.expectEqual(Screen.unlock_blocked, screen);
    try testing.expect(!lock_read);
    try testing.expect(!lock.unlock_armed);
    try testing.expectEqual(@as(usize, 0), api.unlock_call_count);
}

test "armed and locked: menu reaches warning, PIN, then confirmation" {
    tMock(true);
    tReset();
    handle(.enter);
    try testing.expectEqual(Screen.unlock_warn, screen);
    handle(.enter);
    try testing.expectEqual(Screen.unlock_pin, screen);
    tType("1234");
    handle(.connectk);
    try testing.expectEqual(Screen.unlock_confirm, screen);
    try testing.expectEqual(@as(usize, 0), api.unlock_call_count);
}

test "esc from warning returns to menu" {
    tMock(true);
    tReset();
    handle(.enter);
    try testing.expectEqual(Screen.unlock_warn, screen);
    handle(.back);
    try testing.expectEqual(Screen.menu, screen);
    try testing.expectEqual(@as(usize, 1), api.disarm_call_count);
}

test "esc from PIN returns to warning and clears the PIN" {
    tMock(true);
    tReset();
    handle(.enter);
    handle(.enter);
    tType("1234");
    try testing.expectEqualStrings("1234", std.mem.sliceTo(&unlock_pin, 0));
    handle(.back);
    try testing.expectEqual(Screen.unlock_warn, screen);
    try testing.expectEqual(@as(usize, 0), unlock_pin_len);
    try testing.expectEqualStrings("", std.mem.sliceTo(&unlock_pin, 0));
}

test "esc from confirm returns to PIN and clears the typed word" {
    tMock(true);
    tReset();
    tReachConfirm();
    tType("UNLOCK");
    handle(.back);
    try testing.expectEqual(Screen.unlock_pin, screen);
    try testing.expectEqual(@as(usize, 0), unlock_len);
    try testing.expectEqualStrings("", std.mem.sliceTo(&unlock_txt, 0));
}

test "wrong confirmation text: F2 does not reach the agent and stays on confirm" {
    tMock(true);
    tReset();
    tReachConfirm();
    tType("unlock");
    handle(.connectk);
    try testing.expectEqual(Screen.unlock_confirm, screen);
    try testing.expectEqual(@as(usize, 0), api.unlock_call_count);
    tType("X");
    handle(.connectk);
    try testing.expectEqual(Screen.unlock_confirm, screen);
    try testing.expectEqual(@as(usize, 0), api.unlock_call_count);
}

test "revoked mid flow: F2 diverts to blocked and does not reach the agent" {
    tMock(true);
    tReset();
    tReachConfirm();
    tType("UNLOCK");
    try testing.expectEqual(Screen.unlock_confirm, screen);
    tMock(false);
    handle(.connectk);
    try testing.expectEqual(Screen.unlock_blocked, screen);
    try testing.expectEqual(@as(usize, 0), api.unlock_call_count);
    try testing.expectEqual(@as(usize, 0), unlock_len);
}

test "exact confirmation text: F2 reaches the agent" {
    tMock(true);
    tReset();
    tReachConfirm();
    tType("UNLOCK");
    handle(.connectk);
    try testing.expectEqual(@as(usize, 1), api.unlock_call_count);
    try testing.expectEqual(Screen.progress, screen);
}

test "already unlocked: menu does not offer unlock" {
    tMock(true);
    tReset();
    handle(.enter);
    try testing.expectEqual(Screen.menu, screen);
    try testing.expect(!lock.locked);
    try testing.expectEqual(@as(usize, 0), api.unlock_call_count);
}

test "debug bridge: entering with no host asking opens a code but shows no fingerprint" {
    tMockSdb(false);
    tResetSdb();
    goPairing();
    try testing.expectEqual(Screen.sdb_pair, screen);
    try testing.expect(pair_read);
    try testing.expect(pairShowsCode());
    try testing.expect(!pair.hasRequest());
    try testing.expectEqual(@as(usize, 1), api.pair_begin_count);
}

test "debug bridge: a presented key shows its fingerprint alongside the code" {
    tMockSdb(true);
    tResetSdb();
    goPairing();
    try testing.expectEqual(Screen.sdb_pair, screen);
    try testing.expect(pairShowsCode());
    try testing.expect(pair.hasRequest());
    try testing.expect(pair.expires_in > 0);
}

test "debug bridge: a lockout shows no code" {
    tMockSdb(true);
    tResetSdb();
    goPairing();
    pair.locked_for = 30;
    try testing.expect(!pairShowsCode());
}

test "debug bridge: an expired code is not shown" {
    tMockSdb(true);
    tResetSdb();
    goPairing();
    pair.active = false;
    pair.code = std.mem.zeroes([16]u8);
    try testing.expect(!pairShowsCode());
}

test "expiry is derived from the absolute timestamp the daemon returns" {
    const body =
        \\{"active":true,"code":"706816","expires_at":"2099-01-02T03:04:05Z","attempts":0}
    ;
    var st: api.PairingState = .{};
    try testing.expect(api.parsePairingBody(body, &st));
    try testing.expect(st.active);
    try testing.expect(st.expires_in > 0);
    try testing.expectEqualStrings("706816", std.mem.sliceTo(&st.code, 0));

    const stale =
        \\{"active":true,"code":"706816","expires_at":"2000-01-02T03:04:05Z","attempts":0}
    ;
    st = .{};
    try testing.expect(api.parsePairingBody(stale, &st));
    try testing.expect(!st.active);
    try testing.expectEqualStrings("", std.mem.sliceTo(&st.code, 0));

    const broken =
        \\{"active":true,"code":"706816","expires_at":"not-a-time","attempts":0}
    ;
    st = .{};
    try testing.expect(!api.parsePairingBody(broken, &st));
    try testing.expectEqualStrings("", std.mem.sliceTo(&st.code, 0));

    const truncated =
        \\{"active":true,"code":"706816","attempts":0}
    ;
    st = .{};
    try testing.expect(!api.parsePairingBody(truncated, &st));
    try testing.expectEqualStrings("", std.mem.sliceTo(&st.code, 0));
}

test "bodies captured from the running daemon parse as the screen expects" {
    const idle =
        \\{"active":false,"attempts":0,"code":"","expires_at":"0001-01-01T00:00:00Z","locked_until":"0001-01-01T00:00:00Z","pending_fingerprint":"","pending_fingerprint_display":"","pending_label":""}
    ;
    var st: api.PairingState = .{};
    try testing.expect(api.parsePairingBody(idle, &st));
    try testing.expect(!st.active);
    try testing.expect(!st.locked());
    try testing.expect(!st.hasRequest());
    try testing.expectEqualStrings("", std.mem.sliceTo(&st.code, 0));

    const started =
        \\{"active":true,"attempts":0,"code":"176809","expires_at":"2026-07-20T15:26:30.824903423+02:00","locked_until":"0001-01-01T00:00:00Z","pending_fingerprint":"","pending_fingerprint_display":"","pending_label":""}
    ;
    st = .{};
    try testing.expect(api.parsePairingBody(started, &st));
    try testing.expect(!st.locked());
    try testing.expect(st.active == (st.expires_in > 0));
    if (!st.active) try testing.expectEqualStrings("", std.mem.sliceTo(&st.code, 0));

    const asking =
        \\{"active":true,"attempts":1,"code":"176809","expires_at":"2099-07-20T15:26:30.824903423+02:00","locked_until":"0001-01-01T00:00:00Z","pending_fingerprint":"9f4c1ab2","pending_fingerprint_display":"9F4C 1AB2","pending_label":"workstation"}
    ;
    st = .{};
    try testing.expect(api.parsePairingBody(asking, &st));
    try testing.expect(st.active);
    try testing.expect(st.hasRequest());
    try testing.expectEqualStrings("9F4C 1AB2", std.mem.sliceTo(&st.fingerprint, 0));
    try testing.expectEqualStrings("workstation", std.mem.sliceTo(&st.label, 0));
    try testing.expectEqual(@as(i32, 1), st.attempts);
}

test "debug bridge: esc cancels pairing and returns to the menu" {
    tMockSdb(true);
    tResetSdb();
    goPairing();
    try testing.expectEqual(Screen.sdb_pair, screen);
    handle(.back);
    try testing.expectEqual(Screen.menu, screen);
    try testing.expectEqual(@as(usize, 1), api.pair_cancel_count);
    try testing.expect(!pairShowsCode());
    try testing.expectEqualStrings("", std.mem.sliceTo(&pair.code, 0));
}

test "debug bridge: unreadable pairing state shows no code" {
    tNoAgent();
    tResetSdb();
    goPairing();
    try testing.expectEqual(Screen.sdb_pair, screen);
    try testing.expect(!pair_read);
    try testing.expect(!pairShowsCode());
    try testing.expectEqualStrings("", std.mem.sliceTo(&pair.code, 0));
    try testing.expect(pair_note[0] != 0);
}

test "debug bridge: a session never survives leaving the screen" {
    tMockSdb(true);
    tResetSdb();
    goPairing();
    try testing.expect(pairShowsCode());
    handle(.back);
    goPairing();
    try testing.expectEqual(Screen.sdb_pair, screen);
    try testing.expectEqual(@as(usize, 2), api.pair_begin_count);
}

pub fn main() void {
    api.open(null);
    if (c.getenv("RECOVERY_PNG") != null) {
        preview();
        return;
    }
    inputOpen();
    if (!drmSetup()) {
        std.debug.print("recovery-ui: no DRM output (RECOVERY_PNG=1 for a preview)\n", .{});
        return;
    }
    _ = api.statusGet(&status);
    lock_read = api.getLockState(&lock);
    if (!lock_read) lock = .{};
    var back: usize = 0;
    var frame: usize = 0;
    while (true) {
        const e = inputPoll(if (screen == .progress) 120 else 400);
        if (e == .quit) break;
        if (e != .none) handle(e);
        frame += 1;
        if (frame % 3 == 0) {
            _ = api.statusGet(&status);
            if (screen == .menu) {
                lock_read = api.getLockState(&lock);
                if (!lock_read) lock = .{};
            }
            if (screen == .sdb_pair) pairRefresh();
        }
        const cr = c.cairo_create(fbs[back].surface);
        render(cr);
        c.cairo_destroy(cr);
        present(&fbs[back]);
        back ^= 1;
    }
}
