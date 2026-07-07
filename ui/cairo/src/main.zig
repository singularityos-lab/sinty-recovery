// Sinty Recovery - Cairo UI.
//
// KMS-direct like singularity-boot-splash: owns a DRM CRTC and renders with Cairo
// through the shared C-ABI loginui. Syscalls go through @cImport of the C
// headers (a hosted libc binary), not std.posix.
// RECOVERY_PNG=1 renders each screen to a file for hardware-less review.
const std = @import("std");
const api = @import("api.zig");
const c = @cImport({
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

const Screen = enum { menu, wifi, password, progress };
var screen: Screen = .menu;

const menu_items = [_][*:0]const u8{ "Reinstall Sinty", "Repair" };
var menu_sel: usize = 0;

var nets: [64]api.Network = undefined;
var net_n: usize = 0;
var net_sel: usize = 0;

var psk: [128]u8 = std.mem.zeroes([128]u8);
var psk_len: usize = 0;
var sel_ssid: [64]u8 = std.mem.zeroes([64]u8);

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

fn drawPassword(cr: ?*c.cairo_t) void {
    var t: [128]u8 = undefined;
    const title = std.fmt.bufPrintZ(&t, "Password for {s}", .{std.mem.sliceTo(&sel_ssid, 0)}) catch "Password";
    header(cr, title.ptr);
    const fwd: f64 = 520;
    const x = (fw() - fwd) / 2;
    const y: f64 = 210;
    const fh_field: f64 = 52;
    fill(cr, x, y, fwd, fh_field, fg, 0.08);
    var mask: [130]u8 = undefined;
    var k: usize = 0;
    while (k < psk_len and k < 128) : (k += 1) mask[k] = '*';
    mask[k] = 0;
    textMid(cr, "22", @ptrCast(&mask), x + 20, y, fh_field, 0, fg);

    var ky: f64 = 300;
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
    text(cr, "14", "arrows move   Enter type   Tab shift   F2 connect   Backspace del   Esc back", fw() / 2, fh() - 92, 1, dim);
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
fn oskType() void {
    var ch = osk_rows[osk_r][osk_c];
    if (osk_shift and ch >= 'a' and ch <= 'z') ch -= 32;
    if (psk_len < psk.len - 1) {
        psk[psk_len] = ch;
        psk_len += 1;
        psk[psk_len] = 0;
    }
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
                } else {
                    if (api.repair()) screen = .progress else setz(&toast, "Nothing to repair to; a reinstall is needed.");
                }
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
            if (e == .up) osk_r = (osk_r + 3) % 4;
            if (e == .down) osk_r = (osk_r + 1) % 4;
            if (e == .left) osk_c = (osk_c + osk_rows[osk_r].len - 1) % osk_rows[osk_r].len;
            if (e == .right) osk_c = (osk_c + 1) % osk_rows[osk_r].len;
            if (osk_c >= osk_rows[osk_r].len) osk_c = osk_rows[osk_r].len - 1;
            if (e == .enter) oskType();
            if (e == .shift) osk_shift = !osk_shift;
            if (e == .del and psk_len > 0) {
                psk_len -= 1;
                psk[psk_len] = 0;
            }
            if (e == .char and psk_len < psk.len - 1) {
                psk[psk_len] = ev_char;
                psk_len += 1;
                psk[psk_len] = 0;
            }
            if (e == .connectk) {
                setz(&toast, "Connecting...");
                _ = api.connect(std.mem.sliceTo(&sel_ssid, 0), std.mem.sliceTo(&psk, 0));
                screen = .menu;
            }
        },
        .progress => {
            if (e == .back and (status.state == .failed or status.state == .done)) screen = .menu;
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
    };
    for (screens) |sc| {
        screen = sc.s;
        png(sc.f);
    }
    std.debug.print("wrote 4 Zig-rendered recovery screens to /tmp/rc-zig-*.png\n", .{});
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
    var back: usize = 0;
    var frame: usize = 0;
    while (true) {
        const e = inputPoll(if (screen == .progress) 120 else 400);
        if (e == .quit) break;
        if (e != .none) handle(e);
        frame += 1;
        if (frame % 3 == 0) _ = api.statusGet(&status);
        const cr = c.cairo_create(fbs[back].surface);
        render(cr);
        c.cairo_destroy(cr);
        present(&fbs[back]);
        back ^= 1;
    }
}
