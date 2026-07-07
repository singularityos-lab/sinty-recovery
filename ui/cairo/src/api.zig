// The recovery Core as the Cairo UI sees it.
// Backed by the agent serve-mode (HTTP over the unix socket /run/atom-recovery.sock)
// or an in-process mock when RECOVERY_MOCK is set, for VM development.
// Syscalls via @cImport of the C headers (a hosted binary linking libc), not std.posix.
const std = @import("std");
const c = @cImport({
    @cInclude("sys/socket.h");
    @cInclude("sys/un.h");
    @cInclude("unistd.h");
    @cInclude("stdlib.h");
});

pub const State = enum(u8) { idle = 0, connecting, working, done, failed };

pub const Network = struct {
    ssid: [64]u8 = std.mem.zeroes([64]u8),
    signal: i32 = -90,
    secure: bool = true,
};

pub const Status = struct {
    online: bool = false,
    current: [64]u8 = std.mem.zeroes([64]u8),
    rollback: [64]u8 = std.mem.zeroes([64]u8),
    state: State = .idle,
    progress: i32 = -1,
    message: [160]u8 = std.mem.zeroes([160]u8),
};

var use_mock = false;
var sock_path_buf: [256]u8 = undefined;
var sock_path: []const u8 = "/run/atom-recovery.sock";

pub fn open(addr: ?[]const u8) void {
    use_mock = if (std.c.getenv("RECOVERY_MOCK")) |m| blk: {
        const s = std.mem.span(m);
        break :blk (s.len > 0 and !std.mem.eql(u8, s, "0"));
    } else false;
    if (addr) |a| {
        @memcpy(sock_path_buf[0..a.len], a);
        sock_path = sock_path_buf[0..a.len];
    }
}

fn setz(dst: []u8, src: []const u8) void {
    const n = @min(dst.len - 1, src.len);
    @memcpy(dst[0..n], src[0..n]);
    dst[n] = 0;
}

// ── minimal JSON field readers (flat objects) ──

fn findVal(j: []const u8, key: []const u8) ?[]const u8 {
    var kbuf: [72]u8 = undefined;
    const pat = std.fmt.bufPrint(&kbuf, "\"{s}\"", .{key}) catch return null;
    const at = std.mem.indexOf(u8, j, pat) orelse return null;
    const colon = std.mem.indexOfScalarPos(u8, j, at + pat.len, ':') orelse return null;
    var i = colon + 1;
    while (i < j.len and (j[i] == ' ' or j[i] == '\t')) i += 1;
    return j[i..];
}

fn jStr(j: []const u8, key: []const u8, out: []u8) void {
    const v = findVal(j, key) orelse return;
    if (v.len == 0 or v[0] != '"') return;
    var i: usize = 1;
    var o: usize = 0;
    while (i < v.len and v[i] != '"' and o + 1 < out.len) : (i += 1) {
        if (v[i] == '\\' and i + 1 < v.len) i += 1;
        out[o] = v[i];
        o += 1;
    }
    out[o] = 0;
}

fn jInt(j: []const u8, key: []const u8, dflt: i32) i32 {
    const v = findVal(j, key) orelse return dflt;
    var end: usize = 0;
    while (end < v.len and (v[end] == '-' or (v[end] >= '0' and v[end] <= '9'))) end += 1;
    if (end == 0) return dflt;
    return std.fmt.parseInt(i32, v[0..end], 10) catch dflt;
}

fn jBool(j: []const u8, key: []const u8, dflt: bool) bool {
    const v = findVal(j, key) orelse return dflt;
    return std.mem.startsWith(u8, v, "true");
}

// ── one request/response over the unix socket ──

fn http(method: []const u8, path: []const u8, body: ?[]const u8, out: []u8) ?[]const u8 {
    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd < 0) return null;
    defer _ = c.close(fd);
    var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    addr.sun_family = c.AF_UNIX;
    @memcpy(addr.sun_path[0..sock_path.len], sock_path);
    if (c.connect(fd, @ptrCast(&addr), @sizeOf(c.struct_sockaddr_un)) != 0) return null;

    var req: [1024]u8 = undefined;
    const blen = if (body) |b| b.len else 0;
    const s = std.fmt.bufPrint(&req, "{s} {s} HTTP/1.0\r\nHost: recovery\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ method, path, blen, body orelse "" }) catch return null;
    if (c.write(fd, s.ptr, s.len) < 0) return null;
    var total: usize = 0;
    while (total < out.len) {
        const n = c.read(fd, out.ptr + total, out.len - total);
        if (n <= 0) break;
        total += @intCast(n);
    }
    const buf = out[0..total];
    const sep = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    return buf[sep + 4 ..];
}

// ── mock ──

var mk_online = false;
var mk_state: State = .idle;
var mk_ticks: i32 = 0;
var mk_msg: [160]u8 = std.mem.zeroes([160]u8);

const fake = [_]struct { s: []const u8, sig: i32, sec: bool }{
    .{ .s = "Sinty-Home", .sig = -48, .sec = true },
    .{ .s = "FASTWEB-9AB21C", .sig = -61, .sec = true },
    .{ .s = "TIM-4471102", .sig = -70, .sec = true },
    .{ .s = "Sinty-Guest", .sig = -74, .sec = false },
    .{ .s = "iliad-88F0", .sig = -82, .sec = true },
};

// ── public ──

pub fn statusGet(out: *Status) bool {
    if (use_mock) {
        out.* = .{};
        out.online = mk_online;
        setz(&out.current, "slotA@a1b2c3");
        setz(&out.rollback, "slotB@d4e5f6");
        out.state = mk_state;
        out.progress = -1;
        if (mk_state == .working) {
            mk_ticks += 5;
            var pct: i32 = mk_ticks;
            if (pct >= 100) {
                pct = 100;
                mk_state = .done;
            }
            out.progress = pct;
            const phase = if (pct < 30) "Downloading image..." else if (pct < 70) "Verifying signature..." else "Staging to slot...";
            setz(&out.message, phase);
        } else {
            setz(&out.message, std.mem.sliceTo(&mk_msg, 0));
        }
        return true;
    }
    var buf: [8192]u8 = undefined;
    const b = http("GET", "/status", null, &buf) orelse return false;
    out.* = .{};
    out.online = jBool(b, "online", false);
    jStr(b, "current", &out.current);
    jStr(b, "rollback", &out.rollback);
    out.state = @enumFromInt(@as(u8, @intCast(@max(0, jInt(b, "state", 0)))));
    out.progress = jInt(b, "progress", -1);
    jStr(b, "message", &out.message);
    return true;
}

pub fn scan(nets: []Network) usize {
    if (use_mock) {
        const n = @min(nets.len, fake.len);
        for (0..n) |i| {
            setz(&nets[i].ssid, fake[i].s);
            nets[i].signal = fake[i].sig;
            nets[i].secure = fake[i].sec;
        }
        return n;
    }
    var buf: [8192]u8 = undefined;
    const b = http("GET", "/scan", null, &buf) orelse return 0;
    var n: usize = 0;
    var rest = b;
    while (n < nets.len) {
        const at = std.mem.indexOf(u8, rest, "\"ssid\"") orelse break;
        const objend = std.mem.indexOfScalarPos(u8, rest, at, '}') orelse rest.len;
        const chunk = rest[at..objend];
        jStr(chunk, "ssid", &nets[n].ssid);
        nets[n].signal = jInt(chunk, "signal", -90);
        nets[n].secure = jBool(chunk, "secure", true);
        n += 1;
        rest = rest[@min(objend + 1, rest.len)..];
    }
    return n;
}

pub fn connect(ssid: []const u8, psk: []const u8) bool {
    if (use_mock) {
        mk_online = true;
        setz(&mk_msg, "Connected.");
        return true;
    }
    var bbuf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&bbuf, "{{\"ssid\":\"{s}\",\"psk\":\"{s}\"}}", .{ ssid, psk }) catch return false;
    var buf: [2048]u8 = undefined;
    const b = http("POST", "/connect", body, &buf) orelse return false;
    return jBool(b, "ok", false);
}

fn startWork() bool {
    mk_state = .working;
    mk_ticks = 0;
    mk_msg = std.mem.zeroes([160]u8);
    return true;
}

fn post(path: []const u8) bool {
    if (use_mock) return startWork();
    var buf: [512]u8 = undefined;
    return http("POST", path, "{}", &buf) != null;
}

pub fn reinstall() bool {
    return post("/reinstall");
}
pub fn repair() bool {
    return post("/repair");
}
pub fn rollback() bool {
    return post("/rollback");
}
