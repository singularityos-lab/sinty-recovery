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
    @cInclude("time.h");
});

pub const State = enum(u8) { idle = 0, connecting, working, done, failed };

pub const Network = struct {
    ssid: [64]u8 = std.mem.zeroes([64]u8),
    signal: i32 = -90,
    secure: bool = true,
};

pub const LockState = struct {
    locked: bool = true,
    unlock_armed: bool = false,
    unlock_count: i32 = 0,
};

pub const PairingState = struct {
    active: bool = false,
    code: [16]u8 = std.mem.zeroes([16]u8),
    expires_in: i32 = 0,
    fingerprint: [128]u8 = std.mem.zeroes([128]u8),
    label: [64]u8 = std.mem.zeroes([64]u8),
    attempts: i32 = 0,
    locked_for: i32 = 0,

    pub fn hasRequest(self: *const PairingState) bool {
        return self.fingerprint[0] != 0;
    }
    pub fn locked(self: *const PairingState) bool {
        return self.locked_for > 0;
    }
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
const sdb_sock_path: []const u8 = "/run/sinty-sdb.sock";

pub fn open(addr: ?[]const u8) void {
    use_mock = if (std.c.getenv("RECOVERY_MOCK")) |m| blk: {
        const s = std.mem.span(m);
        break :blk (s.len > 0 and !std.mem.eql(u8, s, "0"));
    } else false;
    mk_armed = if (std.c.getenv("RECOVERY_MOCK_UNLOCK_ARMED")) |m| blk: {
        const s = std.mem.span(m);
        break :blk (s.len > 0 and !std.mem.eql(u8, s, "0"));
    } else false;
    mk_sdb_pending = if (std.c.getenv("RECOVERY_MOCK_SDB_PENDING")) |m| blk: {
        const s = std.mem.span(m);
        break :blk (s.len > 0 and !std.mem.eql(u8, s, "0"));
    } else false;
    mk_sdb_active = false;
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

fn httpAt(sock: []const u8, method: []const u8, path: []const u8, body: ?[]const u8, out: []u8) ?[]const u8 {
    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd < 0) return null;
    defer _ = c.close(fd);
    var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    addr.sun_family = c.AF_UNIX;
    if (sock.len >= addr.sun_path.len) return null;
    @memcpy(addr.sun_path[0..sock.len], sock);
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

fn http(method: []const u8, path: []const u8, body: ?[]const u8, out: []u8) ?[]const u8 {
    return httpAt(sock_path, method, path, body, out);
}

fn daysFromCivil(y: i64, m: i64, d: i64) i64 {
    const yy = y - @intFromBool(m <= 2);
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp = @mod(m + 9, 12);
    const doy = @divTrunc(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn num(s: []const u8, at: usize, len: usize) ?i64 {
    if (at + len > s.len) return null;
    return std.fmt.parseInt(i64, s[at .. at + len], 10) catch null;
}

fn parseRfc3339(s: []const u8) ?i64 {
    if (s.len < 20) return null;
    if (s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != 't')) return null;
    if (s[13] != ':' or s[16] != ':') return null;
    const y = num(s, 0, 4) orelse return null;
    const mo = num(s, 5, 2) orelse return null;
    const d = num(s, 8, 2) orelse return null;
    const h = num(s, 11, 2) orelse return null;
    const mi = num(s, 14, 2) orelse return null;
    const se = num(s, 17, 2) orelse return null;
    if (mo < 1 or mo > 12 or d < 1 or d > 31 or h > 23 or mi > 59 or se > 60) return null;
    var i: usize = 19;
    if (i < s.len and s[i] == '.') {
        i += 1;
        while (i < s.len and s[i] >= '0' and s[i] <= '9') i += 1;
    }
    if (i >= s.len) return null;
    var off: i64 = 0;
    if (s[i] == 'Z' or s[i] == 'z') {} else if (s[i] == '+' or s[i] == '-') {
        const oh = num(s, i + 1, 2) orelse return null;
        if (i + 3 >= s.len or s[i + 3] != ':') return null;
        const om = num(s, i + 4, 2) orelse return null;
        off = oh * 3600 + om * 60;
        if (s[i] == '-') off = -off;
    } else return null;
    return daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - off;
}

fn secondsUntil(j: []const u8, key: []const u8) ?i32 {
    var buf: [64]u8 = std.mem.zeroes([64]u8);
    jStr(j, key, &buf);
    const s = std.mem.sliceTo(&buf, 0);
    if (s.len == 0) return null;
    const at = parseRfc3339(s) orelse return null;
    const left = at - @as(i64, @intCast(c.time(null)));
    if (left <= 0) return 0;
    if (left > std.math.maxInt(i32)) return std.math.maxInt(i32);
    return @intCast(left);
}

// ── mock ──

var mk_online = false;
var mk_state: State = .idle;
var mk_ticks: i32 = 0;
var mk_msg: [160]u8 = std.mem.zeroes([160]u8);
var mk_locked = true;
var mk_armed = false;
var mk_unlock_count: i32 = 0;
var mk_sdb_active = false;
var mk_sdb_pending = false;

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
pub fn getLockState(out: *LockState) bool {
    out.* = .{};
    if (use_mock) {
        out.locked = mk_locked;
        out.unlock_armed = mk_armed;
        out.unlock_count = mk_unlock_count;
        return true;
    }
    var buf: [2048]u8 = undefined;
    const b = http("GET", "/lock-state", null, &buf) orelse return false;
    if (std.mem.indexOf(u8, b, "\"locked\"") == null) return false;
    if (std.mem.indexOf(u8, b, "\"unlock_armed\"") == null) return false;
    out.locked = jBool(b, "locked", true);
    out.unlock_armed = jBool(b, "unlock_armed", false);
    out.unlock_count = jInt(b, "unlock_count", 0);
    return true;
}

pub var disarm_call_count: usize = 0;

pub fn disarmUnlock(msg: []u8) bool {
    disarm_call_count += 1;
    if (use_mock) {
        mk_armed = false;
        setz(msg, "Bootloader unlock consent cleared.");
        return true;
    }
    var buf: [2048]u8 = undefined;
    const b = http("POST", "/arm-unlock", "{\"armed\":false}", &buf) orelse return false;
    jStr(b, "message", msg);
    return jBool(b, "ok", false);
}

pub var pair_begin_count: usize = 0;
pub var pair_cancel_count: usize = 0;

pub fn getPairingState(out: *PairingState) bool {
    out.* = .{};
    if (use_mock) {
        if (!mk_sdb_active) return true;
        out.active = true;
        setz(&out.code, "706816");
        out.expires_in = 96;
        out.attempts = if (mk_sdb_pending) 1 else 0;
        if (mk_sdb_pending) {
            setz(&out.fingerprint, "9F4C 1AB2 07E5 D386 0BC7 4F21 A9E0 D5C8");
            setz(&out.label, "workstation");
        }
        return true;
    }
    var buf: [8192]u8 = undefined;
    const b = httpAt(sdb_sock_path, "GET", "/pairing/state", null, &buf) orelse return false;
    return parsePairingBody(b, out);
}

pub fn parsePairingBody(b: []const u8, out: *PairingState) bool {
    out.* = .{};
    if (std.mem.indexOf(u8, b, "\"active\"") == null) return false;
    if (std.mem.indexOf(u8, b, "\"attempts\"") == null) return false;

    out.attempts = jInt(b, "attempts", 0);
    jStr(b, "pending_fingerprint_display", &out.fingerprint);
    jStr(b, "pending_label", &out.label);
    if (secondsUntil(b, "locked_until")) |left| out.locked_for = left;

    if (!jBool(b, "active", false)) return true;
    jStr(b, "code", &out.code);
    const left = secondsUntil(b, "expires_at") orelse {
        out.* = .{};
        return false;
    };
    if (out.code[0] == 0) {
        out.* = .{};
        return false;
    }
    if (left == 0) {
        out.code = std.mem.zeroes([16]u8);
        return true;
    }
    out.active = true;
    out.expires_in = left;
    return true;
}

pub fn pairingStart() bool {
    pair_begin_count += 1;
    if (use_mock) {
        mk_sdb_active = true;
        return true;
    }
    var buf: [2048]u8 = undefined;
    const b = httpAt(sdb_sock_path, "POST", "/pairing/start", "{}", &buf) orelse return false;
    if (!jBool(b, "ok", false)) return false;
    var code: [16]u8 = std.mem.zeroes([16]u8);
    jStr(b, "code", &code);
    return code[0] != 0;
}

pub fn pairingCancel() bool {
    pair_cancel_count += 1;
    if (use_mock) {
        mk_sdb_active = false;
        return true;
    }
    var buf: [2048]u8 = undefined;
    const b = httpAt(sdb_sock_path, "POST", "/pairing/cancel", "{}", &buf) orelse return false;
    return jBool(b, "ok", false);
}

pub var unlock_call_count: usize = 0;

pub fn unlockBootloader(confirm: []const u8, pin: []const u8, msg: []u8) bool {
    unlock_call_count += 1;
    if (use_mock) {
        if (!mk_armed or !std.mem.eql(u8, confirm, "UNLOCK") or pin.len < 4) {
            setz(msg, "The device refused the unlock request.");
            return false;
        }
        mk_locked = false;
        mk_armed = false;
        mk_unlock_count += 1;
        return startWork();
    }
    if (confirm.len == 0 or confirm.len > 64) return false;
    for (confirm) |ch| {
        if (ch < 0x20 or ch > 0x7e or ch == '"' or ch == '\\') return false;
    }
    if (pin.len < 4 or pin.len > 256) return false;
    var escaped: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, escaped[0..]);
    var escaped_len: usize = 0;
    for (pin) |ch| {
        if (ch < 0x20) return false;
        if (ch == '"' or ch == '\\') {
            if (escaped_len + 2 > escaped.len) return false;
            escaped[escaped_len] = '\\';
            escaped_len += 1;
        } else if (escaped_len + 1 > escaped.len) return false;
        escaped[escaped_len] = ch;
        escaped_len += 1;
    }
    var bbuf: [768]u8 = undefined;
    defer std.crypto.secureZero(u8, bbuf[0..]);
    const body = std.fmt.bufPrint(&bbuf, "{{\"confirm\":\"{s}\",\"pin\":\"{s}\"}}", .{ confirm, escaped[0..escaped_len] }) catch return false;
    var buf: [2048]u8 = undefined;
    const b = http("POST", "/unlock-bootloader", body, &buf) orelse return false;
    jStr(b, "message", msg);
    return jBool(b, "ok", false);
}
