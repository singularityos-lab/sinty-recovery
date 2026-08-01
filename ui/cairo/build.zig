// build.zig for the Cairo recovery UI.
// Zig 0.16: linking + C sources live on the Module, not the Compile step.
// Link the KMS/Cairo/input C stack and compile the shared C-ABI loginui straight
// in (drop the C sources once loginui itself is Zig).
const std = @import("std");

fn uiModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // KMS + Cairo + input, plus loginui's own deps (pangocairo, gdk-pixbuf,
    // wayland-client) since we compile its C sources into this exe.
    for ([_][]const u8{
        "cairo",  "pangocairo", "gdk-pixbuf-2.0", "wayland-client",
        "libdrm", "libinput",   "libudev",        "xkbcommon",
    }) |lib|
        mod.linkSystemLibrary(lib, .{});

    // Shared loginui renderer, still C during the migration: compile its sources
    // into this exe and @cImport loginui.h from Zig (see src/main.zig). No meson.
    // When loginui becomes Zig, delete these lines and @import the Zig module.
    const loginui = "subprojects/singularity-loginui";
    mod.addIncludePath(b.path(loginui));
    mod.addCSourceFiles(.{
        .files = &.{
            loginui ++ "/src/buffer.c",
            loginui ++ "/src/draw.c",
            loginui ++ "/src/image.c",
            loginui ++ "/src/render.c",
        },
        .flags = &.{"-std=c11"},
    });
    return mod;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "sinty-recovery-ui",
        .root_module = uiModule(b, target, optimize),
    });
    b.installArtifact(exe);

    const tests = b.addTest(.{ .root_module = uiModule(b, target, optimize) });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run the recovery UI tests").dependOn(&run_tests.step);
}
