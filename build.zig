const std = @import("std");
const Build = std.Build;
const LazyPath = Build.LazyPath;

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zigwin32 = b.dependency("zigwin32", .{});

    const zasm_exe = b.addExecutable(.{
        .name = "zasm",
        .root_source_file = b.path("src/zasm.zig"),
        .target = target,
        .optimize = optimize,
    });
    zasm_exe.root_module.addImport("zigwin32", zigwin32.module("zigwin32"));
    b.installArtifact(zasm_exe);

    const tests = b.addTest(.{
        .root_source_file = b.path("src/zasm.zig"),
        .target = target,
        .optimize = optimize,
    });
    zasm_exe.root_module.addImport("zigwin32", zigwin32.module("zigwin32"));
    const test_step = b.step("test", "Run tests.");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
