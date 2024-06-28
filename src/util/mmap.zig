const std = @import("std");
const posix = std.posix;
const fd_t = posix.fd_t;
const builtin = @import("builtin");
const windows = std.os.windows;
const ntdll = windows.ntdll;
const zigwin = @import("zigwin32");
const HANDLE = zigwin.foundation.HANDLE;
const winmem = zigwin.system.memory;

pub const MappingHandle = if (builtin.os.tag == .windows) HANDLE else struct {
    fd: fd_t,
    mode: u32,
};

pub fn create_mapping(file: std.fs.File, mode: std.fs.File.OpenMode) !MappingHandle {
    if (builtin.os.tag == .windows) {
        return winmem.CreateFileMapping(
            file.handle,
            null,
            .{
                .PAGE_READONLY = mode == .read_only,
                .PAGE_READWRITE = mode != .read_only,
            },
            0,
            0,
            null,
        ) orelse switch (windows.kernel32.GetLastError()) {
            else => |err| return windows.unexpectedError(err),
        };
    } else {
        return .{ .fd = file.handle, .mode = switch (mode) {
            .read_only => posix.PROT.READ,
            .write_only => posix.PROT.WRITE,
            .read_write => posix.PROT.READ | posix.PROT.WRITE,
        } };
    }
}

pub fn map_view_of_file(mapping: MappingHandle, ofs: usize, len: ?usize, mode: if (builtin.os.tag == .windows) std.fs.File.OpenMode else void) !*anyopaque {
    if (builtin.os.tag == .windows) {
        return winmem.MapViewOfFile(
            mapping,
            .{ .WRITE = mode != .read_only, .READ = mode != .write_only },
            ofs >> 32,
            @truncate(ofs),
            len orelse 0,
        ) orelse switch (windows.kernel32.GetLastError()) {
            else => |err| return windows.unexpectedError(err),
        };
    } else {
        return try posix.mmap(null, len orelse (posix.fstat(mapping.fd).size - ofs), mapping.mode, .{ .TYPE = .PRIVATE }, mapping.fd, ofs);
    }
}

pub fn flush_view_of_file(ptr: []const u8) !void {
    if(builtin.os.tag == .windows) {
        if(winmem.FlushViewOfFile(ptr.ptr, ptr.len) != 0) switch (windows.kernel32.GetLastError()) {
            else => |err| return windows.unexpectedError(err),
        };
    } else {
        try posix.msync(ptr, posix.MSF.SYNC);
    }
}

pub fn unmap_view_of_file(ptr: []const u8) void {
    if(builtin.os.tag == .windows) {
        std.debug.assert(winmem.UnmapViewOfFile(ptr.ptr) == 0);
    } else {
        posix.munmap(ptr);
    }
}

pub fn close_mapping(mapping: MappingHandle) void {
    if(builtin.os.tag == .windows) {
        std.debug.assert(zigwin.foundation.CloseHandle(mapping) == 0);
    }
}

test {
    std.testing.refAllDecls(@This());
}