const std = @import("std");
const Allocator = std.mem.Allocator;
const Core = @import("Core.zig");

const Backend = @This();

ptr: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    reset: *const fn (ctx: *anyopaque, core: *Core) void,
    init: *const fn (ctx: *anyopaque, core: *Core) Allocator.Error!void,
};
