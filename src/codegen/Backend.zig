const std = @import("std");
const Allocator = std.mem.Allocator;
const Core = @import("Core.zig");

const Backend = @This();

pub const Tag = enum {
    x86,
};

fn EmitFn(comptime T: type) type {
    return *const fn (backend: *Backend, core: *Core, item: T) anyerror!u64;
}

tag: Tag,
addressable_unit_bits: u8,
emit_data_fn: EmitFn(Core.DataReservation),
endian: std.builtin.Endian,
