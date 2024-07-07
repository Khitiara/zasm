const std = @import("std");
const meta = std.meta;

pub fn swap(ptr: anytype, new: @typeInfo(@TypeOf(ptr)).Pointer.child) @typeInfo(@TypeOf(ptr)).Pointer.child {
    defer ptr.* = new;
    return ptr.*;
}
