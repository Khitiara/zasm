const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = @import("../parse/Ast.zig");
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringIndexAdapter = std.hash_map.StringIndexAdapter;
const StringIndexContext = std.hash_map.StringIndexContext;

pub fn StringTable(comptime V: type) type {
    return struct {
        const Self = @This();
        const Table = std.HashMapUnmanaged(u32, V, StringIndexContext, std.hash_map.default_max_load_percentage);

        pub const NullTerminatedString = enum(u32) {
            null = 0,
            _,
        };
        pub const Entry = struct {
            idx: NullTerminatedString,
            value_ptr: *V,
        };
        pub const KV = struct {
            idx: NullTerminatedString,
            value: V,
        };
        pub const GetOrPutResult = struct {
            idx: NullTerminatedString,
            value_ptr: *V,
            found_existing: bool,
            pub fn entry(self: GetOrPutResult) Entry {
                return .{
                    .idx = self.idx,
                    .value_ptr = self.value_ptr,
                };
            }
        };

        bytes: ArrayListUnmanaged(u8) = .{},
        table: Table = .{},

        pub fn init(alloc: Allocator) Allocator.Error!Self {
            const self: Self = .{};
            try self.bytes.append(alloc, 0);
            return self;
        }

        pub fn get_index(self: Self, idx: u32) ?KV {
            const value = self.table.getContext(idx, .{ .bytes = &self.bytes }) orelse return null;
            return .{ .idx = idx, .value = value };
        }

        pub fn get_string(self: Self, key: []const u8) ?KV {
            const entry = self.table.getEntryAdapted(key, StringIndexAdapter{ .bytes = &self.bytes }) orelse return null;
            return .{ .idx = entry.key_ptr.*, .value = entry.value_ptr.* };
        }

        pub fn get_entry_index(self: Self, idx: u32) ?Entry {
            const inner = self.table.getEntryContext(idx, .{ .bytes = &self.bytes }) orelse return null;
            return .{ .idx = idx, .value_ptr = inner.value_ptr };
        }

        pub fn get_entry_string(self: Self, key: []const u8) ?Table.Entry {
            const inner = self.table.getEntryAdapted(key, StringIndexAdapter{ .bytes = &self.bytes }) orelse return null;
            return .{ .idx = inner.key_ptr.*, .value_ptr = inner.value_ptr };
        }

        pub fn get_or_put(self: Self, alloc: Allocator, key: []const u8) Allocator.Error!GetOrPutResult {
            const idx = self.bytes.items.len;
            // append first and shrink retaining capacity after so allocation failure
            // on append doesnt create an entry in the table
            try self.bytes.appendSlice(alloc, key);
            try self.bytes.append(alloc, 0);
            const result = try self.table.getOrPutContextAdapted(alloc, key, StringIndexAdapter{ .bytes = &self.bytes }, .{ .bytes = &self.bytes });
            if (!result.found_existing) {
                result.key_ptr.* = idx;
            } else {
                self.bytes.shrinkRetainingCapacity(idx);
            }
            return .{
                .found_existing = result.found_existing,
                .idx = result.key_ptr.*,
                .value_ptr = result.value_ptr,
            };
        }

        pub fn put_index(self: Self, alloc: Allocator, key: u32, value: V) Allocator.Error!void {
            return self.table.putContext(alloc, key, value, .{ .bytes = &self.bytes });
        }

        pub fn put_string(self: Self, alloc: Allocator, key: []const u8, value: V) Allocator.Error!u32 {
            const result = try self.get_or_put(alloc, key);
            result.value_ptr.* = value;
            return result.key_ptr.*;
        }

        pub fn get_string_for_index(self: Self, idx: u32) []const u8 {
            return std.mem.sliceTo(self.bytes.items[idx..], 0);
        }

        pub fn lockPointers(self: *Self) void {
            self.table.lockPointers();
        }

        pub fn unlockPointers(self: *Self) void {
            self.table.unlockPointers();
        }
    };
}
