const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = @import("../parse/Ast.zig");
const StringTable = @import("../util/string_table.zig").StringTable;
const Backend = @import("Backend.zig");
const assert = std.debug.assert;
const ArrayListUnmanaged = std.ArrayListUnmanaged;

const Core = @This();

const Strings = StringTable(void);

const Error = struct {
    /// null terminated string index
    msg: Strings.NullTerminatedString,
    node: u32,
    /// If node is 0 then this will be populated.
    token: u32,
    /// Can be used in combination with `token`.
    byte_offset: u32,
    /// 0 or a payload index of a `Block`, each is a payload
    /// index of another `Item`.
    notes: u32,
};

pub const IdentTarget = union(enum) {
    label: u64,
    equ: u32,
};

gpa: Allocator,
arena: Allocator,
address: u64 = 0,
tree: *const Ast,
strings: Strings = .{},
backend: Backend,
last_section_name: u32,
last_section_addr: u64,
extra: ArrayListUnmanaged(u32),
errors: ArrayListUnmanaged(Error),
label_srclocs: std.AutoHashMapUnmanaged(Strings.NullTerminatedString, u32),
ident_targets: std.AutoHashMapUnmanaged(Strings.NullTerminatedString, IdentTarget),

fn addExtra(core: *Core, extra: anytype) Allocator.Error!u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    try core.extra.ensureUnusedCapacity(core.gpa, fields.len);
    return addExtraAssumeCapacity(core, extra);
}

fn addExtraAssumeCapacity(core: *Core, extra: anytype) u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    const extra_index: u32 = @intCast(core.extra.items.len);
    core.extra.items.len += fields.len;
    setExtra(core, extra_index, extra);
    return extra_index;
}

fn setExtra(core: *Core, index: usize, extra: anytype) void {
    const fields = std.meta.fields(@TypeOf(extra));
    var i = index;
    inline for (fields) |field| {
        core.extra.items[i] = switch (field.type) {
            u32 => @field(extra, field.name),

            Strings.NullTerminatedString,
            => @intFromEnum(@field(extra, field.name)),

            i32,
            => @bitCast(@field(extra, field.name)),

            else => @compileError("bad field type"),
        };
        i += 1;
    }
}

fn reserveExtra(core: *Core, size: usize) Allocator.Error!u32 {
    const extra_index: u32 = @intCast(core.extra.items.len);
    try core.extra.resize(core.gpa, extra_index + size);
    return extra_index;
}

fn errNoteTok(
    core: *Core,
    token: u32,
    comptime format: []const u8,
    args: anytype,
) Allocator.Error!u32 {
    return errNoteTokOff(core, token, 0, format, args);
}

fn errNoteTokOff(
    core: *Core,
    token: u32,
    byte_offset: u32,
    comptime format: []const u8,
    args: anytype,
) Allocator.Error!u32 {
    @setCold(true);
    const msg = fmtString(core, format, args);
    return core.addExtra(Error{
        .msg = msg,
        .node = 0,
        .token = token,
        .byte_offset = byte_offset,
        .notes = 0,
    });
}

fn errNoteNode(
    core: *Core,
    node: u32,
    comptime format: []const u8,
    args: anytype,
) Allocator.Error!u32 {
    @setCold(true);
    const msg = fmtString(core, format, args);
    return core.addExtra(Error{
        .msg = msg,
        .node = node,
        .token = 0,
        .byte_offset = 0,
        .notes = 0,
    });
}

pub fn failNode(
    core: *Core,
    node: u32,
    comptime format: []const u8,
    args: anytype,
) !void {
    @setCold(true);
    return core.failNodeNotes(node, format, args, &[0]u32{});
}

pub fn failNodeNotes(
    core: *Core,
    node: u32,
    comptime format: []const u8,
    args: anytype,
    notes: []const u8,
) !void {
    @setCold(true);
    try core.appendErrorNodeNotes(node, format, args, notes);
    return error.CompilerError;
}

pub fn appendErrorNodeNotes(
    core: *Core,
    node: u32,
    comptime format: []const u8,
    args: anytype,
    notes: []const u8,
) Allocator.Error!void {
    @setCold(true);
    const msg = try fmtString(core, format, args);
    const notes_index: u32 = if (notes.len != 0) blk: {
        const notes_start = core.extra.items.len;
        try core.extra.ensureTotalCapacity(core.gpa, notes_start + 1 + notes.len);
        core.extra.appendAssumeCapacity(@intCast(notes.len));
        core.extra.appendSliceAssumeCapacity(notes);
        break :blk @intCast(notes_start);
    } else 0;

    try core.errors.append(core.gpa, .{
        .msg = msg,
        .node = node,
        .token = 0,
        .byte_offset = 0,
        .notes = notes_index,
    });
}

fn fmtString(core: *Core, comptime format: []const u8, args: anytype) Allocator.Error!Strings.NullTerminatedString {
    const string_bytes = &core.strings.bytes;
    const idx: Strings.NullTerminatedString = @enumFromInt(string_bytes.items.len);
    try string_bytes.writer(core.gpa).print(format ++ "\x00", args);
    return idx;
}

fn identToStringFmt(core: *Core, comptime format: []const u8, args: anytype) Allocator.Error!Strings.GetOrPutResult {
    const string_bytes = &core.strings.bytes;
    const idx: Strings.NullTerminatedString = @enumFromInt(string_bytes.items.len);
    try string_bytes.writer(core.gpa).print(format ++ "\x00", args);
    const result = try core.strings.table.getOrPutContextAdapted(
        core.gpa,
        idx,
        {},
        std.hash_map.StringIndexAdapter{ .bytes = &core.strings.bytes },
        .{ .bytes = &core.strings.bytes },
    );
    if (!result.found_existing) {
        result.key_ptr.* = idx;
    } else {
        core.strings.bytes.shrinkRetainingCapacity(idx);
    }
    return .{
        .found_existing = result.found_existing,
        .idx = result.key_ptr.*,
        .value_ptr = result.value_ptr,
    };
}

fn identToString(core: *Core, token: u32) Allocator.Error!Strings.GetOrPutResult {
    assert(core.tree.tokens.items(.tag)[token] == .identifier);

    const token_str = core.tree.tokenSlice(token);
    const result = try core.strings.get_or_put(core.gpa, token_str);
    if (!result.found_existing) {
        try core.label_srclocs.put(core.gpa, result.idx, token);
    }
    return result;
}

fn genResolveIdent(core: *Core, node: u32) !?IdentTarget {
    assert(core.tree.nodes.items(.tag)[node] == .identifier);
    const identifier = core.tree.nodes.items(.main_token)[node];
    const tokenSlice = core.tree.tokenSlice(identifier);
    const entry = if (tokenSlice[0] == '.') blk: {
        const glob = core.strings.get_string_for_index(core.last_section_name);
        break :blk identToStringFmt(core, "{s}.{s}", .{ glob, tokenSlice });
    } else try core.identToString(identifier);

    return core.ident_targets.get(entry.idx);
}

fn firstPassGenLabel(core: *Core, node: u32) !void {
    assert(core.tree.nodes.items(.tag)[node] == .label);
    const identifier = core.tree.nodes.items(.data)[node].lhs;
    const global = core.tree.tokenSlice(identifier)[0] != '.';
    const entry = if (!global) blk: {
        const glob = core.strings.get_string_for_index(core.last_section_name);
        break :blk try identToStringFmt(core, "{s}.{s}", .{ glob, core.tree.tokenSlice(identifier) });
    } else try core.identToString(identifier);

    if (entry.found_existing) {
        try core.failNodeNotes(
            node,
            "Duplicate label '{s}:'",
            .{core.strings.get_string_for_index(entry.idx)},
            .{
                try core.errNoteTok(core.label_srclocs.get(entry.idx), "previous declaration here", .{}),
            },
        );
    }
    core.ident_targets.put(core.gpa, entry.idx, .{ .label = core.address });
    if (global) {
        core.last_section_name = entry.idx;
        core.last_section_addr = core.address;
    }
}

fn firstPassGenEqu(core: *Core, node: u32) !void {
    assert(core.tree.nodes.items(.tag)[node] == .equ);
    const data = core.tree.nodes.items(.data)[node];
    const identifier = data.lhs;
    const expr = data.rhs;
    const entry = try core.identToString(identifier);

    if (entry.found_existing) {
        try core.failNode(node, "Duplicate equ definition for '{s}'", core.strings.get_string_for_index(entry.idx));
    }
    core.ident_targets.put(core.gpa, entry.idx, expr);
}
