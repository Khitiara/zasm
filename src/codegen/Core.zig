const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = @import("../parse/Ast.zig");
const StringTable = @import("../util/string_table.zig").StringTable;
const Backend = @import("Backend.zig");
const assert = std.debug.assert;
const number_literal = @import("../parse/number_literal.zig");
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

pub const DataSize = enum {
    /// 8 bits/1 byte
    byte,
    /// 16 bits/2 bytes
    word,
    /// 32 bits/4 bytes
    dword,
    /// 64 bits/8 bytes
    qword,
    /// 80 bits/10 bytes
    tword,
    /// 128 bits/16 bytes
    oword,
    /// 256 bits/32 bytes
    yword,
    /// 512 bits/64 bytes
    zword,
    /// unknown size, resolve to smallest possible
    unknown,

    pub inline fn bits(sz: DataSize) u16 {
        return switch (sz) {
            .byte => 8,
            .word => 16,
            .dword => 32,
            .qword => 64,
            .tword => 80,
            .oword => 128,
            .yword => 256,
            .zword => 512,
            .unknown => undefined,
        };
    }
};

pub const DataReservation = struct {
    size: DataSize,
    count: u32,
    items: []const u32,
};

pub const ByteString = struct {
    index: u32,
    length: u32,
};

gpa: Allocator,
arena: Allocator,
address: u64 = 0,
tree: *const Ast,
strings: Strings,
backend: *Backend,
last_section_name: u32,
last_section_addr: u64,
extra: ArrayListUnmanaged(u32) = .{},
errors: ArrayListUnmanaged(Error) = .{},
label_srclocs: std.AutoHashMapUnmanaged(Strings.NullTerminatedString, u32) = .{},
ident_targets: std.AutoHashMapUnmanaged(Strings.NullTerminatedString, IdentTarget) = .{},
bytestrings: ArrayListUnmanaged(u8) = .{},
resolved_exprs: std.AutoHashMapUnmanaged(u32, u32) = .{},
scratch: ArrayListUnmanaged(u32) = .{},

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

pub const BuildError = error{CompilerError} || Allocator.Error;

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
) BuildError!noreturn {
    @setCold(true);
    return core.failNodeNotes(node, format, args, &[0]u32{});
}

pub fn failNodeNotes(
    core: *Core,
    node: u32,
    comptime format: []const u8,
    args: anytype,
    notes: []const u8,
) BuildError!noreturn {
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

fn failTok(
    core: *Core,
    token: Ast.TokenIndex,
    comptime format: []const u8,
    args: anytype,
) BuildError!noreturn {
    return core.failTokNotes(token, format, args, &[0]u32{});
}

fn appendErrorTok(
    core: *Core,
    token: Ast.TokenIndex,
    comptime format: []const u8,
    args: anytype,
) !void {
    try core.appendErrorTokNotesOff(token, 0, format, args, &[0]u32{});
}

fn failTokNotes(
    core: *Core,
    token: Ast.TokenIndex,
    comptime format: []const u8,
    args: anytype,
    notes: []const u32,
) BuildError!noreturn {
    try appendErrorTokNotesOff(core, token, 0, format, args, notes);
    return error.AnalysisFail;
}

fn appendErrorTokNotes(
    core: *Core,
    token: Ast.TokenIndex,
    comptime format: []const u8,
    args: anytype,
    notes: []const u32,
) !void {
    return appendErrorTokNotesOff(core, token, 0, format, args, notes);
}

/// Same as `fail`, except given a token plus an offset from its starting byte
/// offset.
fn failOff(
    core: *Core,
    token: u32,
    byte_offset: u32,
    comptime format: []const u8,
    args: anytype,
) BuildError {
    try appendErrorTokNotesOff(core, token, byte_offset, format, args, &.{});
    return error.AnalysisFail;
}

fn appendErrorTokNotesOff(
    core: *Core,
    token: u32,
    byte_offset: u32,
    comptime format: []const u8,
    args: anytype,
    notes: []const u32,
) !void {
    @setCold(true);
    const gpa = core.gpa;
    const string_bytes = &core.string_bytes;
    const msg: Strings.NullTerminatedString = @enumFromInt(string_bytes.items.len);
    try string_bytes.writer(gpa).print(format ++ "\x00", args);
    const notes_index: u32 = if (notes.len != 0) blk: {
        const notes_start = core.extra.items.len;
        try core.extra.ensureTotalCapacity(gpa, notes_start + 1 + notes.len);
        core.extra.appendAssumeCapacity(@intCast(notes.len));
        core.extra.appendSliceAssumeCapacity(notes);
        break :blk @intCast(notes_start);
    } else 0;
    try core.compile_errors.append(gpa, .{
        .msg = msg,
        .node = 0,
        .token = token,
        .byte_offset = byte_offset,
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

fn genResolveIdent(core: *Core, node: u32) BuildError!?IdentTarget {
    assert(core.tree.nodes.items(.tag)[node] == .identifier);
    const identifier = core.tree.nodes.items(.main_token)[node];
    const tokenSlice = core.tree.tokenSlice(identifier);
    const entry = if (tokenSlice[0] == '.') blk: {
        const glob = core.strings.get_string_for_index(core.last_section_name);
        break :blk identToStringFmt(core, "{s}.{s}", .{ glob, tokenSlice });
    } else try core.identToString(identifier);

    return core.ident_targets.get(entry.idx);
}

fn firstPassGenLabel(core: *Core, node: u32) BuildError!void {
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

fn firstPassGenEqu(core: *Core, node: u32) BuildError!void {
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

fn sizeByKeyword(tag: Ast.Token.Tag) ?DataSize {
    return switch (tag) {
        .keyword_db, .keyword_resb => .byte,
        .keyword_dw, .keyword_resw => .word,
        .keyword_dd, .keyword_resd => .dword,
        .keyword_dq, .keyword_resq => .qword,
        .keyword_dt, .keyword_rest => .tword,
        .keyword_do, .keyword_reso => .oword,
        .keyword_dy, .keyword_resy => .yword,
        .keyword_dz, .keyword_resz => .zword,
        else => unreachable,
    };
}

pub fn ExprType(comptime size: DataSize) type {
    return union(enum) {
        int: if (size == .unknown or size.bits() > 64) std.math.big.int.Managed else std.meta.Int(.unsigned, size.bits()),
        float: if (size == .unknown or size.bits() > 128) f128 else if (size == .byte) f16 else std.meta.Float(size.bits()),
        bytes: u32,
    };
}

fn addByteString(core: *Core, idx: u32, end: u32) Allocator.Error!u32 {
    const string_bytes = &core.strings.bytes;
    const key = string_bytes.items[idx..end];

    if (std.mem.indexOfScalar(u8, key, 0)) |_| return core.addExtra(ByteString{
        .index = @enumFromInt(idx),
        .len = @intCast(key.len),
    });

    const gop = try core.strings.table.getOrPutContextAdapted(core.gpa, key, std.hash_map.StringIndexAdapter{
        .bytes = &string_bytes,
    }, .{
        .bytes = &string_bytes,
    });
    if (gop.found_existing) {
        string_bytes.shrinkRetainingCapacity(idx);
        return core.addExtra(ByteString{
            .index = @enumFromInt(idx),
            .len = @intCast(key.len),
        });
    }
}

const Sign = enum { negative, positive };

fn resolveExprToByteString(core: *Core, expr_node: u32, comptime size: DataSize) BuildError!u32 {
    const gop = try core.resolved_exprs.getOrPut(core.gpa, expr_node);
    if (!gop.found_existing) {
        const expr = try resolveExpr(core, expr_node, .unknown);
        switch (expr) {
            .bytes => |idx| gop.value_ptr.* = idx,
            .int => |mut| {
                defer mut.deinit();

                const bits = if (size == .unknown) mut.bitCountTwosComp() else size.bits();
                const bytes = bits / 8;
                const string_bytes = &core.strings.bytes;
                const idx = string_bytes.items.len;
                try string_bytes.ensureUnusedCapacity(core.gpa, bytes);
                string_bytes.items.len += bytes;
                mut.toConst().writePackedTwosComplement(string_bytes, idx * 8, bits, core.backend.endian);
                gop.value_ptr.* = try core.addByteString(idx, string_bytes.items.len);
            },
            .float => |f| {
                const string_bytes = &core.strings.bytes;
                const idx = string_bytes.items.len;
                try string_bytes.ensureUnusedCapacity(core.gpa, size.bits() / 8);
                const I = std.meta.Int(.unsigned, size.bits());
                string_bytes.fixedWriter().writeInt(I, @bitCast(f), core.backend.endian) catch unreachable;
                gop.value_ptr.* = try core.addByteString(idx, string_bytes.items.len);
            },
        }
    }
    return gop.value_ptr.*;
}

/// resolve an expression by AST node index. call during first pass only for critical expressions
fn resolveExpr(core: *Core, expr_node: u32, comptime size: DataSize) BuildError!ExprType(size) {
    switch (core.tree.nodes.items(.tag)[expr_node]) {
        .number => {
            const tok = core.tree.nodes.items(.main_token)[expr_node];
            assert(core.tree.tokens.items(.tag)[tok] == .number_literal);
            const slice = core.tree.tokenSlice(tok);
            var i: u8 = 0;
            const sign: Sign = switch (slice[0]) {
                '-' => b: {
                    i += 1;
                    break :b .negative;
                },
                '+' => b: {
                    i += 1;
                    break :b .positive;
                },
                else => .positive,
            };

            return switch (number_literal.parseNumberLiteral(slice[i..])) {
                .int => |num| if (sign == .negative) .{ .int = -num } else .{ .int = num },
                .big_int => |big| b: {
                    const gpa = core.gpa;
                    var mut = try std.math.big.int.Managed.init(gpa);
                    defer mut.deinit();
                    const len = slice.len - big.skip_end;
                    mut.setString(@intFromEnum(big.base), slice[i + big.skip_start .. len]) catch |err| switch (err) {
                        error.InvalidCharacter => unreachable, // caught in `parseNumberLiteral`
                        error.InvalidBase => unreachable, // we only pass 16, 10, 8, 2, see above
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                    if (size.bits() > 64) {
                        break :b .{ .int = mut };
                    } else {
                        break :b .{ .int = mut.to(std.meta.Int(if (sign == .negative) .signed else .unsigned, size.bits())) };
                    }
                },
                .float => b: {
                    const unsigned_float_number = std.fmt.parseFloat(f128, slice) catch |err| switch (err) {
                        error.InvalidCharacter => unreachable, // validated by tokenizer
                    };
                    const float_number = switch (sign) {
                        .negative => -unsigned_float_number,
                        .positive => unsigned_float_number,
                    };

                    @setFloatMode(.strict);
                    break :b .{ .float = @floatCast(float_number) };
                },
                .failure => |err| try core.failWithNumberError(err, tok, slice),
            };
        },
        .string => {
            const tok = core.tree.nodes.items(.main_token)[expr_node];
            assert(core.tree.tokens.items(.tag)[tok] == .string_literal);
            const slice = core.tree.tokenSlice(tok);

            const string_bytes = &core.strings.bytes;
            const idx = string_bytes.items.len;
            errdefer string_bytes.shrinkRetainingCapacity(idx);
            switch (try @import("../parse/string_literal.zig").parseWrite(string_bytes.writer(core.gpa), slice)) {
                .success => {},
                .failure => |f| return failWithStrLitError(core, f, tok, slice, 0),
            }
            return try core.addByteString(idx, string_bytes.items.len);
        },
        else => {
            // TODO expressions
            return undefined;
        },
    }
}

fn failWithNumberError(core: *Core, err: number_literal.Error, token: u32, bytes: []const u8) BuildError {
    const is_float = std.mem.indexOfScalar(u8, bytes, '.') != null;
    switch (err) {
        .leading_zero => if (is_float) {
            return core.failTok(token, "number '{s}' has leading zero", .{bytes});
        } else {
            return core.failTokNotes(token, "number '{s}' has leading zero", .{bytes}, &.{
                try core.errNoteTok(token, "use '0o' prefix for octal literals", .{}),
            });
        },
        .digit_after_base => return core.failTok(token, "expected a digit after base prefix", .{}),
        .upper_case_base => |i| return core.failOff(token, @intCast(i), "base prefix must be lowercase", .{}),
        .invalid_float_base => |i| return core.failOff(token, @intCast(i), "invalid base for float literal", .{}),
        .repeated_underscore => |i| return core.failOff(token, @intCast(i), "repeated digit separator", .{}),
        .invalid_underscore_after_special => |i| return core.failOff(token, @intCast(i), "expected digit before digit separator", .{}),
        .invalid_digit => |info| return core.failOff(token, @intCast(info.i), "invalid digit '{c}' for {s} base", .{ bytes[info.i], @tagName(info.base) }),
        .invalid_digit_exponent => |i| return core.failOff(token, @intCast(i), "invalid digit '{c}' in exponent", .{bytes[i]}),
        .duplicate_exponent => |i| return core.failOff(token, @intCast(i), "duplicate exponent", .{}),
        .exponent_after_underscore => |i| return core.failOff(token, @intCast(i), "expected digit before exponent", .{}),
        .special_after_underscore => |i| return core.failOff(token, @intCast(i), "expected digit before '{c}'", .{bytes[i]}),
        .trailing_special => |i| return core.failOff(token, @intCast(i), "expected digit after '{c}'", .{bytes[i - 1]}),
        .trailing_underscore => |i| return core.failOff(token, @intCast(i), "trailing digit separator", .{}),
        .duplicate_period => unreachable, // Validated by tokenizer
        .invalid_character => unreachable, // Validated by tokenizer
        .invalid_exponent_sign => |i| {
            assert(bytes.len >= 2 and bytes[0] == '0' and bytes[1] == 'x'); // Validated by tokenizer
            return core.failOff(token, @intCast(i), "sign '{c}' cannot follow digit '{c}' in hex base", .{ bytes[i], bytes[i - 1] });
        },
    }
}

fn failWithStrLitError(core: *Core, err: std.zig.string_literal.Error, token: u32, bytes: []const u8, offset: u32) BuildError {
    const raw_string = bytes[offset..];
    switch (err) {
        .invalid_escape_character => |bad_index| {
            return core.failOff(
                token,
                offset + @as(u32, @intCast(bad_index)),
                "invalid escape character: '{c}'",
                .{raw_string[bad_index]},
            );
        },
        .expected_hex_digit => |bad_index| {
            return core.failOff(
                token,
                offset + @as(u32, @intCast(bad_index)),
                "expected hex digit, found '{c}'",
                .{raw_string[bad_index]},
            );
        },
        .empty_unicode_escape_sequence => |bad_index| {
            return core.failOff(
                token,
                offset + @as(u32, @intCast(bad_index)),
                "empty unicode escape sequence",
                .{},
            );
        },
        .expected_hex_digit_or_rbrace => |bad_index| {
            return core.failOff(
                token,
                offset + @as(u32, @intCast(bad_index)),
                "expected hex digit or '}}', found '{c}'",
                .{raw_string[bad_index]},
            );
        },
        .invalid_unicode_codepoint => |bad_index| {
            return core.failOff(
                token,
                offset + @as(u32, @intCast(bad_index)),
                "unicode escape does not correspond to a valid unicode scalar value",
                .{},
            );
        },
        .expected_lbrace => |bad_index| {
            return core.failOff(
                token,
                offset + @as(u32, @intCast(bad_index)),
                "expected '{{', found '{c}",
                .{raw_string[bad_index]},
            );
        },
        .expected_rbrace => |bad_index| {
            return core.failOff(
                token,
                offset + @as(u32, @intCast(bad_index)),
                "expected '}}', found '{c}",
                .{raw_string[bad_index]},
            );
        },
        .expected_single_quote => |bad_index| {
            return core.failOff(
                token,
                offset + @as(u32, @intCast(bad_index)),
                "expected single quote ('), found '{c}",
                .{raw_string[bad_index]},
            );
        },
        .invalid_character => |bad_index| {
            return core.failOff(
                token,
                offset + @as(u32, @intCast(bad_index)),
                "invalid byte in string or character literal: '{c}'",
                .{raw_string[bad_index]},
            );
        },
    }
}

fn genDataOrSpace(core: *Core, node: u32) BuildError!void {
    const idx = core.scratch.items.len;
    defer core.scratch.shrinkRetainingCapacity(idx);
    try core.scratch.ensureUnusedCapacity(core.gpa, 2);
    const n = core.tree.nodes.get(node);
    const count: u32 = switch (n.tag) {
        .data_two => blk: {
            core.scratch.appendAssumeCapacity(n.data.lhs);
            if (n.data.rhs != 0) {
                core.scratch.append(n.data.rhs);
            }
            break :blk core.scratch.items.len;
        },
        .data => blk: {
            core.scratch.appendAssumeCapacity(n.data.lhs);
            const range = core.tree.extraData(n.data.rhs, Ast.Node.SubRange);
            core.scratch.appendSlice(core.tree.extra_data[range.start..range.end]);
            break :blk core.scratch.items.len;
        },
        .reserved_space => blk: {
            const count = try core.resolveExpr(n.data.lhs, .unknown);
            switch (count) {
                .int => |i| break :blk @intCast(i),
                else => try core.failNode(n.data.lhs, "Expected integer reserved space count", .{}),
            }
        },
        else => try core.failNode(node, "Expected data or reserved space", .{}),
    };
    core.address += core.backend.emit_data_fn(core.backend, core, DataReservation{
        .size = sizeByKeyword(core.tree.tokens.items(.tag)[n.main_token]),
        .count = count,
        .items = core.scratch.items[idx..],
    }) catch |err| switch (err) {
        error.OutOfMemory, error.CompileError => return err,
        else => try core.failNodeNotes(
            node,
            "Unexpected error emitting data or reservation {s}",
            .{@errorName(err)},
            &.{
                core.errNoteNode(0, "Error Return Trace {?}", .{@errorReturnTrace()}),
            },
        ),
    };
}
