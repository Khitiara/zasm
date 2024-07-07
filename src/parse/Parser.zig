const std = @import("std");
const Tokenizer = @import("Tokenizer.zig");
const Token = Tokenizer.Token;
const Ast = @import("Ast.zig");
const Allocator = std.mem.Allocator;
const swap = @import("../util/utils.zig").swap;
const Node = Ast.Node;
const assert = std.debug.assert;

pub const Error = error{ParseError} || Allocator.Error;

gpa: Allocator,
source: [:0]const u8,
token_tags: []const Token.Tag,
token_starts: []const usize,
token_ends: []const usize,
tok_index: u32,

errors: std.ArrayListUnmanaged(Ast.Error),
nodes: Ast.NodeList,
extra_data: std.ArrayListUnmanaged(u32),
scratch: std.ArrayListUnmanaged(u32),

const Parser = @This();

const Instructions = struct {
    len: usize,
    lhs: Node.Index,
    rhs: Node.Index,

    fn toSpan(self: Instructions, p: *Parser) !Node.SubRange {
        if (self.len <= 2) {
            const nodes = [2]u32{ self.lhs, self.rhs };
            return p.listToSpan(nodes[0..self.len]);
        } else {
            return Node.SubRange{ .start = self.lhs, .end = self.rhs };
        }
    }
};

fn fail(p: *Parser, tag: Ast.Error.Tag) Error {
    @setCold(true);
    return p.failMsg(.{ .tag = tag, .token = p.tok_i });
}

fn failExpected(p: *Parser, expected_token: Token.Tag) Error {
    @setCold(true);
    return p.failMsg(.{
        .tag = .expected_token,
        .token = p.tok_i,
        .extra = .{ .expected_tag = expected_token },
    });
}

fn failMsg(p: *Parser, msg: Ast.Error) Error {
    @setCold(true);
    try p.warnMsg(msg);
    return error.ParseError;
}

fn warn(p: *Parser, tag: Ast.Error.Tag) error{OutOfMemory}!void {
    @setCold(true);
    return p.warnMsg(.{ .tag = tag, .token = p.tok_index });
}

fn warnExpected(p: *Parser, expected_token: Token.Tag) error{OutOfMemory}!void {
    @setCold(true);
    return p.warnMsg(.{
        .tag = .expected_token,
        .token = p.tok_i,
        .extra = .{ .expected_tag = expected_token },
    });
}

fn warnMsg(p: *Parser, msg: Ast.Error) error{OutOfMemory}!void {
    @setCold(true);
    if (msg.token != 0 and !p.tokensOnSameLine(msg.token - 1, msg.token)) {
        var copy = msg;
        copy.token_is_prev = true;
        copy.token -= 1;
        return p.errors.append(p.gpa, copy);
    }
    try p.errors.append(p.gpa, msg);
}

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8) !Ast {
    var tokens = Ast.TokenList{};
    defer tokens.deinit(gpa);

    var tokenizer = Tokenizer.init(source);
    while (true) {
        const token = tokenizer.next();
        try tokens.append(gpa, token);
        if (token.tag == .eof) break;
    }

    var parser: Parser = .{
        .source = source,
        .gpa = gpa,
        .token_tags = tokens.items(.tag),
        .token_starts = tokens.items(.start),
        .token_ends = tokens.items(.end),
        .tok_index = 0,
        .nodes = .{},
        .extra_data = .{},
        .scratch = .{},
    };
    defer parser.nodes.deinit(gpa);
    defer parser.extra_data.deinit(gpa);
    defer parser.scratch.deinit(gpa);

    try parser.parseRoot();

    return .{
        .source = source,
        .tokens = tokens.toOwnedSlice(),
        .nodes = parser.nodes.toOwnedSlice(),
        .extra_data = try parser.extra_data.toOwnedSlice(gpa),
        .errors = try parser.errors.toOwnedSlice(gpa),
    };
}

pub fn parseRoot(p: *Parser) !void {
    try p.nodes.append(p.gpa, .{
        .tag = .root,
        .main_token = 0,
        .data = undefined,
    });

    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    while (true) {
        const node = try p.parseRootEntry();
        if (node == 0) {
            break;
        }
        try p.scratch.append(p.gpa, node);
    }

    const items = p.scratch.items[scratch_top..];
    const instrs: Instructions = switch (items.len) {
        0 => .{
            .len = 0,
            .lhs = 0,
            .rhs = 0,
        },
        1 => .{
            .len = 1,
            .lhs = items[0],
            .rhs = 0,
        },
        2 => .{
            .len = 2,
            .lhs = items[0],
            .rhs = items[1],
        },
        else => {
            const span = try p.listToSpan(items);
            return .{
                .len = items.len,
                .lhs = span.start,
                .rhs = span.end,
            };
        },
    };

    const root = try instrs.toSpan(p);
    if (p.token_tags[p.tok_index] != .eof) {
        try p.warnExpected(.eof);
    }
    p.nodes.items(.data)[0] = .{
        .lhs = root.start,
        .rhs = root.end,
    };
}

fn tokensOnSameLine(p: *Parser, token1: u32, token2: u32) bool {
    return std.mem.indexOfScalar(u8, p.source[p.token_starts[token1]..p.token_starts[token2]], '\n') == null;
}

fn nextToken(p: *Parser) u32 {
    return @atomicRmw(u32, &p.tok_index, .Add, 1, .unordered);
}

fn addNode(p: *Parser, elem: Node) Allocator.Error!u32 {
    const result: u32 = @intCast(p.nodes.len);
    try p.nodes.append(p.gpa, elem);
    return result;
}

fn eatToken(p: *Parser, tag: Token.Tag) ?u32 {
    return if (p.token_tags[p.tok_index] == tag) p.nextToken() else null;
}

fn expectToken(p: *Parser, tag: Token.Tag) Error!u32 {
    if (p.token_tags[p.tok_index] != tag) {
        return p.failExpected(tag);
    }
    return p.nextToken();
}

fn parseRootEntry(p: *Parser) !u32 {
    while (p.eatToken(.newline)) |_| {}
    switch (p.token_tags[p.tok_index]) {
        .keyword_db, .keyword_dw, .keyword_dd, .keyword_dq, .keyword_do, .keyword_dt, .keyword_dy, .keyword_dz => {
            return p.expectDataExpr();
        },
        .keyword_resb, .keyword_resw, .keyword_resd, .keyword_resq, .keyword_reso, .keyword_rest, .keyword_resy, .keyword_resz => {
            return p.addNode(.{
                .tag = .reserved_space,
                .main_token = p.nextToken(),
                .data = .{
                    .lhs = try p.parseExpr(),
                    .rhs = try p.expectToken(.newline),
                },
            });
        },
        .keyword_embed => {
            return p.addNode(.{
                .tag = .embed_raw,
                .main_token = p.nextToken(),
                .data = .{
                    .lhs = p.expectToken(.string_literal),
                    .rhs = undefined,
                },
            });
        },
        .identifier => {
            if (p.token_tags[p.tok_index + 1] == .colon) {
                return p.addNode(.{
                    .tag = .label,
                    .data = .{
                        .lhs = p.nextToken(),
                        .rhs = undefined,
                    },
                    .main_token = p.nextToken(),
                });
            } else if (p.token_tags[p.tok_index + 1] == .keyword_equ) {
                const lhs = p.nextToken();
                return p.addNode(.{
                    .tag = .equ,
                    .main_token = p.nextToken(),
                    .data = .{
                        .lhs = lhs,
                        .rhs = try p.expectExpr(),
                    },
                });
            } else {
                return p.expectInstruction();
            }
        },
        .l_square_bracket => {
            return p.expectDirective();
        },
        else => {
            return 0;
        },
    }
}

fn addExtra(p: *Parser, extra: anytype) Allocator.Error!Node.Index {
    const fields = std.meta.fields(@TypeOf(extra));
    try p.extra_data.ensureUnusedCapacity(p.gpa, fields.len);
    const result = @as(u32, @intCast(p.extra_data.items.len));
    inline for (fields) |field| {
        comptime assert(field.type == u32);
        p.extra_data.appendAssumeCapacity(@field(extra, field.name));
    }
    return result;
}

fn listToSpan(p: *Parser, list: []const u32) !Node.SubRange {
    const start = p.extra_data.items.len;
    try p.extra_data.appendSlice(p.gpa, list);
    return Node.SubRange{
        .start = start,
        .end = p.extra_data.items.len,
    };
}

fn parseDirective(p: *Parser) Error!u32 {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    const lbracket = p.nextToken();
    const directive = try p.expectToken(.identifier);

    if (p.eatToken(.r_square_bracket) == null) {
        while (true) {
            const item = try p.expectPrefixExpr();
            try p.scratch.append(p.gpa, item);
            if (p.eatToken(.comma) == null) {
                _ = try p.expectToken(.r_square_bracket);
                _ = try p.expectToken(.newline);
                break;
            }
        }
    } else {
        _ = try p.expectToken(.newline);
    }
    const items = p.scratch.items[scratch_top..];
    switch (items.len) {
        0 => {
            return p.addNode(.{
                .tag = .directive_one,
                .main_token = lbracket,
                .data = .{
                    .lhs = directive,
                    .rhs = 0,
                },
            });
        },
        1 => {
            return p.addNode(.{
                .tag = .directive_one,
                .main_token = lbracket,
                .data = .{
                    .lhs = directive,
                    .rhs = items[0],
                },
            });
        },
        else => {
            return p.addNode(.{
                .tag = .directive,
                .main_token = lbracket,
                .data = .{
                    .lhs = directive,
                    .rhs = try p.addExtra(try p.listToSpan(items)),
                },
            });
        },
    }
}

fn expectDirective(p: *Parser) Error!u32 {
    const node = try p.parseDirective();
    if (node == 0) {
        return p.fail(.expected_instruction);
    } else {
        return node;
    }
}

fn parseInstruction(p: *Parser) Error!u32 {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    const instruction = p.nextToken();
    if (p.eatToken(.newline) == null) {
        while (true) {
            const item = p.expectExpr();
            try p.scratch.append(p.gpa, item);
            if (p.eatToken(.comma) == null) {
                _ = try p.expectToken(.newline);
                break;
            }
        }
    }
    const items = p.scratch.items[scratch_top..];
    switch (items.len) {
        0 => {
            return p.addNode(.{
                .tag = .instruction_two,
                .main_token = instruction,
                .data = .{
                    .lhs = 0,
                    .rhs = 0,
                },
            });
        },
        1 => {
            return p.addNode(.{
                .tag = .instruction_two,
                .main_token = instruction,
                .data = .{
                    .lhs = items[0],
                    .rhs = 0,
                },
            });
        },
        2 => {
            return p.addNode(.{
                .tag = .instruction_two,
                .main_token = instruction,
                .data = .{
                    .lhs = items[0],
                    .rhs = items[1],
                },
            });
        },
        else => {
            return p.addNode(.{
                .tag = .instruction,
                .main_token = instruction,
                .data = .{
                    .lhs = items[0],
                    .rhs = try p.addExtra(try p.listToSpan(items[1..])),
                },
            });
        },
    }
}

fn expectInstruction(p: *Parser) Error!u32 {
    const node = try p.parseInstruction();
    if (node == 0) {
        return p.fail(.expected_instruction);
    } else {
        return node;
    }
}

fn parseExpr(p: *Parser) Error!u32 {
    return p.parseExprPrecedence(0);
}

fn expectExpr(p: *Parser) Error!u32 {
    const node = try p.parseExpr();
    if (node == 0) {
        return p.fail(.expected_operand_expr);
    } else {
        return node;
    }
}

const Assoc = enum {
    left,
    none,
};
const OperInfo = struct {
    prec: i8,
    tag: Node.Tag,
    assoc: Assoc = .left,
};

const operTable = std.enums.directEnumArrayDefault(
    Token.Tag,
    OperInfo,
    .{ .prec = -1, .tag = Node.Tag.root },
    0,
    .{
        .ampersand = .{ .prec = 40, .tag = .bit_and },
        .caret = .{ .prec = 40, .tag = .bit_xor },
        .pipe = .{ .prec = 40, .tag = .bit_or },

        .angle_bracket_angle_bracket_left = .{ .prec = 50, .tag = .shl },
        .angle_bracket_angle_bracket_left_pipe = .{ .prec = 50, .tag = .shl_sat },
        .angle_bracket_angle_bracket_right = .{ .prec = 50, .tag = .shr },

        .plus = .{ .prec = 60, .tag = .add },
        .minus = .{ .prec = 60, .tag = .sub },

        .asterisk = .{ .prec = 70, .tag = .mul },
        .slash = .{ .prec = 70, .tag = .div },
        .slash_slash = .{ .prec = 70, .tag = .signed_div },
        .percent = .{ .prec = 70, .tag = .mod },
        .percent_percent = .{ .prec = 70, .tag = .signed_mod },
    },
);

fn parseExprPrecedence(p: *Parser, min_prec: i32) Error!u32 {
    // node is the perpetual LHS of binary ops
    var node = try p.parsePrefixExpr();
    if (node == 0)
        return 0;

    while (true) {
        const tok_tag = p.token_tags[p.tok_index];
        const info = operTable[@as(usize, @intCast(@intFromEnum(tok_tag)))];

        if (info.prec < min_prec) {
            break;
        }

        const tok = p.nextToken();

        // handle decreasing precedence (executes first) by recursing
        // and increasing precedence (executes later) by looping
        const rhs = p.parseExprPrecedence(min_prec + 1);
        if (rhs == 0) {
            try p.warn(.expected_expr);
            return node;
        }

        {
            const len = tok_tag.lexeme().len;
            const before = p.source[p.token_starts[tok] - 1];
            const after = p.source[p.token_starts[tok] + len];
            if (std.ascii.isWhitespace(before) != std.ascii.isWhitespace(after)) {
                try p.warnMsg(.{ .tag = .mismatched_binary_op_whitespace, .token = tok });
            }
        }

        node = try p.addNode(.{
            .tag = info.tag,
            .main_token = tok,
            .data = .{
                .lhs = node,
                .rhs = rhs,
            },
        });
    }

    return node;
}

fn parseSecondaryExpr(p: *Parser) Error!u32 {
    switch (p.token_tags[p.tok_index]) {
        .l_square_bracket => {
            const lbracket = p.nextToken();
            const expr = try p.parseExpr();
            if (expr == 0) return 0;
            const rbracket = p.expectToken(.r_square_bracket);
            return p.addNode(.{
                .tag = .lea,
                .main_token = lbracket,
                .data = .{
                    .lhs = expr,
                    .rhs = rbracket,
                },
            });
        },
        .l_parenthesis => {
            _ = p.nextToken();
            const expr = try p.parseExpr();
            if (expr == 0) return 0;
            _ = try p.expectToken(.r_parenthesis);
            return expr;
        },
        else => {
            return p.parsePrefixExpr();
        },
    }
}

fn parsePrefixExpr(p: *Parser) Error!u32 {
    const tag: Node.Tag = switch (p.token_tags[p.tok_index]) {
        .bang => .bool_not,
        .minus => .negation,
        .tilde => .bit_not,
        .keyword_seg => .seg,
        else => return p.parsePrimaryExpr(),
    };
    return p.addNode(.{
        .tag = tag,
        .main_token = p.nextToken(),
        .data = .{
            .lhs = try p.expectPrefixExpr(),
            .rhs = undefined,
        },
    });
}

fn expectPrefixExpr(p: *Parser) Error!u32 {
    const node = try p.parsePrefixExpr();
    if (node == 0) {
        return p.fail(.expected_prefix_expr);
    }
    return node;
}

fn parsePrimaryExpr(p: *Parser) Error!u32 {
    switch (p.token_tags[p.tok_index]) {
        .identifier => {
            return p.addNode(.{
                .tag = .identifier,
                .main_token = p.nextToken(),
                .data = undefined,
            });
        },
        .string_literal => {
            return p.addNode(.{
                .tag = .string,
                .main_token = p.nextToken(),
                .data = undefined,
            });
        },
        .number_literal => {
            return p.addNode(.{
                .tag = .number,
                .main_token = p.nextToken(),
                .data = undefined,
            });
        },
        .dollar => {
            return p.addNode(.{
                .tag = .current_pos,
                .main_token = p.nextToken(),
                .data = undefined,
            });
        },
        .dollar_dollar => {
            return p.addNode(.{
                .tag = .section_pos,
                .main_token = p.nextToken(),
                .data = undefined,
            });
        },
    }
}

fn expectPrimaryExpr(p: *Parser) Error!u32 {
    const node = try p.parsePrimaryExpr();
    if (node == 0) {
        return p.fail(.expected_primary_expr);
    } else {
        return node;
    }
}

fn parseDataExpr(p: *Parser) Error!u32 {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    const keyword = p.nextToken();
    while (true) {
        const item = p.expectExpr();
        try p.scratch.append(p.gpa, item);
        if (p.eatToken(.comma) == null) {
            _ = try p.expectToken(.newline);
            break;
        }
    }
    const items = p.scratch.items[scratch_top..];
    switch (items.len) {
        1 => {
            return p.addNode(.{
                .tag = .data_two,
                .main_token = keyword,
                .data = .{
                    .lhs = items[0],
                    .rhs = 0,
                },
            });
        },
        2 => {
            return p.addNode(.{
                .tag = .data_two,
                .main_token = keyword,
                .data = .{
                    .lhs = items[0],
                    .rhs = items[1],
                },
            });
        },
        else => {
            return p.addNode(.{
                .tag = .data,
                .main_token = keyword,
                .data = .{
                    .lhs = items[0],
                    .rhs = try p.addExtra(try p.listToSpan(items[1..])),
                },
            });
        },
    }
}

fn expectDataExpr(p: *Parser) Error!u32 {
    const node = try p.parseDataExpr();
    if (node == 0) {
        return p.fail(.expected_data_expr);
    } else {
        return node;
    }
}
