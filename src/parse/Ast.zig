const std = @import("std");
const Tokenizer = @import("Tokenizer.zig");
pub const Token = Tokenizer.Token;
const Ast = @This();
const assert = std.debug.assert;

source: [:0]const u8,

tokens: TokenList.Slice,
/// The root AST node is assumed to be index 0. Since there can be no
/// references to the root node, this means 0 is available to indicate null.
nodes: NodeList.Slice,
extra_data: []u32,

errors: []const Error,

pub const Location = struct {
    line: usize,
    column: usize,
    line_start: usize,
    line_end: usize,
};

pub const TokenList = std.MultiArrayList(Token);

pub const NodeList = std.MultiArrayList(Node);

pub const Span = struct {
    start: usize,
    end: usize,
    main: usize,
};

pub fn extraData(tree: Ast, index: usize, comptime T: type) T {
    const fields = std.meta.fields(T);
    var result: T = undefined;
    inline for (fields, 0..) |field, i| {
        comptime assert(field.type == Node.Index);
        @field(result, field.name) = tree.extra_data[index + i];
    }
    return result;
}

pub fn tokenLocation(self: Ast, start_offset: usize, token_index: u32) Location {
    var loc = Location{
        .line = 0,
        .column = 0,
        .line_start = start_offset,
        .line_end = self.source.len,
    };
    const token_start = self.tokens.items(.start)[token_index];

    // Scan to by line until we go past the token start
    while (std.mem.indexOfScalarPos(u8, self.source, loc.line_start, '\n')) |i| {
        if (i >= token_start) {
            // Went past so this is the first newline after the token
            loc.line_end = i;
            break;
        }
        loc.line += 1;
        loc.line_start = i + 1;
    }

    loc.column = token_start - loc.line_start;
    return loc;
}

pub fn tokenSlice(self: Ast, index: u32) []const u8 {
    const tag = self.tokens.items(.tag)[index];
    if (tag.lexeme()) |lexeme| {
        return lexeme;
    }

    const tok = self.tokens.get(index);
    return self.source[tok.start..tok.end];
}

pub const Node = struct {
    tag: Tag,
    main_token: u32,
    data: Data,

    pub const Tag = enum(u8) {
        /// sub_list[lhs...rhs]
        root,
        /// lhs:
        label,
        /// general directive like [bits 64] or [org 0x8000] etc, [lhs rhs]
        directive_one,
        /// general directive like [bits 64] or [org 0x8000] etc, [lhs SubList(rhs)]
        directive,
        /// mov lhs, rhs, main token is the instruction itself, lhs and rhs both optional
        instruction_two,
        /// mov lhs, extra_data[rhs] is a subrange and main token is the instruction
        instruction,
        /// db ..., lhs is first value and rhs optionally points to a second value
        data_two,
        /// db ..., lhs is first value and rhs optionally points to subrange of more values
        data,
        /// resb lhs, main token is keyword
        reserved_space,
        /// embed "lhs"
        embed_raw,
        /// times lhs rhs
        times,
        /// lhs and rhs unused
        string,
        /// lhs * rhs
        mul,
        /// lhs / rhs
        div,
        /// lhs // rhs
        signed_div,
        /// lhs % rhs
        mod,
        /// lhs %% rhs
        signed_mod,
        /// lhs + rhs
        add,
        /// lhs - rhs
        sub,
        /// lhs << rhs
        shl,
        /// lhs >> rhs
        shr,
        /// lhs & rhs
        bit_and,
        /// lhs | rhs
        bit_or,
        /// ~lhs
        bit_not,
        /// seg lhs
        seg,
        /// lhs ^ rhs
        bit_xor,
        /// -lhs
        negation,
        /// !lhs
        bool_not,
        /// [lhs], main_token is open bracket
        lea,
        /// lhs and rhs unused
        current_pos,
        /// lhs and rhs unused
        section_pos,
        /// lhs and rhs unused
        identifier,
        /// lhs and rhs unused
        number_literal,
        /// lhs equ rhs
        equ,
        /// lhs : rhs (segmented addressing)
        segment,
    };

    pub const Data = struct {
        lhs: u32,
        rhs: u32,
    };

    pub const SubRange = struct {
        /// Index into sub_list.
        start: u32,
        /// Index into sub_list.
        end: u32,
    };
};

pub const Error = struct {
    tag: Tag,
    is_note: bool = false,
    /// True if `token` points to the token before the token causing an issue.
    token_is_prev: bool = false,
    token: u32,
    extra: union {
        none: void,
        expected_tag: Token.Tag,
    } = .{ .none = {} },
    pub const Tag = enum {
        expected_token,
        expected_expr,
        expected_operand_expr,
        expected_primary_expr,
        expected_data_expr,
        expected_instruction,
        mismatched_binary_op_whitespace,
    };
};
