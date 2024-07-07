const std = @import("std");
const swap = @import("../util/utils.zig").swap;

const Tokenizer = @This();

pub const Token = struct {
    tag: Tag,
    start: usize,
    end: usize,

    pub const keywords = std.StaticStringMap(Tag).initComptime(.{
        .{ "db", .keyword_db },
        .{ "dw", .keyword_dw },
        .{ "dd", .keyword_dd },
        .{ "dq", .keyword_dq },
        .{ "do", .keyword_do },
        .{ "dt", .keyword_dt },
        .{ "dy", .keyword_dy },
        .{ "dz", .keyword_dz },
        .{ "resb", .keyword_resb },
        .{ "resw", .keyword_resw },
        .{ "resd", .keyword_resd },
        .{ "resq", .keyword_resq },
        .{ "reso", .keyword_reso },
        .{ "rest", .keyword_rest },
        .{ "resy", .keyword_resy },
        .{ "resz", .keyword_resz },
        .{ "times", .keyword_times },
        .{ "embed", .keyword_embed },
        .{ "equ", .keyword_equ },
        .{ "seg", .keyword_seg },
        .{ "wrt", .keyword_wrt },
    });

    pub const Tag = enum {
        invalid,
        identifier,
        string_literal,
        eof,
        comma,
        semicolon,
        number_literal,
        l_square_bracket,
        r_square_bracket,
        l_parenthesis,
        r_parenthesis,
        colon,
        plus,
        minus,
        double_l_angle_bracket,
        double_r_angle_bracket,
        pipe,
        caret,
        ampersand,
        asterisk,
        slash,
        slash_slash,
        percent,
        percent_percent,
        tilde,
        bang,
        dollar,
        dollar_dollar,
        keyword_db,
        keyword_dw,
        keyword_dd,
        keyword_dq,
        keyword_do,
        keyword_dt,
        keyword_dy,
        keyword_dz,
        keyword_resb,
        keyword_resw,
        keyword_resd,
        keyword_resq,
        keyword_reso,
        keyword_rest,
        keyword_resy,
        keyword_resz,
        keyword_times,
        keyword_embed,
        keyword_equ,
        keyword_seg,
        keyword_wrt,
        newline,
    };

    pub fn lexeme(tag: Tag) ?[]const u8 {
        return switch (tag) {
            .invalid, .identifier, .eof, .string_literal, .number_literal, .newline => null,
            .comma => ",",
            .l_square_bracket => "[",
            .r_square_bracket => "]",
            .l_parenthesis => "(",
            .r_parenthesis => ")",
            .colon => ":",
            .plus => "+",
            .minus => "-",
            .semicolon => ";",
            .double_l_angle_bracket => "<<",
            .double_r_angle_bracket => ">>",
            .pipe => "|",
            .caret => "^",
            .ampersand => "&",
            .asterisk => "*",
            .slash => "/",
            .slash_slash => "//",
            .percent => "%",
            .percent_percent => "%%",
            .tilde => "~",
            .bang => "!",
            .dollar => "$",
            .dollar_dollar => "$$",
            .keyword_db => "db",
            .keyword_dw => "dw",
            .keyword_dd => "dd",
            .keyword_dq => "dq",
            .keyword_do => "do",
            .keyword_dt => "dt",
            .keyword_dy => "dy",
            .keyword_dz => "dz",
            .keyword_resb => "resb",
            .keyword_resw => "resw",
            .keyword_resd => "resd",
            .keyword_resq => "resq",
            .keyword_reso => "reso",
            .keyword_rest => "rest",
            .keyword_resy => "resy",
            .keyword_resz => "resz",
            .keyword_times => "times",
            .keyword_embed => "embed",
            .keyword_equ => "equ",
            .keyword_seg => "seg",
            .keyword_wrt => "wrt",
        };
    }
};

buffer: [:0]const u8,
index: usize,
pending_invalid_token: ?Token,

/// For debugging purposes
pub fn dump(self: *Tokenizer, token: *const Token, writer: anytype) !void {
    try writer.print("{s} \"{s}\"\n", .{ @tagName(token.tag), self.buffer[token.start..token.end] });
}

pub fn init(buffer: [:0]const u8) Tokenizer {
    // Skip the UTF-8 BOM if present
    const src_start: usize = if (std.mem.startsWith(u8, buffer, "\xEF\xBB\xBF")) 3 else 0;
    return Tokenizer{
        .buffer = buffer,
        .index = src_start,
        .pending_invalid_token = null,
    };
}

const State = enum {
    start,
    end,
    string_literal,
    identifier,
    comment_or_line_feed,
    line_continue,
    number,
    dollar,
    doubled_symbol,
};

fn char_to_tag(char: u8) ?Token.Tag {
    inline for (std.enums.values(Token.Tag)) |t| {
        if (Token.lexeme(t)) |lexeme| {
            if (lexeme.len > 0 and char == lexeme[0]) {
                return t;
            }
        }
    }
    return null;
}

pub fn next(self: *Tokenizer) Token {
    if (swap(&self.pending_invalid_token, null)) |token| {
        return token;
    }

    var state: State = .start;
    var result = Token{
        .tag = .eof,
        .start = self.index,
        .end = undefined,
    };
    var saved_char: u8 = undefined;
    while (true) : (self.index += 1) {
        const c = self.buffer[self.index];
        switch (state) {
            .end => break,
            .start => switch (c) {
                0 => {
                    if (self.index != self.buffer.len) {
                        result.tag = .invalid;
                        result.start = self.index;
                        result.end = self.index;
                    } else {
                        self.index -= 1;
                    }
                    state = .end;
                },
                ' ', '\t' => {
                    result.start = self.index + 1;
                },
                '\r', ';' => { // semi = comment, and the newline state will go until it hits a line feed
                    state = .comment_or_line_feed;
                    result.tag = .newline;
                },
                '\n' => {
                    result.tag = .newline;
                    state = .end;
                },
                '\\' => {
                    state = .line_continue;
                },
                '"', '\'' => {
                    saved_char = c;
                    state = .string_literal;
                    result.tag = .string_literal;
                },
                'a'...'z', 'A'...'Z', '.', '_', '?' => {
                    state = .identifier;
                    result.tag = .identifier;
                },
                '%', '<', '>', '/' => {
                    saved_char = c;
                    state = .doubled_symbol;
                },
                inline '!', ':', ',', '|', '&', '*', '^', '+', '(', ')', '[', ']' => |c2| {
                    result.tag = comptime char_to_tag(c2) orelse @panic("");
                    state = .end;
                },
                '-' => {
                    result.tag = .minus;
                    state = .end;
                },
                '0'...'9' => {
                    state = .number;
                    result.tag = .number_literal;
                },
                '$' => {
                    state = .dollar;
                },
                else => {
                    result.tag = .invalid;
                    self.index -= 1;
                    state = .end;
                },
            },
            .dollar => switch (c) {
                '$' => {
                    result.tag = .dollar_dollar;
                    state = .end;
                },
                '0'...'9' => {
                    result.tag = .number_literal;
                    state = .number;
                },
                else => {
                    result.tag = .dollar;
                    self.index -= 1;
                    state = .end;
                },
            },
            .comment_or_line_feed => switch (c) {
                '\n' => {
                    result.tag = .newline;
                    state = .end;
                },
                else => {},
            },
            .line_continue => switch (c) {
                '\n' => {
                    result.start = self.index + 1;
                    state = .start;
                },
                else => {
                    result.start = self.index + 1;
                },
            },
            .identifier => switch (c) {
                'a'...'z', 'A'...'Z', '_', '0'...'9', '$', '?', '.', '~', '#', '@' => {},
                else => {
                    if (Token.keywords.get(self.buffer[result.start..self.index])) |tag| {
                        result.tag = tag;
                    }
                    self.index -= 1;
                    state = .end;
                },
            },
            .doubled_symbol => if (c == saved_char) {
                switch (c) {
                    '<' => {
                        result.tag = .double_l_angle_bracket;
                    },
                    '>' => {
                        result.tag = .double_r_angle_bracket;
                    },
                    '%' => {
                        result.tag = .percent_percent;
                    },
                    '/' => {
                        result.tag = .slash_slash;
                    },
                    else => unreachable,
                }
                state = .end;
            } else {
                switch (saved_char) {
                    '%' => {
                        result.tag = .percent;
                    },
                    '/' => {
                        result.tag = .slash;
                    },
                    else => {
                        result.tag = .invalid;
                    },
                }
                self.index -= 1;
                state = .end;
            },
            .number => switch (c) {
                '0'...'9', 'a'...'f', 'A'...'F', 'x', '_', 'o', '+', '-' => {},
                else => {
                    self.index -= 1;
                    state = .end;
                },
            },
            .string_literal => if (c == saved_char) {
                self.index -= 1;
                state = .end;
            } else switch (c) {
                '\\' => {
                    self.index += 1;
                },
                '\n' => {
                    result.tag = .invalid;
                    state = .end;
                },
                else => {},
            },
        }
    }
    if (result.tag == .eof) {
        if (swap(&self.pending_invalid_token, null)) |token| {
            return token;
        }
        result.start = self.index;
    }
    result.end = self.index;
    if (result.tag == .newline) {
        result.end -= 1;
        if (self.buffer[result.end - 1] == '\r') {
            result.end -= 1;
        }
    }
    return result;
}
