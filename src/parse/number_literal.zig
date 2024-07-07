const std = @import("std");
const assert = std.debug.assert;
const utf8Decode = std.unicode.utf8Decode;
const utf8Encode = std.unicode.utf8Encode;

pub const ParseError = error{
    OutOfMemory,
    InvalidLiteral,
};

pub const Base = enum(u8) { decimal = 10, hex = 16, binary = 2, octal = 8 };
pub const FloatBase = enum(u8) { decimal = 10, hex = 16 };

pub const Result = union(enum) {
    /// Result fits if it fits in u64
    int: u64,
    /// Result is an int that doesn't fit in u64. Payload is the base, if it is
    /// not `.decimal` then the slice has a two character prefix.
    big_int: struct { base: Base, skip_start: u8, skip_end: u8 },
    /// Result is a float. Payload is the base, if it is not `.decimal` then
    /// the slice has a two character prefix.
    float: FloatBase,
    failure: Error,
};

pub const Error = union(enum) {
    /// The number has leading zeroes.
    leading_zero,
    /// Expected a digit after base prefix.
    digit_after_base,
    /// The base prefix is in uppercase.
    upper_case_base: usize,
    /// Float literal has an invalid base prefix.
    invalid_float_base: usize,
    duplicate_base: usize,
    repeated_underscore: usize,
    /// '_' digit separator after special character (+-.)
    invalid_underscore_after_special: usize,
    /// Invalid digit for the specified base.
    invalid_digit: struct { i: usize, base: Base },
    /// Invalid digit for an exponent.
    invalid_digit_exponent: usize,
    /// Float literal has multiple periods.
    duplicate_period,
    /// Float literal has multiple exponents.
    duplicate_exponent: usize,
    /// Exponent comes directly after '_' digit separator.
    exponent_after_underscore: usize,
    /// Special character (+-.) comes directly after exponent.
    special_after_underscore: usize,
    /// Number ends in special character (+-.)
    trailing_special: usize,
    /// Number ends in '_' digit separator.
    trailing_underscore: usize,
    /// Character not in [0-9a-zA-Z.+-_]
    invalid_character: usize,
    /// [+-] not immediately after [pPeE]
    invalid_exponent_sign: usize,
};

/// Parse Zig number literal accepted by fmt.parseInt, fmt.parseFloat and big_int.setString.
/// Valid for any input.
pub fn parseNumberLiteral(bytes1: []const u8) Result {
    var i: usize = 0;
    var base: u8 = 10;
    var has_base: bool = false;
    var bytes = bytes1;
    if (bytes.len >= 1 and bytes[0] == '$') {
        base = 16;
        i += 1;
        has_base = true;
    }
    if (bytes.len >= 2 and bytes[i] == '0') switch (bytes[i + 1]) {
        'b', 'y' => {
            if (has_base) {
                return .{ .failure = .{ .duplicate_base = i + 1 } };
            }
            base = 2;
            i += 2;
            has_base = true;
        },
        'o', 'q' => {
            if (has_base) {
                return .{ .failure = .{ .duplicate_base = i + 1 } };
            }
            base = 8;
            i += 2;
            has_base = true;
        },
        'x', 'h' => {
            if (has_base) {
                return .{ .failure = .{ .duplicate_base = i + 1 } };
            }
            base = 16;
            i += 2;
            has_base = true;
        },
        'd', 't' => {
            if (has_base) {
                return .{ .failure = .{ .duplicate_base = i + 1 } };
            }
            base = 10;
            i += 2;
            has_base = true;
        },
        'B', 'O', 'X' => return .{ .failure = .{ .upper_case_base = 1 } },
        else => return .{},
    };

    if ((bytes.len == 1 and bytes[0] == '$') or (bytes.len == 2 and has_base)) return .{ .failure = .digit_after_base };

    if (bytes.len >= 2) {
        switch (bytes[bytes.len - 1]) {
            'H', 'X', 'h', 'x' => {
                if (has_base) {
                    return .{ .failure = .{ .duplicate_base = bytes.len - 1 } };
                }
                base = 16;
                bytes = bytes[0 .. bytes.len - 1];
            },
            'D', 'T', 'd', 't' => {
                if (has_base) {
                    return .{ .failure = .{ .duplicate_base = bytes.len - 1 } };
                }
                base = 10;
                bytes = bytes[0 .. bytes.len - 1];
            },
            'Q', 'O', 'q', 'o' => {
                if (has_base) {
                    return .{ .failure = .{ .duplicate_base = bytes.len - 1 } };
                }
                base = 8;
                bytes = bytes[0 .. bytes.len - 1];
            },
            'B', 'Y', 'b', 'y' => {
                if (has_base) {
                    return .{ .failure = .{ .duplicate_base = bytes.len - 1 } };
                }
                base = 2;
                bytes = bytes[0 .. bytes.len - 1];
            },
        }
    }

    var x: u64 = 0;
    var overflow = false;
    var underscore = false;
    var period = false;
    var special: u8 = 0;
    var exponent = false;
    var float = false;
    while (i < bytes.len) : (i += 1) {
        const c = bytes[i];
        switch (c) {
            '_' => {
                if (i == 2 and base != 10) return .{ .failure = .{ .invalid_underscore_after_special = i } };
                if (special != 0) return .{ .failure = .{ .invalid_underscore_after_special = i } };
                if (underscore) return .{ .failure = .{ .repeated_underscore = i } };
                underscore = true;
                continue;
            },
            'e', 'E' => if (base == 10) {
                float = true;
                if (exponent) return .{ .failure = .{ .duplicate_exponent = i } };
                if (underscore) return .{ .failure = .{ .exponent_after_underscore = i } };
                special = c;
                exponent = true;
                continue;
            },
            'p', 'P' => if (base == 16) {
                float = true;
                if (exponent) return .{ .failure = .{ .duplicate_exponent = i } };
                if (underscore) return .{ .failure = .{ .exponent_after_underscore = i } };
                special = c;
                exponent = true;
                continue;
            },
            '.' => {
                float = true;
                if (base != 10 and base != 16) return .{ .failure = .{ .invalid_float_base = 2 } };
                if (period) return .{ .failure = .duplicate_period };
                period = true;
                if (underscore) return .{ .failure = .{ .special_after_underscore = i } };
                special = c;
                continue;
            },
            '+', '-' => {
                switch (special) {
                    'p', 'P' => {},
                    'e', 'E' => if (base != 10) return .{ .failure = .{ .invalid_exponent_sign = i } },
                    else => return .{ .failure = .{ .invalid_exponent_sign = i } },
                }
                special = c;
                continue;
            },
            else => {},
        }
        const digit = switch (c) {
            '0'...'9' => c - '0',
            'A'...'Z' => c - 'A' + 10,
            'a'...'z' => c - 'a' + 10,
            else => return .{ .failure = .{ .invalid_character = i } },
        };
        if (digit >= base) return .{ .failure = .{ .invalid_digit = .{ .i = i, .base = @as(Base, @enumFromInt(base)) } } };
        if (exponent and digit >= 10) return .{ .failure = .{ .invalid_digit_exponent = i } };
        underscore = false;
        special = 0;

        if (float) continue;
        if (x != 0) {
            const res = @mulWithOverflow(x, base);
            if (res[1] != 0) overflow = true;
            x = res[0];
        }
        const res = @addWithOverflow(x, digit);
        if (res[1] != 0) overflow = true;
        x = res[0];
    }
    if (underscore) return .{ .failure = .{ .trailing_underscore = bytes.len - 1 } };
    if (special != 0) return .{ .failure = .{ .trailing_special = bytes.len - 1 } };

    if (float) return .{ .float = @as(FloatBase, @enumFromInt(base)) };
    if (overflow) return .{ .big_int = @as(Base, @enumFromInt(base)) };
    return .{ .int = x };
}
