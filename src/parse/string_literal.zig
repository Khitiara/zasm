const std = @import("std");
const assert = std.debug.assert;
const parseEscapeSequence = std.zig.string_literal.parseEscapeSequence;
const utf8Encode = std.unicode.utf8Encode;

pub const Result = std.zig.string_literal.Result;

pub fn parseWrite(writer: anytype, bytes: []const u8) error{OutOfMemory}!Result {
    assert(bytes.len >= 2 and bytes[0] == bytes[bytes.len - 1] and (bytes[0] == '"' or bytes[0] == '\''));
    const quote = bytes[0];
    var index: usize = 1;
    while (true) {
        const b = bytes[index];
        if (b == quote) return .success;
        switch (b) {
            '\\' => {
                const escape_char_index = index + 1;
                const result = parseEscapeSequence(bytes, &index);
                switch (result) {
                    .success => |codepoint| {
                        if (bytes[escape_char_index] == 'u') {
                            var buf: [4]u8 = undefined;
                            const len = utf8Encode(codepoint, &buf) catch {
                                return Result{ .failure = .{ .invalid_unicode_codepoint = escape_char_index + 1 } };
                            };
                            try writer.writeAll(buf[0..len]);
                        } else {
                            try writer.writeByte(@as(u8, @intCast(codepoint)));
                        }
                    },
                    .failure => |err| return .{ .failure = err },
                }
            },
            '\n' => return .{ .failure = .{ .invalid_character = index } },
            else => {
                try writer.writeByte(b);
                index += 1;
            },
        }
    }
}
