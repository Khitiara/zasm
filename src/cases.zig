const Tokenizer = @import("parse/Tokenizer.zig");
const std = @import("std");
const testing = std.testing;
const io = std.io;

pub fn tokenizer_test_case(comptime name: []const u8) !void {
    const a = @embedFile(std.fmt.comptimePrint("cases/{s}.asm", .{name}));
    const expected = @embedFile(std.fmt.comptimePrint("cases/{s}.expected.txt", .{name}));
    const out = try std.fs.cwd().createFile(std.fmt.comptimePrint("cases/{s}.actual.txt", .{name}), .{});
    defer out.close();
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var multi = io.multiWriter(.{ out.writer(), buf.writer() });
    const writer = multi.writer();

    var tokenizer = Tokenizer.init(a);
    while (true) {
        const t = tokenizer.next();
        try tokenizer.dump(&t, writer);
        if(t.tag == .eof) break;
    }
    try testing.expectEqualStrings(expected, buf.items);
}

test "simple tokenizing" {
    try tokenizer_test_case("tokenizer_simple");
}