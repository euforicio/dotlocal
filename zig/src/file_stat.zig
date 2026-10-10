//! translate-c drops the macOS SDK's asm aliases. Intel macOS requires the
//! INODE64 libc symbols for the struct stat layout in its current headers.
const builtin = @import("builtin");
const native = @import("native");
const inode64 = builtin.os.tag == .macos and builtin.cpu.arch == .x86_64;

pub const fstat = if (inode64) @"fstat$INODE64" else native.fstat;
pub const lstat = if (inode64) @"lstat$INODE64" else native.lstat;
pub const stat = if (inode64) @"stat$INODE64" else native.stat;
pub const fstatat = if (inode64) @"fstatat$INODE64" else native.fstatat;

extern "c" fn @"fstat$INODE64"(c_int, [*c]native.struct_stat) c_int;
extern "c" fn @"lstat$INODE64"([*c]const u8, [*c]native.struct_stat) c_int;
extern "c" fn @"stat$INODE64"([*c]const u8, [*c]native.struct_stat) c_int;
extern "c" fn @"fstatat$INODE64"(c_int, [*c]const u8, [*c]native.struct_stat, c_int) c_int;
