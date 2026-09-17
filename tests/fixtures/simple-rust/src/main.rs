mod auth;
mod network;

fn main() {
    let session = auth::establish_session("alice");
    println!("{}", network::describe(&session));
    println!("{}", pinned_by_comment());
    let payload = b"hello";
    println!("{}", exported_checksum(payload.as_ptr(), payload.len()));
}

/// Deliberately hidden from the rename pass: the symbol name is the C ABI.
#[no_mangle]
pub extern "C" fn exported_checksum(data: *const u8, len: usize) -> u32 {
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    internal_fold(bytes)
}

fn internal_fold(data: &[u8]) -> u32 {
    data.iter()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(*b as u32))
}

// obfuscator:keep
fn pinned_by_comment() -> &'static str {
    "keep me"
}
