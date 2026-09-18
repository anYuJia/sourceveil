const COMPILE_TIME_PROTOCOL: &str = "compile-time-protocol";

fn internal_state() -> &'static str {
    "license-check"
}

fn repeated_values() -> (&'static str, &'static str) {
    ("device-validation", "device-validation")
}

fn macro_owned() {
    println!("{}", "macro-protocol-name");
}

fn main() {
    let state = internal_state();
    let (a, b) = repeated_values();

    // Keep the calls themselves out of macro token trees so the symbol rename
    // fixture and the string fixture test independent things.
    let line = format!("{state}:{a}:{b}:{COMPILE_TIME_PROTOCOL}");
    println!("{line}");
    macro_owned();
}
