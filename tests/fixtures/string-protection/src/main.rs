const COMPILE_TIME_PROTOCOL: &str = "compile-time-protocol";

fn internal_state() -> &'static str {
    "license-check"
}

fn repeated_values() -> (&'static str, &'static str) {
    ("device-validation", "device-validation")
}

fn mixed_runtime() -> &'static str {
    "mixed-protocol"
}

fn macro_owned() {
    println!("{}", "macro-protocol-name");
    println!("{}", "mixed-protocol");
}

fn main() {
    let state = internal_state();
    let (a, b) = repeated_values();
    let mixed = mixed_runtime();
    let compile_time = COMPILE_TIME_PROTOCOL;

    // Keep the calls themselves out of macro token trees so the symbol rename
    // fixture and the string fixture test independent things.
    let line = format!("{state}:{a}:{b}:{mixed}:{compile_time}");
    println!("{line}");
    macro_owned();
}
