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

fn nested_runtime() -> &'static str {
    "nested-protocol"
}

fn macro_owned() {
    println!("{}", "macro-protocol-name");
    println!("{}", "mixed-protocol");
    println!("a larger nested-protocol diagnostic");
}

fn benchmark() {
    let first_start = std::time::Instant::now();
    std::hint::black_box(internal_state());
    let first_ns = first_start.elapsed().as_nanos();

    let repeat_start = std::time::Instant::now();
    for _ in 0..100_000 {
        std::hint::black_box(internal_state());
    }
    let repeat_total_ns = repeat_start.elapsed().as_nanos();
    println!("first_ns={first_ns} repeat_total_ns={repeat_total_ns}");
}

fn main() {
    if std::env::args().any(|arg| arg.len() == 7 && arg.starts_with('-')) {
        benchmark();
        return;
    }

    let state = internal_state();
    let (a, b) = repeated_values();
    let mixed = mixed_runtime();
    let nested = nested_runtime();
    let compile_time = COMPILE_TIME_PROTOCOL;

    // Keep the calls themselves out of macro token trees so the symbol rename
    // fixture and the string fixture test independent things.
    let line = format!("{state}:{a}:{b}:{mixed}:{nested}:{compile_time}");
    println!("{line}");
    macro_owned();
}
