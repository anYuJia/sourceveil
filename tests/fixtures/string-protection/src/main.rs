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

fn plain_runtime_strings() -> [&'static str; 6] {
    [
        "document",
        "navigate",
        "Accept",
        "text/html,application/xhtml+xml",
        r#"webid=(\d+)"#,
        "0",
    ]
}

fn macro_owned() {
    println!("{}", "macro-protocol-name");
    println!("{}", "mixed-protocol");
    println!("a larger nested-protocol diagnostic");
}

fn formatted_runtime() -> Vec<String> {
    let name = "Ada";
    let value = 12.3456;
    let width = 8;
    let precision = 2;
    vec![
        format!("Cookie 无效: {}", 401),
        format!("indexed {0:>8} named {name}", 7),
        format!(r#"raw {{label}} {value:>width$.precision$}"#),
    ]
}

fn anyhow_runtime() -> anyhow::Result<String> {
    let detail = "request-detail";
    Ok(anyhow::anyhow!("Request failed: {}", detail).to_string())
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
    let plain = plain_runtime_strings().join("|");

    // Keep the calls themselves out of macro token trees so the symbol rename
    // fixture and the string fixture test independent things.
    let line = format!("{state}:{a}:{b}:{mixed}:{nested}:{compile_time}");
    println!("{line}");
    println!("{plain}");
    println!("{}", anyhow_runtime().unwrap());
    for line in formatted_runtime() {
        println!("{line}");
    }
    macro_owned();
}
