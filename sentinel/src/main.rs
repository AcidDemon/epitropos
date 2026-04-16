use epitropos_sentinel::error::SentinelError;

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("epitropos-sentinel: {e}");
            std::process::exit(e.exit_code());
        }
    }
}

fn run() -> Result<(), SentinelError> {
    Err(SentinelError::Usage(
        "CLI dispatcher not yet wired (Track D(c) Phase 9)".into(),
    ))
}
