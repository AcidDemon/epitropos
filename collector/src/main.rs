use epitropos_collector::error::CollectorError;

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("epitropos-collector: {e}");
            std::process::exit(e.exit_code());
        }
    }
}

fn run() -> Result<(), CollectorError> {
    // Placeholder — filled in by the CLI dispatcher task.
    eprintln!("epitropos-collector: not yet implemented");
    Err(CollectorError::Usage(
        "no subcommand yet; this is a Track C work-in-progress build".into(),
    ))
}
