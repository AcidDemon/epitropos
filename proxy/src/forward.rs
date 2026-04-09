//! epitropos-forward — placeholder. The real forwarder (TLS + mutual
//! auth + remote append-only receiver) lands in Track C. Until then
//! this binary refuses to run so nothing downstream can rely on a
//! `.forwarded` marker that lies about actual delivery.

// sysexits.h EX_UNAVAILABLE
const EX_UNAVAILABLE: i32 = 69;

fn main() {
    // --version is honoured even in the stub so operator tooling that
    // inventories binaries still works.
    for arg in std::env::args().skip(1) {
        if arg == "--version" || arg == "-V" {
            println!(
                "epitropos-forward {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("EPITROPOS_GIT_COMMIT")
            );
            std::process::exit(0);
        }
    }
    eprintln!("epitropos-forward: not implemented (Track C)");
    std::process::exit(EX_UNAVAILABLE);
}
