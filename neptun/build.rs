use std::error::Error;
use vergen_git2::{Emitter, Git2Builder};

fn main() -> Result<(), Box<dyn Error>> {
    // Output git build time env variables
    let git2 = Git2Builder::all_git()?;
    Emitter::default().add_instructions(&git2)?.emit()?;

    Ok(())
}
