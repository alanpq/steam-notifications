use std::io::Result;
fn main() -> Result<()> {
    let files = std::fs::read_dir("proto/")?.filter_map(|f| Some(f.ok()?.path())).collect::<Vec<_>>();
    prost_build::compile_protos(&files, &["proto/"])?;
    Ok(())
}
