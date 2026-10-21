//! Private-pipe executable. No file arguments, profile, logger or key persistence.
use rustpush::native_qualification::{qualify_once, QualificationReport};
use std::io::{Read, Write};

fn read_frame(maximum: usize) -> Result<Vec<u8>, &'static str> {
    let mut size = [0; 4];
    let mut input = std::io::stdin().lock();
    input
        .read_exact(&mut size)
        .map_err(|_| "input-read-failed")?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > maximum {
        return Err("input-size-rejected");
    }
    let mut bytes = vec![0; size];
    input
        .read_exact(&mut bytes)
        .map_err(|_| "input-read-failed")?;
    Ok(bytes)
}

fn write_frame(kind: u8, bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err("output-size-rejected");
    }
    let mut output = std::io::stdout().lock();
    output
        .write_all(&[kind])
        .map_err(|_| "output-write-failed")?;
    output
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| "output-write-failed")?;
    output.write_all(bytes).map_err(|_| "output-write-failed")?;
    output.flush().map_err(|_| "output-write-failed")
}

fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("native-aps-qualifier-panic");
    }));
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args != ["--run-once"] {
        println!("native-aps-qualifier: default offline; no profile or account access");
        return;
    }
    // Parent owns the hard process deadline, including blocking stdin reads.
    // Only the private cert/signature pipe is accepted, never paths or secrets
    // through arguments/environment. No logging backend is initialized.
    let certificate = match read_frame(8192) {
        Ok(value) => value,
        Err(status) => {
            emit_report(QualificationReport::failed(status));
            return;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            emit_report(QualificationReport::failed("runtime-unavailable"));
            return;
        }
    };
    let report = runtime.block_on(qualify_once(&certificate, |nonce| async move {
        tokio::task::spawn_blocking(move || {
            write_frame(1, &nonce)?;
            read_frame(512)
        })
        .await
        .map_err(|_| "signer-pipe-failed")?
    }));
    emit_report(report);
    // Do not wait indefinitely for an already-timed-out blocking private pipe.
    runtime.shutdown_timeout(std::time::Duration::from_millis(100));
}

fn emit_report(report: QualificationReport) {
    if let Ok(value) = serde_json::to_vec(&report) {
        let _ = write_frame(2, &value);
    }
}
