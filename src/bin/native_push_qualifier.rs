//! Private stdin only; never account credentials, logs or live-profile writes.
use serde::Deserialize;
use std::io::{Read, Write};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    config: rustpush::RelayConfig,
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("native-push-qualifier-panic")));
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--run-once"] {
        println!("native-push-qualifier default=offline requests=0 profile_reads=0");
        return;
    }
    let mut bytes = Vec::new();
    if std::io::stdin()
        .take(16385)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > 16384
    {
        return;
    }
    let Ok(input) = serde_json::from_slice::<Input>(&bytes) else {
        return;
    };
    bytes.fill(0);
    drop(bytes);
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    let value = runtime.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(45),
            rustpush::native_push::qualify_native_client(input.config),
        )
        .await
        .unwrap_or_else(|_| serde_json::json!({"schema":1,"status":"native-push-client-timeout"}))
    });
    runtime.shutdown_timeout(std::time::Duration::from_millis(200));
    if let Ok(bytes) = serde_json::to_vec(&value) {
        let _ = std::io::stdout().write_all(&bytes);
    }
}
