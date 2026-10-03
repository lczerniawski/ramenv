#[tokio::main(flavor = "current_thread")]
async fn main() {
    ramenv::run_cli().await;
}
