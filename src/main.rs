mod app;
mod cli;
mod core;
mod network;
mod storage;
mod utils;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    cli::run(args);
}
