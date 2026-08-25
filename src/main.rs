fn main() {
    let args: Vec<String> = std::env::args().collect();
    kivo::cli::run(args);
}
