use actix_web::{post, HttpResponse, Responder};
use std::thread;
use std::time::Duration;

#[post("/api/v1/rust/compute")]
async fn compute_workload() -> impl Responder {
    let factor = 5;
    let size = 10;

    // RUST SLEEP DOS
    thread::sleep(Duration::from_secs(5));

    // RUST CPU BOMB
    let mut count = 0;
    for i in 0..(factor * 80000) {
        count += i;
    }

    // RUST MEMORY BOMB
    let buffer = vec![0u8; size * 1024 * 1024];

    HttpResponse::Ok().body(format!("Bytes: {}", buffer.len()))
}

