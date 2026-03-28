use std::process::Command;
use std::time::Duration;
use reqwest::Client;
use std::thread::sleep;

const WEB1: &str = "https://polyglotte-institute.eu";
const WEB2: &str = "https://ledvance.ewyse.agency";
const GOOGLE: &str = "https://google.com";

async fn is_reachable(client: &Client, url: &str) -> bool {
    client.get(url).timeout(Duration::from_secs(3)).send().await.is_ok()
}

fn ctl(action: &str, domain: &str) {
    let domain_clean = domain.replace("https://", "");
    let status = Command::new("./target/release/ctl")
        .args([action, &domain_clean])
        .status()
        .expect("Failed to execute ctl");
    
    if !status.success() {
        panic!("[ERR] ctl {} {} failed", action, domain_clean);
    }
}

fn assert_status(reachable: bool, name: &str, expected: bool) {
    if reachable == expected {
        println!("[PASS] {} is {}", name, if reachable { "REACHABLE" } else { "BLOCKED" });
    } else {
        println!("[FAIL] {} expected reachable={}, got={}", name, expected, reachable);
        std::process::exit(1);
    }
}

#[tokio::test]
async fn main() {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    println!("--- STEP 1: Initial State (All Open) ---");
    assert_status(is_reachable(&client, WEB1).await, "Web1", true);
    assert_status(is_reachable(&client, WEB2).await, "Web2", true);
    assert_status(is_reachable(&client, GOOGLE).await, "Google", true);

    println!("\n--- STEP 2: Block Web1 (Polyglotte) ---");
    ctl("add", WEB1);
    sleep(Duration::from_secs(5));    
    assert_status(is_reachable(&client, WEB1).await, "Web1", false);
    assert_status(is_reachable(&client, WEB2).await, "Web2", true); // Shared IP check
    assert_status(is_reachable(&client, GOOGLE).await, "Google", true);

    println!("\n--- STEP 3: Block Google ---");
    ctl("add", GOOGLE);
    sleep(Duration::from_secs(5));    
    assert_status(is_reachable(&client, WEB1).await, "Web1", false);
    assert_status(is_reachable(&client, WEB2).await, "Web2", true);
    assert_status(is_reachable(&client, GOOGLE).await, "Google", false);

    println!("\n--- STEP 4: Remove Web1 ---");
    ctl("remove", WEB1);
    sleep(Duration::from_secs(5));    
    assert_status(is_reachable(&client, WEB1).await, "Web1", true);
    assert_status(is_reachable(&client, WEB2).await, "Web2", true);
    assert_status(is_reachable(&client, GOOGLE).await, "Google", false);

    println!("\n--- STEP 5: Remove google ---");
    ctl("remove", GOOGLE);
    sleep(Duration::from_secs(5));    
    assert_status(is_reachable(&client, WEB1).await, "Web1", true);
    assert_status(is_reachable(&client, WEB2).await, "Web2", true);
    assert_status(is_reachable(&client, GOOGLE).await, "Google", true);


    println!("\n[RESULT] All FQDN blocking tests passed.");
}