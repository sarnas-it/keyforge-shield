// Демонстрационный инструмент выпуска токена (НЕ прод-keyctl — тот живёт
// в репозитории keyforge-менеджера и хранит корневой ключ офлайн/в HSM).
// Здесь — одноразовая генерация keypair в памяти, чтобы прогнать прототип
// end-to-end: issue -> verify через C ABI из Go.
use ed25519_dalek::{Signer, SigningKey};
use keyforge_core::TokenPayload;
use rand::rngs::OsRng;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: {} <product> <edition> <client> <ttl-seconds>",
            args[0]
        );
        std::process::exit(2);
    }
    let (product, edition, client) = (args[1].clone(), args[2].clone(), args[3].clone());
    let ttl_seconds: u64 = args[4].parse().expect("ttl-seconds must be a number");

    let signing_key = SigningKey::generate(&mut OsRng);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = TokenPayload {
        product,
        edition,
        client,
        issued_at: now,
        expires_at: now + ttl_seconds,
    };

    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = signing_key.sign(&payload_bytes);
    let token = keyforge_core::encode_token(&payload, &signature);

    println!("public_key={}", hex::encode(signing_key.verifying_key().to_bytes()));
    println!("token={token}");
}
