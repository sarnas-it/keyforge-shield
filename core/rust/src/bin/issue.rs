// Демонстрационный инструмент выпуска токена (НЕ прод-keyctl — тот живёт
// в репозитории keyforge-менеджера и хранит корневой ключ офлайн/в HSM).
// Здесь — одноразовая генерация keypair в памяти, чтобы прогнать прототип
// end-to-end: issue -> verify через C ABI из Go.
use ed25519_dalek::{Signer, SigningKey};
use keyforge_core::{SeatMode, TokenPayload};
use rand::rngs::OsRng;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

/// Разбирает последний CLI-аргумент в SeatMode:
///   "unbound"              -> SeatMode::Unbound
///   "named:<N>"             -> SeatMode::NamedUsers { count: N }
///   "device:<fingerprint>"  -> SeatMode::DeviceLocked { fingerprint }
fn parse_seat_mode(raw: &str) -> SeatMode {
    if raw == "unbound" {
        return SeatMode::Unbound;
    }
    if let Some(count_str) = raw.strip_prefix("named:") {
        let count: u32 = count_str.parse().expect("named:<N> — N must be a number");
        return SeatMode::NamedUsers { count };
    }
    if let Some(fingerprint) = raw.strip_prefix("device:") {
        return SeatMode::DeviceLocked { fingerprint: fingerprint.to_string() };
    }
    panic!("unrecognised seat-mode {raw:?}; expected unbound | named:<N> | device:<fingerprint>");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 8 {
        eprintln!(
            "usage: {} <product> <edition> <client> <license-id> <ttl-seconds> <grace-seconds> <seat-mode>",
            args[0]
        );
        eprintln!(
            "  <license-id>   — водяной знак конкретной выдачи (место/машина), \
             не имя клиента. Пример: seat-0007"
        );
        eprintln!(
            "  <grace-seconds> — сколько секунд после истечения токен ещё даёт \
             Grace, а не Expired. 0 — жёсткий стоп."
        );
        eprintln!(
            "  <seat-mode>    — unbound | named:<N> | device:<fingerprint>"
        );
        std::process::exit(2);
    }
    let (product, edition, client, license_id) =
        (args[1].clone(), args[2].clone(), args[3].clone(), args[4].clone());
    let ttl_seconds: u64 = args[5].parse().expect("ttl-seconds must be a number");
    let grace_period_secs: u64 = args[6].parse().expect("grace-seconds must be a number");
    let seat_mode = parse_seat_mode(&args[7]);

    let signing_key = SigningKey::generate(&mut OsRng);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = TokenPayload {
        product,
        edition,
        client,
        license_id,
        issued_at: now,
        expires_at: now + ttl_seconds,
        grace_period_secs,
        seat_mode,
    };

    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = signing_key.sign(&payload_bytes);
    let token = keyforge_core::encode_token(&payload, &signature);

    println!("public_key={}", hex::encode(signing_key.verifying_key().to_bytes()));
    println!("token={token}");
}
