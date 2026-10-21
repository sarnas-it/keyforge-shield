// keyforge-shield / core — OPEN SOURCE (Apache-2.0)
//
// Референсная реализация протокола верификации лицензионного токена.
// Крейт работает полностью самостоятельно. Hardening-слой (платный, закрытый,
// отдельный репозиторий) — опциональная надстройка сверху; core не деградирует
// и не требует её присутствия.

mod token;
pub use token::{encode_token, OnlineMode, SeatMode, TokenPayload, TokenStatus, UsageQuota};

use ed25519_dalek::VerifyingKey;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// Проверяет лицензионный токен против публичного ключа (hex, 32 байта) и
/// текущего времени. Код возврата:
///   1  — валиден
///   3  — подпись верна, токен просрочен, но в пределах grace_period_secs
///   2  — подпись верна, но токен просрочен (вне grace-периода)
///   0  — подпись неверна
///  -1  — вход не распознан (null-указатель, невалидный hex-ключ, "мусор")
///
/// Весь путь — Option/Result-комбинаторы, без unwrap/expect/panic!: вход
/// непроверенный (чужой токен), а крейт собран с `panic = "abort"`, так что
/// паника здесь — это не ошибка, пойманная вызывающей стороной, а падение
/// всего процесса. Проверяющая сторона обязана не паниковать, а не "ловить".
#[no_mangle]
pub extern "C" fn keyforge_verify_token(token: *const c_char, pubkey_hex: *const c_char) -> i32 {
    if token.is_null() || pubkey_hex.is_null() {
        return -1;
    }

    let status = (|| -> Option<TokenStatus> {
        let token_str = unsafe { CStr::from_ptr(token) }.to_str().ok()?;
        let pubkey_str = unsafe { CStr::from_ptr(pubkey_hex) }.to_str().ok()?;
        let pubkey_bytes = decode_hex32(pubkey_str)?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).ok()?;
        Some(token::verify(token_str, &verifying_key, now_unix()))
    })();

    match status {
        Some(TokenStatus::Valid) => 1,
        Some(TokenStatus::Grace) => 3,
        Some(TokenStatus::Expired) => 2,
        Some(TokenStatus::BadSignature) => 0,
        Some(TokenStatus::Malformed) | None => -1,
    }
}

/// Версия ABI-контракта core-библиотеки. Hardening-слой при загрузке
/// проверяет совместимость через эту константу, а не наоборот — core
/// ничего не знает про hardening и не ссылается на него напрямую.
///
/// 3: добавлен код возврата 3 (TokenStatus::Grace) и поля payload
/// grace_period_secs/seat_mode — существующие коды 1/2/0/-1 не менялись,
/// это аддитивное расширение, но версия бита всё равно поднята, чтобы
/// hardening-слой мог логировать факт обновления контракта.
/// 4: добавлено поле payload usage_quota (Option) — тоже аддитивно,
/// коды возврата не менялись.
/// 5: добавлено поле payload features (BTreeSet<String>, по умолчанию
/// пустое множество) — тоже аддитивно, коды возврата не менялись.
/// 6: добавлено поле payload online (Option<OnlineMode>) — онлайн-ключи;
/// аддитивно, старые токены читаются как офлайн.
#[no_mangle]
pub extern "C" fn keyforge_core_abi_version() -> i32 {
    6
}

#[cfg(test)]
mod ffi_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::ffi::CString;

    #[test]
    fn ffi_roundtrip_valid_token() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let payload = TokenPayload {
            product: "demo".into(),
            edition: "pro".into(),
            client: "ffi-test".into(),
            license_id: "seat-ffi".into(),
            issued_at: 0,
            expires_at: now_unix() + 3600,
            grace_period_secs: 0,
            seat_mode: SeatMode::NamedUsers { count: 1 },
            usage_quota: None,
            features: Default::default(),
            online: None,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = signing_key.sign(&payload_bytes);
        let token = token::encode_token(&payload, &signature);

        let token_c = CString::new(token).unwrap();
        let pubkey_c = CString::new(hex::encode(signing_key.verifying_key().to_bytes())).unwrap();

        assert_eq!(keyforge_verify_token(token_c.as_ptr(), pubkey_c.as_ptr()), 1);
    }

    #[test]
    fn ffi_rejects_null() {
        let a = CString::new("x").unwrap();
        assert_eq!(keyforge_verify_token(std::ptr::null(), a.as_ptr()), -1);
    }

    #[test]
    fn ffi_rejects_garbage_pubkey() {
        let token = CString::new("whatever.whatever").unwrap();
        let bad_key = CString::new("not-hex").unwrap();
        assert_eq!(keyforge_verify_token(token.as_ptr(), bad_key.as_ptr()), -1);
    }

    #[test]
    fn reports_abi_version() {
        assert_eq!(keyforge_core_abi_version(), 6);
    }

    #[test]
    fn ffi_reports_grace_status() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let payload = TokenPayload {
            product: "demo".into(),
            edition: "pro".into(),
            client: "ffi-test".into(),
            license_id: "seat-ffi-grace".into(),
            issued_at: 0,
            expires_at: now_unix().saturating_sub(10), // уже истёк
            grace_period_secs: 3600,                   // но внутри grace
            seat_mode: SeatMode::Unbound,
            usage_quota: None,
            features: Default::default(),
            online: None,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = signing_key.sign(&payload_bytes);
        let token = token::encode_token(&payload, &signature);

        let token_c = CString::new(token).unwrap();
        let pubkey_c = CString::new(hex::encode(signing_key.verifying_key().to_bytes())).unwrap();

        assert_eq!(keyforge_verify_token(token_c.as_ptr(), pubkey_c.as_ptr()), 3);
    }
}
