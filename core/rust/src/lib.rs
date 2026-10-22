// keyforge-shield / core — OPEN SOURCE (Apache-2.0)
//
// Референсная реализация протокола верификации лицензионного токена.
// Крейт работает полностью самостоятельно. Hardening-слой (платный, закрытый,
// отдельный репозиторий) — опциональная надстройка сверху; core не деградирует
// и не требует её присутствия.

mod lease;
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

/// Запрос на проверку аренды онлайн-ключа: одна структура вместо дюжины
/// аргументов. Через hardening-слой функция вызывается машинным трамплином,
/// который сохраняет и подменяет адрес возврата и передаёт аргументы
/// регистрами; указатель на структуру — единственный аргумент, и порядок
/// полей (repr(C)) — часть ABI. Строки — NUL-терминированные UTF-8.
#[repr(C)]
pub struct KfLeaseRequest {
    pub token: *const c_char,
    pub pubkey_hex: *const c_char,
    pub license_id: *const c_char,
    pub status: *const c_char,
    pub checked_at: i64,
    pub valid_until: i64,
    pub nonce: *const c_char,
    pub signature_b64: *const c_char,
    pub now_unix: i64,
    /// bit0 — свежий ответ сервера (проверять расхождение часов).
    pub flags: i32,
}

/// Проверяет аренду онлайн-ключа. Коды возврата:
///   1  — аренда подлинна и ключ действует сейчас
///   2  — аренда подлинна, но ключ не действует (revoked/expired/unknown,
///        срок вышел, часы откатывали)
///   0  — подпись аренды неверна
///  -1  — вход не распознан или противоречит токену (чужая лицензия,
///        аренда длиннее потолка в токене, офлайн-токен, токен чужой подписи)
///
/// Весь путь без unwrap/expect/panic (крейт собран с panic = "abort").
#[no_mangle]
pub extern "C" fn keyforge_verify_lease(req: *const KfLeaseRequest) -> i32 {
    if req.is_null() {
        return lease::LEASE_INVALID;
    }
    let r = unsafe { &*req };
    let s = |p: *const c_char| -> Option<&str> {
        if p.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(p) }.to_str().ok()
        }
    };
    let parsed = (|| {
        let pubkey = VerifyingKey::from_bytes(&decode_hex32(s(r.pubkey_hex)?)?).ok()?;
        Some((
            pubkey,
            s(r.token)?,
            s(r.license_id)?,
            s(r.status)?,
            s(r.nonce)?,
            s(r.signature_b64)?,
        ))
    })();
    let Some((pubkey, token, license_id, status, nonce, signature_b64)) = parsed else {
        return lease::LEASE_INVALID;
    };
    lease::verify_lease(&lease::LeaseInput {
        token,
        pubkey: &pubkey,
        license_id,
        status,
        checked_at: r.checked_at,
        valid_until: r.valid_until,
        nonce,
        signature_b64,
        now: r.now_unix,
        fresh: r.flags & 1 != 0,
    })
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
/// 7: добавлена функция keyforge_verify_lease (нативная проверка аренды).
#[no_mangle]
pub extern "C" fn keyforge_core_abi_version() -> i32 {
    7
}

#[cfg(test)]
mod ffi_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::ffi::CString;
    use crate::OnlineMode;

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
        assert_eq!(keyforge_core_abi_version(), 7);
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

    #[test]
    fn ffi_verify_lease_end_to_end_through_the_c_abi() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let key = SigningKey::generate(&mut OsRng);
        let now = now_unix() as i64;
        let payload = TokenPayload {
            product: "demo".into(),
            edition: "pro".into(),
            client: "ffi".into(),
            license_id: "seat-0123456789abcdef".into(),
            issued_at: 0,
            expires_at: now as u64 + 86_400,
            grace_period_secs: 0,
            seat_mode: SeatMode::Unbound,
            usage_quota: None,
            features: Default::default(),
            online: Some(OnlineMode { lease_secs: 3600 }),
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let token = token::encode_token(&payload, &key.sign(&bytes));
        let canon = format!("KFL1\nseat-0123456789abcdef\nactive\n{now}\n{}\nnonce-0123456789abcdef", now + 3600);
        let sig = URL_SAFE_NO_PAD.encode(key.sign(canon.as_bytes()).to_bytes());

        let token_c = CString::new(token).unwrap();
        let pub_c = CString::new(hex::encode(key.verifying_key().to_bytes())).unwrap();
        let id_c = CString::new("seat-0123456789abcdef").unwrap();
        let status_c = CString::new("active").unwrap();
        let nonce_c = CString::new("nonce-0123456789abcdef").unwrap();
        let sig_c = CString::new(sig).unwrap();
        let mut req = KfLeaseRequest {
            token: token_c.as_ptr(),
            pubkey_hex: pub_c.as_ptr(),
            license_id: id_c.as_ptr(),
            status: status_c.as_ptr(),
            checked_at: now,
            valid_until: now + 3600,
            nonce: nonce_c.as_ptr(),
            signature_b64: sig_c.as_ptr(),
            now_unix: now,
            flags: 1,
        };
        assert_eq!(keyforge_verify_lease(&req), 1);

        let revoked_c = CString::new("revoked").unwrap();
        req.status = revoked_c.as_ptr(); // статус подписан как active: правка ломает подпись
        assert_eq!(keyforge_verify_lease(&req), 0);

        assert_eq!(keyforge_verify_lease(std::ptr::null()), -1);
        req.status = std::ptr::null();
        assert_eq!(keyforge_verify_lease(&req), -1, "a null field must be refused, not dereferenced");
    }
}
