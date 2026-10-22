// Проверка "аренды" онлайн-ключа (протокол KFL1) — нативная реализация той
// же логики, что в Go SDK (core/go/online.go: Lease.Verify + Active).
//
// Зачем отдельно от Go: решение "ключ действует" принимается здесь, в
// нативном коде, который при наличии платного hardening-слоя вызывается
// через защищённую точку входа (трамплин, самопроверка целостности,
// тайминг-инвариант), а не живёт обычным Go-кодом, который проще
// подменить. Сеть и разбор ответа остаются в Go — подлинность ответа
// определяется подписью, а не каналом.
//
// Канонический текст подписи:
//   "KFL1\n" license_id "\n" status "\n" checked_at "\n" valid_until "\n" nonce
// подпись — Ed25519 корневым ключом, base64url без паддинга.

use crate::token::verified_payload;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};

/// Допустимое расхождение часов клиента и сервера, секунды.
pub const CLOCK_SKEW_SECS: i64 = 600;

/// Коды результата `keyforge_verify_lease`.
pub const LEASE_ACTIVE: i32 = 1; // подлинная аренда, ключ действует сейчас
pub const LEASE_INACTIVE: i32 = 2; // подлинная аренда, но ключ не действует
pub const LEASE_BAD_SIGNATURE: i32 = 0; // подпись аренды не сошлась
pub const LEASE_INVALID: i32 = -1; // вход не распознан или противоречит токену

pub struct LeaseInput<'a> {
    pub token: &'a str,
    pub pubkey: &'a VerifyingKey,
    pub license_id: &'a str,
    pub status: &'a str,
    pub checked_at: i64,
    pub valid_until: i64,
    pub nonce: &'a str,
    pub signature_b64: &'a str,
    pub now: i64,
    /// Свежий ответ сервера: время сервера должно быть близко к нашему.
    /// Сохранённую на диске аренду так не проверяют (она по определению старая).
    pub fresh: bool,
}

fn canonical(i: &LeaseInput) -> Vec<u8> {
    format!(
        "KFL1\n{}\n{}\n{}\n{}\n{}",
        i.license_id, i.status, i.checked_at, i.valid_until, i.nonce
    )
    .into_bytes()
}

/// Без panic/unwrap: вход приходит через FFI от недоверенного окружения.
pub fn verify_lease(i: &LeaseInput) -> i32 {
    let sig_bytes = match URL_SAFE_NO_PAD.decode(i.signature_b64) {
        Ok(b) => b,
        Err(_) => return LEASE_BAD_SIGNATURE,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return LEASE_BAD_SIGNATURE,
    };
    if i.pubkey
        .verify_strict(&canonical(i), &Signature::from_bytes(&sig_arr))
        .is_err()
    {
        return LEASE_BAD_SIGNATURE;
    }

    // Подпись верна: теперь сверяем аренду с самим токеном. Токен проверяется
    // тем же ключом — подлинность аренды не должна опираться на то, что
    // вызывающий уже проверил токен.
    let payload = match verified_payload(i.token, i.pubkey) {
        Some(p) => p,
        None => return LEASE_INVALID,
    };
    let online = match payload.online {
        Some(o) => o,
        None => return LEASE_INVALID, // офлайн-ключу аренда не положена
    };
    if payload.license_id != i.license_id {
        return LEASE_INVALID; // аренда выдана на другую лицензию
    }
    // Срок не больше потолка, подписанного в токене: даже ошибочный или
    // скомпрометированный сервер не продлит ключ дольше, чем разрешил выпуск.
    if i.valid_until < i.checked_at || (i.valid_until - i.checked_at) as u64 > online.lease_secs {
        return LEASE_INVALID;
    }
    if i.fresh && (i.now - i.checked_at).abs() > CLOCK_SKEW_SECS {
        return LEASE_INVALID; // часы сервера и клиента слишком расходятся
    }

    // Действует: статус active, срок не вышел, часы не откатывали раньше
    // момента проверки.
    if i.status == "active" && i.now < i.valid_until && i.now >= i.checked_at - CLOCK_SKEW_SECS {
        LEASE_ACTIVE
    } else {
        LEASE_INACTIVE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{encode_token, OnlineMode, SeatMode, TokenPayload};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::collections::BTreeSet;

    const NOW: i64 = 1_800_000_000;

    struct Fx {
        key: SigningKey,
        token: String,
    }

    fn fixture(online: Option<u64>) -> Fx {
        let key = SigningKey::generate(&mut OsRng);
        let payload = TokenPayload {
            product: "p".into(),
            edition: "e".into(),
            client: "shop:c".into(),
            license_id: "seat-0123456789abcdef".into(),
            issued_at: NOW as u64,
            expires_at: NOW as u64 + 86_400,
            grace_period_secs: 0,
            seat_mode: SeatMode::Unbound,
            usage_quota: None,
            features: BTreeSet::new(),
            online: online.map(|lease_secs| OnlineMode { lease_secs }),
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let token = encode_token(&payload, &key.sign(&bytes));
        Fx { key, token }
    }

    fn sign(key: &SigningKey, id: &str, status: &str, c: i64, v: i64, nonce: &str) -> String {
        let canon = format!("KFL1\n{id}\n{status}\n{c}\n{v}\n{nonce}");
        URL_SAFE_NO_PAD.encode(key.sign(canon.as_bytes()).to_bytes())
    }

    fn input<'a>(f: &'a Fx, vk: &'a VerifyingKey, sig: &'a str, status: &'a str, c: i64, v: i64) -> LeaseInput<'a> {
        LeaseInput {
            token: &f.token, pubkey: vk, license_id: "seat-0123456789abcdef", status,
            checked_at: c, valid_until: v, nonce: "nonce-0123456789abcdef", signature_b64: sig, now: NOW, fresh: true,
        }
    }

    #[test]
    fn active_lease_is_active() {
        let f = fixture(Some(3600));
        let vk = f.key.verifying_key();
        let sig = sign(&f.key, "seat-0123456789abcdef", "active", NOW, NOW + 3600, "nonce-0123456789abcdef");
        assert_eq!(verify_lease(&input(&f, &vk, &sig, "active", NOW, NOW + 3600)), LEASE_ACTIVE);
    }

    #[test]
    fn signed_revoked_is_authentic_but_inactive() {
        let f = fixture(Some(3600));
        let vk = f.key.verifying_key();
        let sig = sign(&f.key, "seat-0123456789abcdef", "revoked", NOW, NOW, "nonce-0123456789abcdef");
        assert_eq!(verify_lease(&input(&f, &vk, &sig, "revoked", NOW, NOW)), LEASE_INACTIVE);
    }

    #[test]
    fn editing_the_status_breaks_the_signature() {
        let f = fixture(Some(3600));
        let vk = f.key.verifying_key();
        let sig = sign(&f.key, "seat-0123456789abcdef", "revoked", NOW, NOW, "nonce-0123456789abcdef");
        // перехватчик выдаёт подписанный "revoked" за "active"
        assert_eq!(verify_lease(&input(&f, &vk, &sig, "active", NOW, NOW)), LEASE_BAD_SIGNATURE);
    }

    #[test]
    fn foreign_key_and_garbage_signature_are_rejected() {
        let f = fixture(Some(3600));
        let vk = f.key.verifying_key();
        let other = SigningKey::generate(&mut OsRng);
        let sig = sign(&other, "seat-0123456789abcdef", "active", NOW, NOW + 60, "nonce-0123456789abcdef");
        assert_eq!(verify_lease(&input(&f, &vk, &sig, "active", NOW, NOW + 60)), LEASE_BAD_SIGNATURE);
        assert_eq!(verify_lease(&input(&f, &vk, "!!!", "active", NOW, NOW + 60)), LEASE_BAD_SIGNATURE);
        assert_eq!(verify_lease(&input(&f, &vk, "AAAA", "active", NOW, NOW + 60)), LEASE_BAD_SIGNATURE);
    }

    #[test]
    fn lease_longer_than_the_signed_token_cap_is_invalid() {
        let f = fixture(Some(3600));
        let vk = f.key.verifying_key();
        let sig = sign(&f.key, "seat-0123456789abcdef", "active", NOW, NOW + 7200, "nonce-0123456789abcdef");
        assert_eq!(verify_lease(&input(&f, &vk, &sig, "active", NOW, NOW + 7200)), LEASE_INVALID);
    }

    #[test]
    fn lease_for_another_license_or_offline_token_is_invalid() {
        let f = fixture(Some(3600));
        let vk = f.key.verifying_key();
        let sig = sign(&f.key, "seat-ffffffffffffffff", "active", NOW, NOW + 60, "nonce-0123456789abcdef");
        let mut i = input(&f, &vk, &sig, "active", NOW, NOW + 60);
        i.license_id = "seat-ffffffffffffffff";
        assert_eq!(verify_lease(&i), LEASE_INVALID);

        let offline = fixture(None);
        let ovk = offline.key.verifying_key();
        let sig = sign(&offline.key, "seat-0123456789abcdef", "active", NOW, NOW + 60, "nonce-0123456789abcdef");
        assert_eq!(verify_lease(&input(&offline, &ovk, &sig, "active", NOW, NOW + 60)), LEASE_INVALID);
    }

    #[test]
    fn token_signed_by_another_key_is_invalid_even_with_a_good_lease_signature() {
        let f = fixture(Some(3600));
        let evil = fixture(Some(3600)); // токен подписан другим ключом
        let vk = f.key.verifying_key();
        let sig = sign(&f.key, "seat-0123456789abcdef", "active", NOW, NOW + 60, "nonce-0123456789abcdef");
        let mut i = input(&f, &vk, &sig, "active", NOW, NOW + 60);
        i.token = &evil.token;
        assert_eq!(verify_lease(&i), LEASE_INVALID);
    }

    #[test]
    fn expiry_clock_rollback_and_skew() {
        let f = fixture(Some(3600));
        let vk = f.key.verifying_key();
        let sig = sign(&f.key, "seat-0123456789abcdef", "active", NOW, NOW + 3600, "nonce-0123456789abcdef");

        let mut late = input(&f, &vk, &sig, "active", NOW, NOW + 3600);
        late.now = NOW + 3601; // аренда кончилась
        late.fresh = false;
        assert_eq!(verify_lease(&late), LEASE_INACTIVE);

        let mut rolled_back = input(&f, &vk, &sig, "active", NOW, NOW + 3600);
        rolled_back.now = NOW - 86_400; // часы откатили
        rolled_back.fresh = false;
        assert_eq!(verify_lease(&rolled_back), LEASE_INACTIVE);

        let mut skewed = input(&f, &vk, &sig, "active", NOW, NOW + 3600);
        skewed.now = NOW + 7200; // свежий ответ, но часы расходятся на 2 часа
        assert_eq!(verify_lease(&skewed), LEASE_INVALID);
        skewed.fresh = false; // а сохранённая аренда так не проверяется
        assert_eq!(verify_lease(&skewed), LEASE_INACTIVE); // 7200 > 3600: срок вышел
    }
}
