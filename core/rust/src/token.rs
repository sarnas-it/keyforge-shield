// Формат токена keyforge-shield (open, часть публичного протокола —
// см. ADR-0001: криптографическая часть открыта по принципу Керкгоффса).
//
// token := base64url(json(TokenPayload)) "." base64url(signature_64_bytes)
//
// Весь путь верификации — только Option/Result-комбинаторы, без unwrap/expect
// и без паник: функция вызывается через FFI на непроверенном входе
// (чужой, возможно подделанный токен), и панику через границу C ABI нельзя
// ни поймать (крейт собран с `panic = "abort"`), ни допустить.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPayload {
    pub product: String,
    pub edition: String,
    pub client: String,
    /// Водяной знак выдачи, отдельно от имени клиента: `client` отличает
    /// компании друг от друга, `license_id` отличает конкретную выдачу
    /// (место/машину/сотрудника) внутри одного клиента. Нужно для разбора
    /// инцидента утечки — "у клиента А утёк токен" и "у клиента А утёк
    /// именно токен места №7, выданный такого-то числа" — два разных
    /// объёма ответственности и разных следующих шагов.
    ///
    /// Поле открытое (не шифруется) — это осознанно: клиент видит, что
    /// его конкретная копия помечена, это и есть сдерживающий эффект.
    /// Подделать/вырезать нельзя — поле входит в подписанный payload,
    /// изменение рушит подпись без приватного ключа.
    pub license_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl TokenPayload {
    fn to_json_bytes(&self) -> Vec<u8> {
        // Сериализация собственной структуры в собственный формат не может
        // упасть по данным пользователя — `expect` здесь не на пути верификации.
        serde_json::to_vec(self).expect("TokenPayload is always serializable")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStatus {
    Valid,
    Expired,
    BadSignature,
    Malformed,
}

/// Кодирует подписанный токен из payload и 64-байтной подписи.
/// Используется инструментом выпуска (issue-demo-token), не на пути верификации.
pub fn encode_token(payload: &TokenPayload, signature: &Signature) -> String {
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_json_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    format!("{payload_b64}.{sig_b64}")
}

fn decode_token(token: &str) -> Option<(Vec<u8>, Signature)> {
    let (payload_part, sig_part) = token.split_once('.')?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_part).ok()?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_part).ok()?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().ok()?;
    Some((payload_bytes, Signature::from_bytes(&sig_arr)))
}

/// Проверяет токен против публичного ключа и текущего unix-времени.
/// Порядок важен: подпись проверяется ДО разбора полей payload — иначе
/// можно было бы судить о содержимом неподписанных/подделанных данных
/// по тому, на каком шаге разбор провалился (минимальная защита от oracle).
pub fn verify(token: &str, public_key: &VerifyingKey, now_unix: u64) -> TokenStatus {
    let Some((payload_bytes, signature)) = decode_token(token) else {
        return TokenStatus::Malformed;
    };

    if public_key.verify_strict(&payload_bytes, &signature).is_err() {
        return TokenStatus::BadSignature;
    }

    let Ok(payload) = serde_json::from_slice::<TokenPayload>(&payload_bytes) else {
        return TokenStatus::Malformed;
    };

    if now_unix > payload.expires_at {
        return TokenStatus::Expired;
    }

    TokenStatus::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn test_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn test_payload(expires_at: u64) -> TokenPayload {
        TokenPayload {
            product: "demo-product".into(),
            edition: "pro".into(),
            client: "test-client".into(),
            license_id: "seat-0001".into(),
            issued_at: 1_700_000_000,
            expires_at,
        }
    }

    #[test]
    fn valid_token_passes() {
        let signing_key = test_keypair();
        let payload = test_payload(2_000_000_000);
        let signature = signing_key.sign(&payload.to_json_bytes());
        let token = encode_token(&payload, &signature);

        let status = verify(&token, &signing_key.verifying_key(), 1_800_000_000);
        assert_eq!(status, TokenStatus::Valid);
    }

    #[test]
    fn expired_token_is_rejected() {
        let signing_key = test_keypair();
        let payload = test_payload(1_000);
        let signature = signing_key.sign(&payload.to_json_bytes());
        let token = encode_token(&payload, &signature);

        let status = verify(&token, &signing_key.verifying_key(), 2_000);
        assert_eq!(status, TokenStatus::Expired);
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let signing_key = test_keypair();
        let payload = test_payload(2_000_000_000);
        let signature = signing_key.sign(&payload.to_json_bytes());
        let mut token = encode_token(&payload, &signature);
        // Подменяем один символ в закодированном payload — подпись не совпадёт.
        token.replace_range(0..1, if token.starts_with('A') { "B" } else { "A" });

        let status = verify(&token, &signing_key.verifying_key(), 1_800_000_000);
        assert_eq!(status, TokenStatus::BadSignature);
    }

    #[test]
    fn wrong_signing_key_is_rejected() {
        let signing_key = test_keypair();
        let other_key = test_keypair();
        let payload = test_payload(2_000_000_000);
        let signature = signing_key.sign(&payload.to_json_bytes());
        let token = encode_token(&payload, &signature);

        // Проверяем подписью от signing_key, но публичным ключом от другой пары.
        let status = verify(&token, &other_key.verifying_key(), 1_800_000_000);
        assert_eq!(status, TokenStatus::BadSignature);
    }

    #[test]
    fn tampering_with_license_id_breaks_signature() {
        // Ключевое свойство водяного знака: нельзя переклеить license_id
        // на другой (например, чтобы скрыть, с какого места утекла копия)
        // без приватного ключа — payload подписан целиком, license_id в
        // него входит на равных с остальными полями.
        let signing_key = test_keypair();
        let payload = test_payload(2_000_000_000);
        let signature = signing_key.sign(&payload.to_json_bytes());
        let token = encode_token(&payload, &signature);

        let mut forged_payload = payload.clone();
        forged_payload.license_id = "seat-9999".into();
        let forged_token = encode_token(&forged_payload, &signature); // та же подпись, другие данные

        assert_eq!(
            verify(&forged_token, &signing_key.verifying_key(), 1_800_000_000),
            TokenStatus::BadSignature,
            "подмена license_id без новой подписи должна провалить проверку"
        );
        // Контроль: исходный токен с исходным license_id всё ещё валиден.
        assert_eq!(
            verify(&token, &signing_key.verifying_key(), 1_800_000_000),
            TokenStatus::Valid
        );
    }

    #[test]
    fn malformed_token_is_rejected() {
        let signing_key = test_keypair();
        let status = verify("not-a-valid-token", &signing_key.verifying_key(), 0);
        assert_eq!(status, TokenStatus::Malformed);
    }
}
