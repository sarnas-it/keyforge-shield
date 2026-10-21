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
use std::collections::BTreeSet;

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
    /// Сколько секунд после `expires_at` токен ещё даёт `TokenStatus::Grace`
    /// вместо `Expired`. 0 — жёсткий стоп в момент истечения. Не ноль —
    /// мягкая деградация (см. философию "repair вместо краша" в
    /// hardening-слое): продукт решает сам, что показать/урезать в Grace,
    /// core только сообщает статус, не навязывает поведение.
    pub grace_period_secs: u64,
    /// Ось "количество" минимального набора keyforge: именованные места,
    /// привязка к устройству или безлимит. Concurrent/floating-лицензии
    /// сюда не входят осознанно — им нужен stateful lease-сервер (учёт
    /// активных сессий), а не просто подписанное поле; это отдельный
    /// компонент keyforge, не часть offline-протокола токена.
    pub seat_mode: SeatMode,
    /// Ось "объём использования": лимит на метрику, которую считает сам
    /// продукт (API-вызовы, обработанные документы, что угодно, что
    /// решит продукт-интегратор — core не знает семантику metric и не
    /// считает потребление). `None` — без учёта использования.
    ///
    /// ВАЖНО, отличие от seat_mode/expires_at: те проверяются по
    /// неизменному факту (текущее время, зашитое число мест) — здесь же
    /// "сколько уже потрачено" это состояние, которое накапливается на
    /// стороне клиента, а не в подписанном payload. core переносит
    /// только ЛИМИТ (тамперпруф, подписан), не текущий остаток.
    ///
    /// Хранение самого счётчика потребления — ответственность продукта
    /// (его собственный учёт, который ему и так нужен корректным для
    /// работы — например лог обработанных операций), не core/SDK: core
    /// умышленно не владеет этим состоянием. На стороне Go SDK —
    /// `DecodePayload` (читает это поле ПОСЛЕ успешной проверки подписи)
    /// + `CheckUsageQuota` (чистое сравнение репортнутого продуктом
    /// значения с лимитом, без собственного хранения). Это сознательный
    /// компромисс уровня "справедливость, не неуязвимость" (см.
    /// обсуждение бизнес-модели) — продукт технически может соврать о
    /// текущем потреблении, как и при любой другой офлайн-проверке в
    /// этом протоколе; для принуждения, не зависящего от честности
    /// клиента, нужен online-тип ключей с серверным счётчиком, не
    /// реализован.
    pub usage_quota: Option<UsageQuota>,
    /// Ось "продукт/функциональность" сверху `edition`: `edition` — это
    /// целиком пресет ("basic"/"pro"/"enterprise" — набор, который
    /// продукт сам интерпретирует), `features` — a-la-carte отдельные
    /// модули/возможности внутри одного edition, независимо
    /// переключаемые (например edition="pro" + features={"sso",
    /// "audit_log"}). Пустое множество — без дополнительных фич сверх
    /// того, что подразумевает edition.
    ///
    /// BTreeSet, не Vec: нет смысловой разницы в порядке, канонический
    /// порядок при сериализации избавляет от случайных различий байтов
    /// payload между одинаковыми по смыслу токенами, выпущенными в
    /// разном порядке аргументов. core не знает семантику имён фич —
    /// как и metric в UsageQuota, их значение решает продукт-интегратор.
    pub features: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageQuota {
    /// Название метрики — свободная строка, смысл знает только продукт
    /// (например "api_calls", "documents_processed"). core её не
    /// интерпретирует, только переносит как часть подписанных данных.
    pub metric: String,
    pub limit: u64,
    /// `None` — лимит на весь срок действия токена (не сбрасывается).
    /// `Some(secs)` — скользящее окно длиной secs (например ~2_592_000
    /// для "в месяц"); отсчёт окна и сброс счётчика — ответственность
    /// продукта (см. usage_quota выше), core не хранит состояние окна.
    pub period_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SeatMode {
    /// Фиксированное число именованных пользователей/мест, зашитое в токен.
    NamedUsers { count: u32 },
    /// Привязка к конкретному устройству (hardware fingerprint), для
    /// офлайн-активации без сервера.
    DeviceLocked { fingerprint: String },
    /// Без ограничения по количеству (сайт-лицензия и т.п.).
    Unbound,
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
    /// Истёк по `expires_at`, но ещё в пределах `grace_period_secs` —
    /// подпись верна, продукт сам решает, что урезать/показать.
    Grace,
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

    if now_unix <= payload.expires_at {
        return TokenStatus::Valid;
    }

    let grace_deadline = payload.expires_at.saturating_add(payload.grace_period_secs);
    if now_unix <= grace_deadline {
        return TokenStatus::Grace;
    }

    TokenStatus::Expired
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
            grace_period_secs: 0,
            seat_mode: SeatMode::NamedUsers { count: 1 },
            usage_quota: None,
            features: BTreeSet::new(),
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
    fn expired_but_within_grace_period_is_grace() {
        let signing_key = test_keypair();
        let mut payload = test_payload(1_000);
        payload.grace_period_secs = 500;
        let signature = signing_key.sign(&payload.to_json_bytes());
        let token = encode_token(&payload, &signature);

        // 1_300 > expires_at(1_000), но <= expires_at + grace(1_500).
        let status = verify(&token, &signing_key.verifying_key(), 1_300);
        assert_eq!(status, TokenStatus::Grace);
    }

    #[test]
    fn past_grace_period_is_expired() {
        let signing_key = test_keypair();
        let mut payload = test_payload(1_000);
        payload.grace_period_secs = 500;
        let signature = signing_key.sign(&payload.to_json_bytes());
        let token = encode_token(&payload, &signature);

        let status = verify(&token, &signing_key.verifying_key(), 1_600);
        assert_eq!(status, TokenStatus::Expired);
    }

    #[test]
    fn zero_grace_period_expires_immediately() {
        let signing_key = test_keypair();
        let payload = test_payload(1_000); // grace_period_secs: 0 из test_payload
        let signature = signing_key.sign(&payload.to_json_bytes());
        let token = encode_token(&payload, &signature);

        let status = verify(&token, &signing_key.verifying_key(), 1_001);
        assert_eq!(status, TokenStatus::Expired);
    }

    #[test]
    fn seat_mode_round_trips_through_signed_payload() {
        // seat_mode не участвует в verify()-логике напрямую (это дело
        // продукта-интегратора), но обязан переживать json-round-trip и
        // входить в подписанные байты как и любое другое поле payload.
        let signing_key = test_keypair();
        for mode in [
            SeatMode::NamedUsers { count: 5 },
            SeatMode::DeviceLocked { fingerprint: "hw-abc123".into() },
            SeatMode::Unbound,
        ] {
            let mut payload = test_payload(2_000_000_000);
            payload.seat_mode = mode.clone();
            let signature = signing_key.sign(&payload.to_json_bytes());
            let token = encode_token(&payload, &signature);

            assert_eq!(
                verify(&token, &signing_key.verifying_key(), 1_800_000_000),
                TokenStatus::Valid
            );

            let (payload_bytes, _) = decode_token(&token).unwrap();
            let decoded: TokenPayload = serde_json::from_slice(&payload_bytes).unwrap();
            assert_eq!(decoded.seat_mode, mode);
        }
    }

    #[test]
    fn tampering_with_seat_mode_breaks_signature() {
        // Как и license_id, seat_mode входит в подписанный payload целиком —
        // нельзя переклеить "named:1" на "unbound" без приватного ключа.
        let signing_key = test_keypair();
        let payload = test_payload(2_000_000_000);
        let signature = signing_key.sign(&payload.to_json_bytes());

        let mut forged = payload.clone();
        forged.seat_mode = SeatMode::Unbound;
        let forged_token = encode_token(&forged, &signature); // та же подпись

        assert_eq!(
            verify(&forged_token, &signing_key.verifying_key(), 1_800_000_000),
            TokenStatus::BadSignature
        );
    }

    #[test]
    fn usage_quota_round_trips_through_signed_payload() {
        // Как и seat_mode: core не интерпретирует usage_quota, но обязан
        // переносить его как есть через json + подпись.
        let signing_key = test_keypair();
        for quota in [
            None,
            Some(UsageQuota { metric: "api_calls".into(), limit: 10_000, period_secs: Some(2_592_000) }),
            Some(UsageQuota { metric: "documents_processed".into(), limit: 500, period_secs: None }),
        ] {
            let mut payload = test_payload(2_000_000_000);
            payload.usage_quota = quota.clone();
            let signature = signing_key.sign(&payload.to_json_bytes());
            let token = encode_token(&payload, &signature);

            assert_eq!(
                verify(&token, &signing_key.verifying_key(), 1_800_000_000),
                TokenStatus::Valid
            );

            let (payload_bytes, _) = decode_token(&token).unwrap();
            let decoded: TokenPayload = serde_json::from_slice(&payload_bytes).unwrap();
            assert_eq!(decoded.usage_quota, quota);
        }
    }

    #[test]
    fn tampering_with_usage_quota_breaks_signature() {
        let signing_key = test_keypair();
        let mut payload = test_payload(2_000_000_000);
        payload.usage_quota = Some(UsageQuota { metric: "api_calls".into(), limit: 100, period_secs: None });
        let signature = signing_key.sign(&payload.to_json_bytes());

        let mut forged = payload.clone();
        forged.usage_quota = Some(UsageQuota { metric: "api_calls".into(), limit: 1_000_000, period_secs: None });
        let forged_token = encode_token(&forged, &signature); // та же подпись, подменён лимит

        assert_eq!(
            verify(&forged_token, &signing_key.verifying_key(), 1_800_000_000),
            TokenStatus::BadSignature,
            "подмена лимита без новой подписи должна провалить проверку"
        );
    }

    #[test]
    fn features_round_trip_through_signed_payload() {
        let signing_key = test_keypair();
        let mut payload = test_payload(2_000_000_000);
        payload.features = BTreeSet::from(["sso".to_string(), "audit_log".to_string()]);
        let signature = signing_key.sign(&payload.to_json_bytes());
        let token = encode_token(&payload, &signature);

        assert_eq!(
            verify(&token, &signing_key.verifying_key(), 1_800_000_000),
            TokenStatus::Valid
        );

        let (payload_bytes, _) = decode_token(&token).unwrap();
        let decoded: TokenPayload = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(decoded.features, payload.features);
    }

    #[test]
    fn tampering_with_features_breaks_signature() {
        // Как и остальные оси: нельзя дописать себе фичу без новой подписи.
        let signing_key = test_keypair();
        let mut payload = test_payload(2_000_000_000);
        payload.features = BTreeSet::from(["basic_reports".to_string()]);
        let signature = signing_key.sign(&payload.to_json_bytes());

        let mut forged = payload.clone();
        forged.features.insert("enterprise_sso".to_string());
        let forged_token = encode_token(&forged, &signature); // та же подпись, лишняя фича

        assert_eq!(
            verify(&forged_token, &signing_key.verifying_key(), 1_800_000_000),
            TokenStatus::BadSignature,
            "добавление фичи без новой подписи должно провалить проверку"
        );
    }

    #[test]
    fn malformed_token_is_rejected() {
        let signing_key = test_keypair();
        let status = verify("not-a-valid-token", &signing_key.verifying_key(), 0);
        assert_eq!(status, TokenStatus::Malformed);
    }
}
