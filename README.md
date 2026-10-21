# keyforge-shield

Встраиваемая в бинарь верификация лицензионных ключей (Ed25519-подписанные
токены). Open-core модель — см. [ADR-0001](docs/adr/0001-open-core-with-paid-hardening-layer.md)
для полного обоснования.

## Структура

```
core/                — OPEN SOURCE (Apache-2.0), этот репозиторий
├── rust/            — Rust-крейт, C ABI, cdylib. Верификация токена,
│                       инструмент выпуска демо-токенов (issue-demo-token).
└── go/              — эталонный Go-SDK: purego, без cgo, graceful fallback.

docs/adr/            — архитектурные решения.
```

Платный hardening-слой (анти-RE упрочнение) — отдельный **приватный**
репозиторий [sarnas-it/keyforge-shield-hardening](https://github.com/sarnas-it/keyforge-shield-hardening),
не часть этого дерева с самого начала истории (см. ADR-0001 — распространяется
только компилированным артефактом, не исходниками).

## Модель

- **Core** работает самостоятельно и бесплатно: честная криптографическая
  проверка Ed25519-подписанного токена, полностью открытый код.
- **Hardening-слой** (платно, закрыто, доставляется только компилированным
  артефактом, обновляется по подписке) добавляет анти-RE упрочнение — core
  подхватывает его best-effort, при отсутствии продолжает работать в
  open-core режиме и честно сообщает об этом через `Verifier.Mode()`.

## Формат токена

```
token := base64url(json(payload)) "." base64url(signature_64_bytes)
payload := { product, edition, client, issued_at, expires_at }
```

Подпись — Ed25519 над сырыми байтами payload. Публичный ключ (32 байта, hex)
встраивается в проверяющий бинарь. Полная схема в `core/rust/src/token.rs`.

## Прогон прототипа

```bash
cd core/rust
cargo test --release
cargo build --release

# выпустить демо-токен (НЕ прод keyctl — тот хранит корневой ключ офлайн/в HSM)
./target/release/issue-demo-token "my-product" "pro" "client-id" 3600
# -> public_key=<hex>
# -> token=<token>

cd ../go
CGO_ENABLED=0 go build -o demo ./cmd/demo

# open-core edition: в каталоге только libkeyforge_core.so
./demo <dir> "<token>" "<public_key>"
# status: valid | expired | bad-signature | malformed
```
