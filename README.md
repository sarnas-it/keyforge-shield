# keyforge-shield

Встраиваемая в бинарь верификация лицензионных ключей. Open-core модель —
см. [ADR-0001](docs/adr/0001-open-core-with-paid-hardening-layer.md) для полного
обоснования.

## Структура

```
core/                — OPEN SOURCE (Apache-2.0)
├── rust/            — Rust-крейт, C ABI, cdylib. Референсная верификация.
└── go/              — эталонный Go-SDK: purego, без cgo, graceful fallback.

hardening-stub/      — ЗАГОТОВКА платного слоя (не публикуется в OSS-релизе)
└── rust/            — демонстрация ABI-контракта с core, в реальности
                        переезжает в отдельный приватный репозиторий.

docs/adr/            — архитектурные решения.
```

## Модель

- **Core** работает самостоятельно и бесплатно: честная криптографическая/
  протокольная проверка ключа, полностью открытый код.
- **Hardening-слой** (платно, закрыто, доставляется только компилированным
  артефактом, обновляется по подписке) добавляет анти-RE упрочнение — core
  подхватывает его best-effort, при отсутствии продолжает работать в
  open-core режиме и честно сообщает об этом через `Verifier.Mode()`.

## Прогон прототипа

```bash
# core
cd core/rust && cargo test --release && cargo build --release

# hardening-stub (демонстрация контракта, не для прода)
cd hardening-stub/rust && cargo test --release && cargo build --release

# Go SDK + демо
cd core/go && CGO_ENABLED=0 go build -o demo ./cmd/demo

# open-core edition: только core-библиотека рядом
./demo <dir-with-only-core.so> "key" "key"

# paid edition: core + hardening-stub рядом
./demo <dir-with-both.so> "key" "key"
```
