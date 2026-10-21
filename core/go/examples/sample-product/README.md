# sample-product

Пример реальной интеграции `keyforge-shield` в продукт на Go: встраивание
нативной библиотеки через `go:embed`, `Guard()`/`StartAutoRecheck()` вместо
ручного boilerplate на каждую точку проверки, деградация при отказе вместо
краха (`license.go`).

`lib/linux_amd64/*.so` не в git (как и везде в репозитории — `*.so`
в `.gitignore`, это воспроизводимый артефакт сборки, не исходник). Перед
`go build` нужно собрать core и положить его в путь, который ждёт
`go:embed`:

```bash
cd ../../../rust
cargo build --release
cp target/release/libkeyforge_core.so \
   ../go/examples/sample-product/nativelib/lib/linux_amd64/

cd ../go/examples/sample-product
go build .
```

Выпустить тестовый токен (НЕ прод `keyctl` — тот хранит корневой ключ
офлайн/в HSM, см. `keyforge` репозиторий менеджера ключей):

```bash
../../../rust/target/release/issue-demo-token "my-product" "pro" "client-id" 3600
# -> public_key=<hex>   — вписать в const productPublicKeyHex в license.go
# -> token=<token>
```

Запуск:

```bash
PRODUCT_LICENSE_TOKEN=<token> ./sample-product
```

Hardening-слой (платный, `sarnas-it/keyforge-shield-hardening`, приватный
репозиторий) в этот пример не встраивается и не коммитится — у платящего
клиента появляется свой аналог `embed_linux_amd64.go` в приватном форке,
распаковывающий лицензионную `.so` в тот же каталог, что и core; `New()`
в `core/go/verifier.go` подхватывает её best-effort автоматически, без
изменений в этом примере.
