package main

import (
	"fmt"

	keyforgeshield "code.sarnas.ru/keyforge-shield/core/go"
)

// productPublicKeyHex — Ed25519 публичный ключ ПРОДУКТА (не keyforge, у
// каждого продукта свой). Публичный ключ по определению не секрет —
// секретен только приватный ключ подписи на стороне keyforge-сервера,
// который в клиентский код никогда не попадает.
const productPublicKeyHex = "dae53855f6bd5646660f676feaf3aec0339382c136cdfd30d1d090a8611ffe38"

var verifier *keyforgeshield.Verifier

// handleLicenseFailure — деградация, НЕ крах и НЕ явно отличающееся
// сообщение типа "лицензия истекла, выход" прямо в месте отказа. Это
// была бы готовая лакмусовая бумажка для атакующего. Конкретная политика
// (что отключить, насколько незаметно, после какого порога повторных
// отказов) — решение продукта; здесь показан один из вариантов.
func handleLicenseFailure(status keyforgeshield.Status) {
	degradeSilently(status)
}

func degradeSilently(status keyforgeshield.Status) {
	fmt.Fprintln(telemetrySink, "license check degraded:", status)
}
