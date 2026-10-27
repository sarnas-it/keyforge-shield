// Пример реальной интеграции keyforge-shield в продукт. Показывает:
//
//  1. Доставка нативной библиотеки ВМЕСТЕ с Go-бинарём через go:embed +
//     извлечение во временный файл для dlopen (nativelib/).
//  2. Guard()/StartAutoRecheck() — SDK сам снимает с клиента boilerplate
//     "написать if-ы и тикер в каждом месте" (раньше здесь были две
//     ручные проверки; см. git-историю коммита, добавившего эти хелперы,
//     за примером "как было раньше").
//  3. Деградация при отказе, а не немедленный крах (license.go).
//
// Важная оговорка, которую Guard/StartAutoRecheck НЕ решают: КАКИЕ именно
// функции оборачивать и КОГДА запускать re-check — всё равно решает
// клиент, и это видно по исходнику продукта. Если нужно, чтобы точки
// вызова не были предсказуемы по коду, это задача build-time инструмента
// (расставляет вызовы автоматически на этапе сборки), а не этого SDK.
package main

import (
	"fmt"
	"os"
	"time"

	keyforgeshield "code.sarnas.ru/keyforge-shield/core/go"

	"code.sarnas.ru/keyforge-shield/core/go/examples/sample-product/nativelib"
)

var telemetrySink = os.Stderr

func main() {
	libDir, cleanup, err := nativelib.Extract()
	if err != nil {
		fmt.Fprintln(os.Stderr, "не удалось подготовить защиту:", err)
		os.Exit(1)
	}
	defer cleanup()

	verifier, err = keyforgeshield.New(libDir)
	if err != nil {
		// core обязателен — без него продукт работать не должен вовсе,
		// это не "мягкий" отказ.
		fmt.Fprintln(os.Stderr, "не удалось инициализировать верификатор:", err)
		os.Exit(1)
	}
	fmt.Println("режим защиты:", verifier.Mode())

	token := os.Getenv("PRODUCT_LICENSE_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "не задан PRODUCT_LICENSE_TOKEN")
		os.Exit(1)
	}

	// Было (руками): if status := checkLicense(token); status != Valid { ... }
	// Guard снимает boilerplate самой проверки — клиент решает только
	// ЧТО оборачивать (здесь — запуск приложения) и что делать при отказе.
	verifier.Guard(token, productPublicKeyHex, handleLicenseFailure, func() {
		runApplication(token)
	})
}

// runApplication — основной цикл продукта. Периодическая ре-верификация
// теперь не ручной time.Ticker в этой функции (как было раньше), а
// verifier.StartAutoRecheck — SDK сам поднимает горутину.
func runApplication(token string) {
	fmt.Println("приложение запущено")

	stop := verifier.StartAutoRecheck(token, productPublicKeyHex, 5*time.Minute, func(status keyforgeshield.Status) {
		if status != keyforgeshield.StatusValid {
			handleLicenseFailure(status)
		}
	})
	defer stop()

	for {
		doWork()
		time.Sleep(time.Second)
	}
}

func doWork() {
	// Полезная работа продукта — не часть примера защиты.
}
