// Демонстрация open-core/hardening границы: одна и та же сборка Go-бинаря
// (CGO_ENABLED=0) по-разному работает в зависимости от того, какие
// .so-файлы лежат рядом — core обязателен, hardening опционален.
package main

import (
	"fmt"
	"os"

	keyforgeshield "github.com/sarnas-it/keyforge-shield/core/go"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: demo <lib-dir> <token> <pubkey-hex>")
		os.Exit(2)
	}
	libDir, token, pubkeyHex := os.Args[1], os.Args[2], os.Args[3]

	v, err := keyforgeshield.New(libDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	fmt.Println("mode:", v.Mode())
	fmt.Println("status:", v.Verify(token, pubkeyHex))
}
