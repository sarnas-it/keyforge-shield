//go:build linux && amd64

// Package nativelib встраивает core-библиотеку в бинарь продукта через
// go:embed и извлекает её во временный файл для dlopen (purego не умеет
// грузить shared-библиотеку прямо из памяти процесса на Linux без
// memfd_create-трюков — для примера берём простой и переносимый путь
// через временный файл; memfd_create — возможное будущее усиление,
// не обязательное для работы механизма).
//
// Под каждую целевую платформу — свой файл со своим build-тегом
// (embed_darwin_arm64.go, embed_windows_amd64.go, ...), эмбеддящий
// .dylib/.dll из соответствующего lib/<platform>/ — здесь показан только
// linux/amd64, на котором мы разрабатываем и тестируем прототип.
package nativelib

import _ "embed"

//go:embed lib/linux_amd64/libkeyforge_core.so
var coreBytes []byte

// coreFileName — должно совпадать с тем, что core/go/verifier.go ожидает
// найти по имени в libDir (см. coreLibName() там).
const coreFileName = "libkeyforge_core.so"
