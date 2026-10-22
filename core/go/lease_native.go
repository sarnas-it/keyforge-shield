package keyforgeshield

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"
	"unsafe"
)

// Native-путь проверки аренды: решение "аренда действует" принимается
// core-библиотекой (keyforge_verify_lease), а не этим пакетом — в
// hardened-режиме сам вызов идёт через трамплин keyforge-shield-hardening
// (подмена адреса возврата, тайминг-инвариант, самопроверка целостности),
// как и Verifier.Verify для токенов. CheckOnline (пакетная функция выше)
// остаётся отдельной чистой Go-реализацией для open-core издания — обе
// ветки используют общий fetchLease, чтобы не дублировать протокол KFL1.

// Коды возврата keyforge_verify_lease / keyforge_hardened_verify_lease —
// зеркало core/rust/src/lease.rs.
const (
	nativeLeaseBadSignature int32 = 0
	nativeLeaseActive       int32 = 1
	nativeLeaseInactive     int32 = 2
	nativeLeaseInvalid      int32 = -1
)

type leaseVerifyFunc func(req uintptr) int32
type registerLeaseFnFunc func(realFnAddr uintptr)

// kfLeaseRequest — побайтовое зеркало repr(C) KfLeaseRequest в
// core/rust/src/lib.rs. Порядок и размеры полей — часть ABI, не внутреннее
// дело Go: меняется только вместе с Rust-стороной и ABI-версией.
// Строки — указатели на NUL-терминированные байты (см. cStringBytes).
type kfLeaseRequest struct {
	token        uintptr
	pubkeyHex    uintptr
	licenseID    uintptr
	status       uintptr
	checkedAt    int64
	validUntil   int64
	nonce        uintptr
	signatureB64 uintptr
	nowUnix      int64
	flags        int32
	_            int32 // padding — repr(C) добивает размер структуры до кратного 8
}

// cStringBytes — NUL-терминированное представление s для передачи через
// FFI. Возвращается срез (не просто указатель), чтобы вызывающий мог
// держать его живым до возврата из native-вызова через runtime.KeepAlive —
// GC может переместить/освободить память, на которую ссылается только
// uintptr внутри kfLeaseRequest, он не распознаётся как указатель.
func cStringBytes(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return b
}

// VerifyLease проверяет аренду l через native core (или hardened-слой,
// если он загружен) — то же решение "активна или нет", что принимает
// защищённый бинарь, без отдельной чистой Go-реализации, которую легче
// распатчить отдельно от неё. now — текущее время клиента (проверка
// истечения аренды и допустимого расхождения часов); fresh=true означает
// "ответ только что получен от сервера" (как в Verifier.CheckOnline), а не
// восстановлен из файла на диске между запусками продукта.
func (v *Verifier) VerifyLease(l Lease, token, pubkeyHex string, now time.Time, fresh bool) (bool, error) {
	if v.verifyLease == nil {
		return false, fmt.Errorf("keyforgeshield: native lease verification is not loaded (New() failed?)")
	}

	tokenB := cStringBytes(token)
	pubB := cStringBytes(pubkeyHex)
	licB := cStringBytes(l.LicenseID)
	statusB := cStringBytes(l.Status)
	nonceB := cStringBytes(l.Nonce)
	sigB := cStringBytes(l.Signature)

	var flags int32
	if fresh {
		flags = 1
	}
	req := kfLeaseRequest{
		token:        uintptr(unsafe.Pointer(&tokenB[0])),
		pubkeyHex:    uintptr(unsafe.Pointer(&pubB[0])),
		licenseID:    uintptr(unsafe.Pointer(&licB[0])),
		status:       uintptr(unsafe.Pointer(&statusB[0])),
		checkedAt:    l.CheckedAt,
		validUntil:   l.ValidUntil,
		nonce:        uintptr(unsafe.Pointer(&nonceB[0])),
		signatureB64: uintptr(unsafe.Pointer(&sigB[0])),
		nowUnix:      now.Unix(),
		flags:        flags,
	}

	code := v.verifyLease(uintptr(unsafe.Pointer(&req)))
	// Все байтовые срезы и сам req должны дожить до этой точки — выше их
	// держат только "сырые" uintptr-поля, невидимые для GC как указатели.
	runtime.KeepAlive(tokenB)
	runtime.KeepAlive(pubB)
	runtime.KeepAlive(licB)
	runtime.KeepAlive(statusB)
	runtime.KeepAlive(nonceB)
	runtime.KeepAlive(sigB)
	runtime.KeepAlive(req)

	switch code {
	case nativeLeaseActive:
		return true, nil
	case nativeLeaseInactive:
		return false, nil
	case nativeLeaseBadSignature:
		return false, fmt.Errorf("%w: signature mismatch", ErrBadLease)
	default: // nativeLeaseInvalid и всё нераспознанное
		return false, fmt.Errorf("%w: lease does not match token", ErrBadLease)
	}
}

// CheckOnline — тот же сетевой протокол KFL1, что пакетная функция
// CheckOnline, но решение "аренда действует" принимает native/hardened
// core (через VerifyLease), а не чистый Go. В hardened-режиме сам вызов
// защищён трамплином и тайминг-инвариантом так же, как Verify().
//
// active=false без ошибки — это не отказ: подпись подлинна, но ключ сейчас
// не действует (revoked/expired/unknown, аренда истекла, откат часов) —
// то же самое разделение, что у пакетной Lease.Active() при open-core.
func (v *Verifier) CheckOnline(ctx context.Context, client *http.Client, baseURL, token, pubkeyHex string) (lease Lease, active bool, err error) {
	lease, err = fetchLease(ctx, client, baseURL, token)
	if err != nil {
		return Lease{}, false, err
	}
	active, err = v.VerifyLease(lease, token, pubkeyHex, time.Now(), true)
	if err != nil {
		return Lease{}, false, err
	}
	return lease, active, nil
}
