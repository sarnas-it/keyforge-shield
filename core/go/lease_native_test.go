package keyforgeshield

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Эти тесты требуют настоящих собранных библиотек и пропускаются, если
// переменные окружения не заданы:
//
//	KEYFORGE_LIBDIR            — каталог с libkeyforge_core.so (keyforge-shield/core/rust: cargo build --release)
//	KEYFORGE_HARDENING_LIBDIR  — каталог с libkeyforge_hardening_stub.so (keyforge-shield-hardening/rust: cargo build --release);
//	                              если не задан, проверяется только open-core режим.
func nativeTestLibDirs(t *testing.T) (coreDir, hardeningDir string) {
	t.Helper()
	coreDir = os.Getenv("KEYFORGE_LIBDIR")
	if coreDir == "" {
		t.Skip("KEYFORGE_LIBDIR не задан — пропуск native-теста аренды (см. docstring)")
	}
	return coreDir, os.Getenv("KEYFORGE_HARDENING_LIBDIR")
}

// mergedLibDir — New() ищет обе библиотеки по фиксированным именам в одном
// каталоге; core.rust и keyforge-shield-hardening собирают их в разные
// target/, так что для hardened-режима нужно свести симлинки в один t.TempDir().
func mergedLibDir(t *testing.T, coreDir, hardeningDir string) string {
	t.Helper()
	dir := t.TempDir()
	link := func(srcDir, name string) {
		src := filepath.Join(srcDir, name)
		if _, err := os.Stat(src); err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if err := os.Symlink(src, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	link(coreDir, coreLibName())
	link(hardeningDir, hardeningLibName())
	return dir
}

// TestVerifierVerifyLeaseMatchesPureGoDecision — для набора кейсов
// (активна / отозвана / чужая лицензия / аренда длиннее потолка в токене)
// native-решение должно совпадать с чистой Go-реализацией (Lease.Verify +
// Active) — это одно и то же решение, вынесенное за трамплин, не другая
// логика.
func TestVerifierVerifyLeaseMatchesPureGoDecision(t *testing.T) {
	coreDir, hardeningDir := nativeTestLibDirs(t)
	f := newOnlineToken(t, 3600)
	now := time.Now()

	sign := func(status string, checkedAt, validUntil int64) Lease {
		l := Lease{LicenseID: "seat-0123456789abcdef", Status: status, CheckedAt: checkedAt, ValidUntil: validUntil, Nonce: "n-" + status}
		sig := ed25519.Sign(f.priv, leaseCanonical(l))
		l.Signature = base64.RawURLEncoding.EncodeToString(sig)
		return l
	}

	cases := []struct {
		name  string
		lease Lease
	}{
		{"active", sign(LeaseActive, now.Unix()-10, now.Unix()+100)},
		{"revoked", sign(LeaseRevoked, now.Unix()-10, now.Unix()+100)},
		{"expired-window", sign(LeaseActive, now.Unix()-30, now.Unix()-5)},
		{"lease-longer-than-cap", sign(LeaseActive, now.Unix(), now.Unix()+7200)}, // токен разрешил 3600
	}

	runFor := func(t *testing.T, libDir string, wantMode Mode) {
		v, err := New(libDir)
		if err != nil {
			t.Fatalf("New(%q): %v", libDir, err)
		}
		if v.Mode() != wantMode {
			t.Fatalf("mode = %v, want %v", v.Mode(), wantMode)
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				wantErr := tc.lease.Verify(pubHex(f), f.token)
				wantActive := wantErr == nil && tc.lease.Active(now)

				gotActive, gotErr := v.VerifyLease(tc.lease, f.token, pubHex(f), now, true)

				if (wantErr == nil) != (gotErr == nil) {
					t.Fatalf("authenticity mismatch: pure-Go err=%v, native err=%v", wantErr, gotErr)
				}
				if wantErr == nil && gotActive != wantActive {
					t.Fatalf("active mismatch: pure-Go=%v, native=%v", wantActive, gotActive)
				}
			})
		}
	}

	t.Run("open-core", func(t *testing.T) {
		runFor(t, coreDir, ModeOpenCore)
	})
	if hardeningDir != "" {
		t.Run("hardened", func(t *testing.T) {
			runFor(t, mergedLibDir(t, coreDir, hardeningDir), ModeHardened)
		})
	}
}

// TestVerifierCheckOnlineAgainstRealServer — полный путь: httptest-сервер
// (leaseServer из online_test.go) отвечает подлинной арендой KFL1,
// Verifier.CheckOnline делает реальный HTTP-запрос и получает решение из
// native core вместо чистого Go.
func TestVerifierCheckOnlineAgainstRealServer(t *testing.T) {
	coreDir, _ := nativeTestLibDirs(t)
	f := newOnlineToken(t, 3600)
	srv := leaseServer(t, f, nil)
	defer srv.Close()

	v, err := New(coreDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	lease, active, err := v.CheckOnline(context.Background(), srv.Client(), srv.URL, f.token, pubHex(f))
	if err != nil {
		t.Fatalf("CheckOnline: %v", err)
	}
	if !active {
		t.Fatalf("lease should be active: %+v", lease)
	}
	if lease.LicenseID != "seat-0123456789abcdef" {
		t.Fatalf("license_id = %q", lease.LicenseID)
	}
}

// TestVerifierCheckOnlineRejectsForgedSignature — сервер подписывает чужим
// ключом: native-путь обязан отличить это так же надёжно, как чистый Go.
func TestVerifierCheckOnlineRejectsForgedSignature(t *testing.T) {
	coreDir, _ := nativeTestLibDirs(t)
	f := newOnlineToken(t, 3600)
	forger := newOnlineToken(t, 3600) // другой ключ
	srv := leaseServer(t, forger, nil)
	defer srv.Close()

	v, err := New(coreDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, _, err = v.CheckOnline(context.Background(), srv.Client(), srv.URL, f.token, pubHex(f))
	if err == nil {
		t.Fatal("ожидалась ошибка подписи для аренды, подписанной чужим ключом")
	}
}
