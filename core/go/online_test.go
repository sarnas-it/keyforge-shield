package keyforgeshield

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type onlineFixture struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	token string
}

// newOnlineToken подписывает токен так же, как это делает выпускающая
// сторона: base64url(json(payload)) "." base64url(подпись).
func newOnlineToken(t *testing.T, leaseSecs uint64) onlineFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := Payload{
		Product: "demo", Edition: "pro", Client: "shop:c1", LicenseID: "seat-0123456789abcdef",
		IssuedAt: uint64(time.Now().Unix()), ExpiresAt: uint64(time.Now().Unix()) + 86400,
		SeatMode: SeatMode{Mode: SeatModeUnbound}, Features: []string{},
	}
	if leaseSecs > 0 {
		p.Online = &OnlineInfo{LeaseSecs: leaseSecs}
	}
	raw, _ := json.Marshal(p)
	sig := ed25519.Sign(priv, raw)
	return onlineFixture{pub, priv, base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)}
}

// leaseServer имитирует сервер выдачи. Формат подписи собран вручную по
// документации протокола, а не вызовом leaseCanonical.
func leaseServer(t *testing.T, f onlineFixture, mutate func(l *Lease, req map[string]string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		now := time.Now().Unix()
		l := Lease{LicenseID: "seat-0123456789abcdef", Status: LeaseActive, CheckedAt: now, ValidUntil: now + 3600, Nonce: req["nonce"]}
		if mutate != nil {
			mutate(&l, req)
		}
		canonical := fmt.Sprintf("KFL1\n%s\n%s\n%d\n%d\n%s", l.LicenseID, l.Status, l.CheckedAt, l.ValidUntil, l.Nonce)
		l.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.priv, []byte(canonical)))
		_ = json.NewEncoder(w).Encode(l)
	}))
}

func pubHex(f onlineFixture) string { return hex.EncodeToString(f.pub) }

func TestCheckOnlineAcceptsValidLease(t *testing.T) {
	f := newOnlineToken(t, 3600)
	srv := leaseServer(t, f, nil)
	defer srv.Close()

	l, err := CheckOnline(context.Background(), nil, srv.URL, f.token, pubHex(f))
	if err != nil {
		t.Fatalf("CheckOnline: %v", err)
	}
	if !l.Active(time.Now()) {
		t.Fatal("fresh active lease must be active")
	}
	if l.Active(time.Now().Add(2 * time.Hour)) {
		t.Fatal("lease must stop being active after valid_until (offline grace is bounded)")
	}
}

func TestCheckOnlineReportsRevokedAsInactiveLeaseNotError(t *testing.T) {
	f := newOnlineToken(t, 3600)
	srv := leaseServer(t, f, func(l *Lease, _ map[string]string) { l.Status = LeaseRevoked; l.ValidUntil = l.CheckedAt })
	defer srv.Close()

	l, err := CheckOnline(context.Background(), nil, srv.URL, f.token, pubHex(f))
	if err != nil {
		t.Fatalf("a signed 'revoked' answer is a valid answer, not an error: %v", err)
	}
	if l.Active(time.Now()) || l.Status != LeaseRevoked {
		t.Fatalf("revoked lease must not be active: %+v", l)
	}
}

func TestCheckOnlineRejectsForgeries(t *testing.T) {
	f := newOnlineToken(t, 3600)
	other, _, _ := ed25519.GenerateKey(nil)

	cases := map[string]struct {
		mutate func(l *Lease, req map[string]string)
		pub    string
	}{
		"подмена nonce (повтор старого ответа)": {mutate: func(l *Lease, _ map[string]string) { l.Nonce = "old-response-nonce-aaaaaaaa" }},
		"аренда другой лицензии":                {mutate: func(l *Lease, _ map[string]string) { l.LicenseID = "seat-ffffffffffffffff" }},
		"срок дольше, чем разрешил токен":       {mutate: func(l *Lease, _ map[string]string) { l.ValidUntil = l.CheckedAt + 99999 }},
		"часы сервера далеко":                   {mutate: func(l *Lease, _ map[string]string) { l.CheckedAt -= 7200; l.ValidUntil -= 7200 }},
		"подписано чужим ключом":                {pub: hex.EncodeToString(other)},
	}
	for name, c := range cases {
		srv := leaseServer(t, f, c.mutate)
		pub := c.pub
		if pub == "" {
			pub = pubHex(f)
		}
		if _, err := CheckOnline(context.Background(), nil, srv.URL, f.token, pub); err == nil || !errors.Is(err, ErrBadLease) {
			t.Errorf("%s: err = %v, want ErrBadLease", name, err)
		}
		srv.Close()
	}
}

func TestLeaseSignatureCoversStatus(t *testing.T) {
	// Перехватчик не может превратить подписанный "revoked" в "active".
	f := newOnlineToken(t, 3600)
	srv := leaseServer(t, f, func(l *Lease, _ map[string]string) { l.Status = LeaseRevoked })
	defer srv.Close()
	l, err := CheckOnline(context.Background(), nil, srv.URL, f.token, pubHex(f))
	if err != nil {
		t.Fatal(err)
	}
	l.Status = LeaseActive
	if err := l.Verify(pubHex(f), f.token); !errors.Is(err, ErrBadLease) {
		t.Fatalf("edited status must fail verification: %v", err)
	}
}

func TestStoredLeaseSurvivesRestartButIsReverified(t *testing.T) {
	f := newOnlineToken(t, 3600)
	srv := leaseServer(t, f, nil)
	defer srv.Close()
	l, _ := CheckOnline(context.Background(), nil, srv.URL, f.token, pubHex(f))

	saved, _ := json.Marshal(l)
	var loaded Lease
	if err := json.Unmarshal(saved, &loaded); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Verify(pubHex(f), f.token); err != nil || !loaded.Active(time.Now()) {
		t.Fatalf("a stored lease must verify after reload: %v", err)
	}
	loaded.ValidUntil += 86400 // правка файла на диске клиента
	if err := loaded.Verify(pubHex(f), f.token); err == nil {
		t.Fatal("a tampered stored lease must fail verification")
	}
}

func TestLeaseNotActiveWhenClockRolledBack(t *testing.T) {
	f := newOnlineToken(t, 3600)
	srv := leaseServer(t, f, nil)
	defer srv.Close()
	l, _ := CheckOnline(context.Background(), nil, srv.URL, f.token, pubHex(f))
	if l.Active(time.Now().Add(-48 * time.Hour)) {
		t.Fatal("system time earlier than the check itself is not trustworthy")
	}
}

func TestOfflineTokenIsNotAnOnlineKey(t *testing.T) {
	f := newOnlineToken(t, 0)
	if _, err := CheckOnline(context.Background(), nil, "http://unused", f.token, pubHex(f)); !errors.Is(err, ErrNotOnlineKey) {
		t.Fatalf("err = %v, want ErrNotOnlineKey", err)
	}
}

func TestCheckOnlineServerErrorsAreErrorsNotLeases(t *testing.T) {
	f := newOnlineToken(t, 3600)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 503) }))
	defer srv.Close()
	if _, err := CheckOnline(context.Background(), nil, srv.URL, f.token, pubHex(f)); err == nil {
		t.Fatal("a 503 must surface as an error so the product can fall back to its cached lease")
	}
}
