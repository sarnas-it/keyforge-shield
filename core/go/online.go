package keyforgeshield

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Онлайн-ключи. Токен с полем online подписан обычным образом, но сам по
// себе не даёт права работать: продукт раз в lease_secs подтверждает его
// у сервера выдачи и получает подписанную "аренду" (Lease). Отзыв ключа
// на сервере вступает в силу не позже конца текущей аренды.
//
// Протокол (KFL1):
//
//	POST <base>/api/v1/online/check  {"token": "...", "nonce": "<16-64 [A-Za-z0-9_-]>"}
//	200 {"license_id","status","checked_at","valid_until","nonce","signature"}
//
//	signature = base64url(Ed25519(root_key, canonical))
//	canonical = "KFL1\n" license_id "\n" status "\n" checked_at "\n" valid_until "\n" nonce
//
// Аренда подписана тем же корневым ключом, чей публичный ключ уже вшит в
// продукт для проверки токенов — отдельного ключа или доверия к TLS-
// сертификату сервера для её подлинности не требуется. Префикс "KFL1"
// отделяет эту подпись от подписи токена: одно нельзя выдать за другое.
// Nonce клиента входит в подпись, поэтому старый ответ "active" нельзя
// переиграть после отзыва.

const (
	LeaseActive  = "active"
	LeaseRevoked = "revoked"
	LeaseExpired = "expired"
	LeaseUnknown = "unknown"

	// leaseClockSkew — допустимое расхождение часов клиента и сервера.
	leaseClockSkew = 10 * time.Minute
	maxLeaseBody   = 64 << 10
)

var (
	ErrNotOnlineKey   = errors.New("keyforgeshield: token is not an online key")
	ErrBadLease       = errors.New("keyforgeshield: lease signature or fields are invalid")
	ErrLeaseNotActive = errors.New("keyforgeshield: lease is not active")
)

// Lease — подтверждение сервера. JSON-сериализуется для хранения между
// запусками продукта; после загрузки обязательно вызвать Verify заново —
// файл на диске клиента не заслуживает доверия сам по себе.
type Lease struct {
	LicenseID  string `json:"license_id"`
	Status     string `json:"status"`
	CheckedAt  int64  `json:"checked_at"`
	ValidUntil int64  `json:"valid_until"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`
}

func leaseCanonical(l Lease) []byte {
	return []byte("KFL1\n" + l.LicenseID + "\n" + l.Status + "\n" +
		strconv.FormatInt(l.CheckedAt, 10) + "\n" + strconv.FormatInt(l.ValidUntil, 10) + "\n" + l.Nonce)
}

// Verify проверяет подпись аренды ключом pubkeyHex и что она выдана именно
// на лицензию из token, а срок не превышает потолок, подписанный в самом
// токене (payload.online.lease_secs): даже скомпрометированный или
// ошибочный сервер не продлит аренду дольше, чем разрешил выпуск ключа.
// Подпись токена здесь не проверяется — это делает Verifier.Verify.
func (l Lease) Verify(pubkeyHex, token string) error {
	pub, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key", ErrBadLease)
	}
	sig, err := base64.RawURLEncoding.DecodeString(l.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), leaseCanonical(l), sig) {
		return fmt.Errorf("%w: signature mismatch", ErrBadLease)
	}
	payload, err := DecodePayload(token)
	if err != nil {
		return err
	}
	if payload.Online == nil {
		return ErrNotOnlineKey
	}
	if l.LicenseID != payload.LicenseID {
		return fmt.Errorf("%w: lease is for another license", ErrBadLease)
	}
	if l.ValidUntil < l.CheckedAt || uint64(l.ValidUntil-l.CheckedAt) > payload.Online.LeaseSecs {
		return fmt.Errorf("%w: lease longer than the key allows", ErrBadLease)
	}
	return nil
}

// Active: аренда подтверждает работу ключа в момент now. Время, ушедшее
// раньше момента проверки (откат системных часов), считается недействительным.
func (l Lease) Active(now time.Time) bool {
	t := now.Unix()
	return l.Status == LeaseActive && t < l.ValidUntil && t >= l.CheckedAt-int64(leaseClockSkew.Seconds())
}

type checkRequest struct {
	Token string `json:"token"`
	Nonce string `json:"nonce"`
}

func newNonce() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// fetchLease — сетевая часть протокола KFL1: запрос, разбор ответа, сверка
// nonce. Подлинность самой аренды (подпись, соответствие токену, срок,
// дрейф часов) здесь НЕ проверяется — это разные пути у двух вызывающих:
// пакетная CheckOnline (чистый Go, Lease.Verify) и Verifier.CheckOnline
// (решение через native/hardened core). Вынесено сюда, чтобы протокол
// запроса не дублировался между ними.
func fetchLease(ctx context.Context, client *http.Client, baseURL, token string) (Lease, error) {
	payload, err := DecodePayload(token)
	if err != nil {
		return Lease{}, err
	}
	if payload.Online == nil {
		return Lease{}, ErrNotOnlineKey
	}
	nonce, err := newNonce()
	if err != nil {
		return Lease{}, err
	}
	body, _ := json.Marshal(checkRequest{Token: token, Nonce: nonce})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/online/check", bytes.NewReader(body))
	if err != nil {
		return Lease{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Lease{}, fmt.Errorf("online check: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxLeaseBody))
	if err != nil {
		return Lease{}, fmt.Errorf("online check: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Lease{}, fmt.Errorf("online check: server answered %d", resp.StatusCode)
	}

	var lease Lease
	if err := json.Unmarshal(raw, &lease); err != nil {
		return Lease{}, fmt.Errorf("%w: %v", ErrBadLease, err)
	}
	if lease.Nonce != nonce {
		return Lease{}, fmt.Errorf("%w: nonce mismatch (replayed or foreign response)", ErrBadLease)
	}
	return lease, nil
}

// CheckOnline запрашивает у сервера baseURL аренду для token и проверяет
// её чистой Go-реализацией (Lease.Verify). Ошибка сети/сервера возвращается
// как error — вызывающий продукт сам решает, продолжать ли работать на
// ранее сохранённой действующей аренде. Статус ответа (revoked/expired/
// unknown) — не ошибка: возвращается Lease с этим статусом; пользоваться
// ключом можно только при Lease.Active.
//
// Open-core путь: подпись аренды проверяется прямо здесь, в Go. Для
// hardened-режима, где это решение защищено трамплином/тайминг-
// инвариантом так же, как Verify(), см. Verifier.CheckOnline.
//
// Перед вызовом токен должен пройти Verifier.Verify (подпись и срок).
func CheckOnline(ctx context.Context, client *http.Client, baseURL, token, pubkeyHex string) (Lease, error) {
	lease, err := fetchLease(ctx, client, baseURL, token)
	if err != nil {
		return Lease{}, err
	}
	if err := lease.Verify(pubkeyHex, token); err != nil {
		return Lease{}, err
	}
	skew := time.Since(time.Unix(lease.CheckedAt, 0))
	if skew > leaseClockSkew || skew < -leaseClockSkew {
		return Lease{}, fmt.Errorf("%w: server time differs from local clock by %v", ErrBadLease, skew)
	}
	return lease, nil
}
