package keyforgeshield

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Payload зеркалит core/rust/src/token.rs::TokenPayload поле в поле.
//
// ВАЖНО: DecodePayload не проверяет подпись — это сделал Verify(). Вызывать
// DecodePayload имеет смысл ТОЛЬКО для той же самой строки токена, для
// которой Verify() уже вернул StatusValid или StatusGrace. Декодирование
// здесь безопасно именно потому, что целостность строки уже установлена
// подписью; вызов на непроверенном токене читает недоверенные данные.
type Payload struct {
	Product         string     `json:"product"`
	Edition         string     `json:"edition"`
	Client          string     `json:"client"`
	LicenseID       string     `json:"license_id"`
	IssuedAt        uint64     `json:"issued_at"`
	ExpiresAt       uint64     `json:"expires_at"`
	GracePeriodSecs uint64     `json:"grace_period_secs"`
	SeatMode        SeatMode   `json:"seat_mode"`
	UsageQuota      *UsageInfo `json:"usage_quota"`
}

// SeatMode зеркалит core/rust/src/token.rs::SeatMode (serde tag="mode").
// Count имеет смысл только при Mode == "named_users", Fingerprint —
// только при Mode == "device_locked".
type SeatMode struct {
	Mode        string `json:"mode"`
	Count       uint32 `json:"count,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// UsageInfo зеркалит core/rust/src/token.rs::UsageQuota.
type UsageInfo struct {
	Metric     string  `json:"metric"`
	Limit      uint64  `json:"limit"`
	PeriodSecs *uint64 `json:"period_secs"`
}

// DecodePayload разбирает подписанную часть токена в Payload. См.
// предупреждение в комментарии к типу — вызывать только после Valid/Grace
// от Verify() на этой же строке token.
func DecodePayload(token string) (Payload, error) {
	payloadPart, _, ok := strings.Cut(token, ".")
	if !ok {
		return Payload{}, fmt.Errorf("malformed token: no '.' separator")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return Payload{}, fmt.Errorf("malformed token payload: %w", err)
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Payload{}, fmt.Errorf("malformed token payload json: %w", err)
	}
	return p, nil
}
