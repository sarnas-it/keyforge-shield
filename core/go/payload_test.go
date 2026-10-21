package keyforgeshield

import "testing"

// Токен ниже выпущен issue-demo-token (named:3, api_calls:5) — реальный
// подписанный Ed25519-токен, не сконструированный вручную JSON. Проверяет,
// что DecodePayload действительно читает то, что кладёт туда core/rust,
// а не только Go-зеркало структуры само с собой.
const realSignedToken = "eyJwcm9kdWN0IjoiZGVtby1wcm9kdWN0IiwiZWRpdGlvbiI6InBybyIsImNsaWVudCI6ImFjbWUtY29ycCIsImxpY2Vuc2VfaWQiOiJzZWF0LTAwNDIiLCJpc3N1ZWRfYXQiOjE3OTI2MDIwMjUsImV4cGlyZXNfYXQiOjE3OTI2MDU2MjUsImdyYWNlX3BlcmlvZF9zZWNzIjowLCJzZWF0X21vZGUiOnsibW9kZSI6Im5hbWVkX3VzZXJzIiwiY291bnQiOjN9LCJ1c2FnZV9xdW90YSI6eyJtZXRyaWMiOiJhcGlfY2FsbHMiLCJsaW1pdCI6NSwicGVyaW9kX3NlY3MiOm51bGx9fQ.PE512uM_XtXt7mVjT0_s5DrhI-3w0IwjAnOmJ5_95ZPJcYAEd9kwmN4sT9sDydzzCk17CAMouBjVxnPrL9m3Dg"

// Выпущен issue-demo-token с features="sso,audit_log" (ABI 5) -
// проверяет, что BTreeSet на стороне Rust сериализуется в канонически
// отсортированный JSON-массив, который Go читает как обычный []string.
const tokenWithFeatures = "eyJwcm9kdWN0IjoiZGVtby1wcm9kdWN0IiwiZWRpdGlvbiI6InBybyIsImNsaWVudCI6ImFjbWUtY29ycCIsImxpY2Vuc2VfaWQiOiJzZWF0LTAwOTkiLCJpc3N1ZWRfYXQiOjE3OTI2MDI0MjAsImV4cGlyZXNfYXQiOjE3OTI2MDYwMjAsImdyYWNlX3BlcmlvZF9zZWNzIjowLCJzZWF0X21vZGUiOnsibW9kZSI6InVuYm91bmQifSwidXNhZ2VfcXVvdGEiOm51bGwsImZlYXR1cmVzIjpbImF1ZGl0X2xvZyIsInNzbyJdfQ.9HSsvgKi-5YFshwixq4UiP0OuyHm9PQIn5Cpi1FHkazKCTQUp7dPvizSsg3Fu9-8eHG3KPFv_PK5Wku4sKwOCg"

func TestDecodePayloadReadsRealRustSignedToken(t *testing.T) {
	p, err := DecodePayload(realSignedToken)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if p.Product != "demo-product" || p.Client != "acme-corp" || p.LicenseID != "seat-0042" {
		t.Fatalf("unexpected identity fields: %+v", p)
	}
	if p.SeatMode.Mode != SeatModeNamedUsers || p.SeatMode.Count != 3 {
		t.Fatalf("unexpected seat_mode: %+v", p.SeatMode)
	}
	if p.UsageQuota == nil || p.UsageQuota.Metric != "api_calls" || p.UsageQuota.Limit != 5 {
		t.Fatalf("unexpected usage_quota: %+v", p.UsageQuota)
	}
	if p.UsageQuota.PeriodSecs != nil {
		t.Fatalf("expected period_secs = null (lifetime), got %v", *p.UsageQuota.PeriodSecs)
	}
}

func TestDecodePayloadRejectsMalformedToken(t *testing.T) {
	if _, err := DecodePayload("not-a-token-at-all"); err == nil {
		t.Fatal("expected an error for a token with no '.' separator")
	}
	if _, err := DecodePayload("not-base64!.sig"); err == nil {
		t.Fatal("expected an error for invalid base64 payload")
	}
}

func TestCheckSeatCountNamedUsers(t *testing.T) {
	mode := SeatMode{Mode: SeatModeNamedUsers, Count: 5}
	if !CheckSeatCount(5, mode) {
		t.Error("reportedActive == limit should still be allowed (exactly at capacity)")
	}
	if CheckSeatCount(6, mode) {
		t.Error("reportedActive > limit must be rejected")
	}
	if !CheckSeatCount(0, mode) {
		t.Error("zero active users is always within any positive limit")
	}
}

func TestCheckSeatCountUnboundAndDeviceLockedAreUnlimitedByCount(t *testing.T) {
	unbound := SeatMode{Mode: SeatModeUnbound}
	if !CheckSeatCount(1_000_000, unbound) {
		t.Error("unbound seat mode must never fail the count check")
	}
	deviceLocked := SeatMode{Mode: SeatModeDeviceLocked, Fingerprint: "hw-abc"}
	if !CheckSeatCount(1_000_000, deviceLocked) {
		t.Error("device-locked seat mode is enforced by fingerprint, not by count")
	}
}

func TestCheckUsageQuotaNilMeansUnlimited(t *testing.T) {
	if !CheckUsageQuota(1_000_000, nil) {
		t.Error("nil quota (token had no usage_quota) must always be allowed")
	}
}

func TestCheckUsageQuotaEnforcesLimit(t *testing.T) {
	quota := &UsageInfo{Metric: "api_calls", Limit: 10}
	if !CheckUsageQuota(9, quota) {
		t.Error("9 < 10 should be allowed")
	}
	if CheckUsageQuota(10, quota) {
		t.Error("10 == limit means exhausted, must be rejected for one more unit")
	}
	if CheckUsageQuota(11, quota) {
		t.Error("over the limit must be rejected")
	}
}

func TestDecodeThenCheckEndToEnd(t *testing.T) {
	// Полный путь продукта: взял реальный подписанный токен (уже прошедший
	// Verify() == Valid в предположении этого теста), декодировал payload,
	// сравнил свои собственные (продуктовые) счётчики с лимитами из токена.
	p, err := DecodePayload(realSignedToken)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}

	if !CheckSeatCount(3, p.SeatMode) {
		t.Error("3 active users against named:3 should be allowed")
	}
	if CheckSeatCount(4, p.SeatMode) {
		t.Error("4 active users against named:3 should be rejected")
	}

	if !CheckUsageQuota(4, p.UsageQuota) {
		t.Error("4 used against api_calls:5 should be allowed")
	}
	if CheckUsageQuota(5, p.UsageQuota) {
		t.Error("5 used against api_calls:5 (limit reached) should be rejected for the 6th call")
	}
}

func TestDecodePayloadReadsFeaturesFromRealToken(t *testing.T) {
	p, err := DecodePayload(tokenWithFeatures)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if !HasFeature(p.Features, "sso") {
		t.Errorf("expected feature sso in %v", p.Features)
	}
	if !HasFeature(p.Features, "audit_log") {
		t.Errorf("expected feature audit_log in %v", p.Features)
	}
	if HasFeature(p.Features, "enterprise_sso") {
		t.Errorf("did not expect enterprise_sso in %v", p.Features)
	}
}

func TestHasFeatureOnEmptyOrNilSet(t *testing.T) {
	if HasFeature(nil, "anything") {
		t.Error("nil features (older token without the field) must not have any feature")
	}
	if HasFeature([]string{}, "anything") {
		t.Error("empty features must not have any feature")
	}
}

func TestDecodePayloadOnOlderTokenWithoutFeaturesField(t *testing.T) {
	// realSignedToken был выпущен до появления оси features (ABI 4) -
	// проверяет обратную совместимость декодирования: отсутствующее поле
	// не должно давать ошибку, просто nil-слайс.
	p, err := DecodePayload(realSignedToken)
	if err != nil {
		t.Fatalf("DecodePayload on a pre-features token: %v", err)
	}
	if HasFeature(p.Features, "anything") {
		t.Error("a token issued before ABI 5 cannot have any feature")
	}
}
