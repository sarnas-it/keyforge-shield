package keyforgeshield

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// UsageCounter — локальный, клиентский учёт потребления по оси
// usage_quota из токена (core/rust/src/token.rs::UsageQuota). Core не
// считает и не хранит потребление — только подписывает объявленный
// лимит (metric/limit/period_secs); сам счётчик "сколько уже
// потрачено" — состояние на стороне клиента, этот файл его реализует.
//
// ОГРАНИЧЕНИЯ (сознательно — см. обсуждение бизнес-модели: справедливость,
// не неуязвимость):
//   - Состояние — обычный JSON-файл на диске клиента. Мотивированный
//     пользователь технически может удалить/откатить файл и обойти
//     лимит — это не криптографическая защита, как и остальной
//     офлайн-протокол (seat_mode/expires_at тоже проверяются только по
//     подписанным данным, не защищены от патча самого бинаря).
//   - Защищает от конкурентного доступа внутри одного процесса
//     (sync.Mutex), но не между несколькими процессами на одном файле —
//     для MVP не нужно: типичный сценарий — один процесс продукта.
//   - Принуждение, не обходимое удалением локального файла, требует
//     online-типа ключей с серверным счётчиком — не реализовано.
type UsageCounter struct {
	path string
	mu   sync.Mutex
}

type usageState struct {
	WindowStart uint64 `json:"window_start"`
	Count       uint64 `json:"count"`
}

// NewUsageCounter открывает (лениво, при первом Consume/Remaining) счётчик,
// хранящий состояние в path. Рекомендуется один файл на license_id, чтобы
// счётчики разных выдач не путались.
func NewUsageCounter(path string) *UsageCounter {
	return &UsageCounter{path: path}
}

func (c *UsageCounter) loadAll() (map[string]usageState, error) {
	data, err := os.ReadFile(c.path)
	if os.IsNotExist(err) {
		return map[string]usageState{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return map[string]usageState{}, nil
	}
	states := map[string]usageState{}
	if err := json.Unmarshal(data, &states); err != nil {
		return nil, fmt.Errorf("corrupt usage counter file %s: %w", c.path, err)
	}
	return states, nil
}

func (c *UsageCounter) saveAll(states map[string]usageState) error {
	data, err := json.Marshal(states)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0o600)
}

// windowState возвращает состояние metric, сбросив окно, если оно истекло.
// periodSecs == 0 — лимит на весь срок действия (как UsageQuota.period_secs
// == None в токене): окно никогда не сбрасывается само.
//
// Вычитание беззнаковое: при откате системных часов назад nowUnix может
// оказаться меньше windowStart, что даёт возврату huge-значение и
// ложное "окно истекло" (досрочный сброс счётчика). Это не угроза
// безопасности в нашу сторону — клиент в худшем случае получает
// нежданный лишний сброс лимита, не обход верификации токена.
func windowState(state usageState, periodSecs uint64, nowUnix uint64) usageState {
	if periodSecs > 0 && nowUnix-state.WindowStart >= periodSecs {
		return usageState{WindowStart: nowUnix, Count: 0}
	}
	return state
}

// Consume пытается учесть одну единицу metric. Возвращает allowed=false
// без изменения состояния на диске, если лимит уже достигнут.
func (c *UsageCounter) Consume(metric string, limit, periodSecs uint64, now time.Time) (allowed bool, remaining uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	states, err := c.loadAll()
	if err != nil {
		return false, 0, err
	}

	state := windowState(states[metric], periodSecs, uint64(now.Unix()))
	if state.Count >= limit {
		return false, 0, nil
	}

	state.Count++
	states[metric] = state
	if err := c.saveAll(states); err != nil {
		return false, 0, err
	}
	return true, limit - state.Count, nil
}

// Remaining сообщает текущий остаток без изменения счётчика — для
// отображения в UI продукта ("осталось 42 из 100 в этом месяце").
func (c *UsageCounter) Remaining(metric string, limit, periodSecs uint64, now time.Time) (remaining uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	states, err := c.loadAll()
	if err != nil {
		return 0, err
	}
	state := windowState(states[metric], periodSecs, uint64(now.Unix()))
	if state.Count >= limit {
		return 0, nil
	}
	return limit - state.Count, nil
}
