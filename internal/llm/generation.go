package llm

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

const initialOutputTokens = 2048
const defaultOutputCeiling = 8192

var ErrOutputLimit = errors.New("model output limit reached")

// OutputLimitError means the provider explicitly finished at its token limit.
// It is not a transport failure, and never contains executable partial calls.
type OutputLimitError struct {
	Limit, Ceiling int
}

func (failure *OutputLimitError) Error() string {
	if failure.Limit == 0 {
		return "model output limit reached before the response completed"
	}
	return fmt.Sprintf("model output limit reached (%d tokens; configured ceiling %d); use a shorter response or increase ROGUE_MAX_OUTPUT_TOKENS", failure.Limit, failure.Ceiling)
}

func (*OutputLimitError) Unwrap() error { return ErrOutputLimit }

func (failure *OutputLimitError) NextLimit() int {
	if failure.Limit <= 0 || failure.Limit >= failure.Ceiling {
		return 0
	}
	return min(failure.Limit*2, failure.Ceiling)
}

type outputLimitKey struct{}
type outputLimitsKey struct{}
type outputLimits struct {
	limit, ceiling int
	model          string
	hints          *sync.Map
}

// WithOutputLimit requests a larger allowance for one response. Each provider
// still clamps it to the configured ceiling; shared clients are never mutated.
func WithOutputLimit(ctx context.Context, limit int) context.Context {
	return context.WithValue(ctx, outputLimitKey{}, limit)
}

func generationContext(ctx context.Context, ceiling int, model string, hints *sync.Map) (context.Context, int) {
	if ceiling <= 0 {
		ceiling = defaultOutputCeiling
	}
	limit := min(initialOutputTokens, ceiling)
	if learned, ok := hints.Load(model); ok {
		limit = min(max(limit, learned.(int)), ceiling)
	}
	if requested, ok := ctx.Value(outputLimitKey{}).(int); ok && requested > 0 {
		limit = min(max(limit, requested), ceiling)
	}
	return context.WithValue(ctx, outputLimitsKey{}, outputLimits{limit: limit, ceiling: ceiling, model: model, hints: hints}), limit
}

// Remember a successfully expanded allowance per model, avoiding the same
// truncation on every operator. This stores no prompts or mission evidence.
func rememberGeneration(ctx context.Context) {
	limits, _ := ctx.Value(outputLimitsKey{}).(outputLimits)
	if limits.hints == nil || limits.limit <= initialOutputTokens {
		return
	}
	for {
		previous, loaded := limits.hints.LoadOrStore(limits.model, limits.limit)
		if !loaded || previous.(int) >= limits.limit {
			return
		}
		if limits.hints.CompareAndSwap(limits.model, previous, limits.limit) {
			return
		}
	}
}

func outputLimitFailure(ctx context.Context) *OutputLimitError {
	limits, _ := ctx.Value(outputLimitsKey{}).(outputLimits)
	return &OutputLimitError{Limit: limits.limit, Ceiling: limits.ceiling}
}
