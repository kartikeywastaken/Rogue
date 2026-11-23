package llm

import (
	"context"
	"errors"
	"math"
	"sync"
)

var ErrBudget = errors.New("model request would exceed the configured budget")

type BudgetLimits struct {
	Tokens           int
	Dollars          float64
	InputPerMillion  float64
	OutputPerMillion float64
}

type Spending struct {
	PricingConfigured bool
	InputTokens       int
	OutputTokens      int
	Dollars           float64
	ReservedTokens    int
	ReservedDollars   float64
	UncertainRequests int
}

// Budget reserves a conservative allowance before each HTTP attempt. If a
// response loses usage information, the allowance remains spent rather than
// assuming that an interrupted request was free.
type Budget struct {
	mu       sync.Mutex
	limits   BudgetLimits
	spending Spending
}

type budgetKey struct{}

func NewBudget(limits BudgetLimits) (*Budget, error) {
	if limits.Tokens < 1 || limits.Dollars < 0 || math.IsNaN(limits.Dollars) || math.IsInf(limits.Dollars, 0) || limits.InputPerMillion < 0 || limits.OutputPerMillion < 0 || math.IsNaN(limits.InputPerMillion) || math.IsNaN(limits.OutputPerMillion) || math.IsInf(limits.InputPerMillion, 0) || math.IsInf(limits.OutputPerMillion, 0) {
		return nil, errors.New("invalid model budget")
	}
	if limits.Dollars > 0 && (limits.InputPerMillion <= 0 || limits.OutputPerMillion <= 0) {
		return nil, errors.New("a dollar budget requires explicit input and output prices")
	}
	return &Budget{limits: limits, spending: Spending{PricingConfigured: limits.InputPerMillion > 0 && limits.OutputPerMillion > 0}}, nil
}

func WithBudget(ctx context.Context, budget *Budget) context.Context {
	return context.WithValue(ctx, budgetKey{}, budget)
}

func (budget *Budget) Snapshot() Spending {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.spending
}

type reservation struct {
	budget *Budget
	input  int
	output int
	cost   float64
}

func reserve(ctx context.Context, requestBytes, outputLimit int) (*reservation, error) {
	budget, _ := ctx.Value(budgetKey{}).(*Budget)
	if budget == nil {
		return &reservation{}, nil
	}
	// A byte-sized input estimate deliberately overestimates typical tokenization.
	// Extra allowance covers protocol framing that is absent from the JSON body.
	input := requestBytes + 1024
	budget.mu.Lock()
	defer budget.mu.Unlock()
	cost := (float64(input)*budget.limits.InputPerMillion + float64(outputLimit)*budget.limits.OutputPerMillion) / 1_000_000
	spent := budget.spending
	if spent.InputTokens+spent.OutputTokens+spent.ReservedTokens+input+outputLimit > budget.limits.Tokens {
		return nil, ErrBudget
	}
	if budget.limits.Dollars > 0 && spent.Dollars+spent.ReservedDollars+cost > budget.limits.Dollars {
		return nil, ErrBudget
	}
	budget.spending.ReservedTokens += input + outputLimit
	budget.spending.ReservedDollars += cost
	return &reservation{budget: budget, input: input, output: outputLimit, cost: cost}, nil
}

func (request *reservation) finish(usage Usage, complete bool) {
	if request.budget == nil {
		return
	}
	budget := request.budget
	budget.mu.Lock()
	defer budget.mu.Unlock()
	budget.spending.ReservedTokens -= request.input + request.output
	budget.spending.ReservedDollars -= request.cost
	input, output := request.input, request.output
	if complete && usage.PromptTokens > 0 {
		input, output = usage.PromptTokens, usage.CompletionTokens
	} else {
		budget.spending.UncertainRequests++
	}
	budget.spending.InputTokens += input
	budget.spending.OutputTokens += output
	budget.spending.Dollars += (float64(input)*budget.limits.InputPerMillion + float64(output)*budget.limits.OutputPerMillion) / 1_000_000
}

func account(ctx context.Context, stream <-chan StreamDelta, request *reservation) <-chan StreamDelta {
	output := make(chan StreamDelta, 64)
	go func() {
		defer close(output)
		var usage Usage
		complete := false
		settled := false
		defer func() {
			if !settled {
				request.finish(usage, complete)
			}
		}()
		for delta := range stream {
			usage.PromptTokens = max(usage.PromptTokens, delta.Usage.PromptTokens)
			usage.CompletionTokens = max(usage.CompletionTokens, delta.Usage.CompletionTokens)
			complete = complete || delta.Done
			if delta.Done {
				request.finish(usage, true)
				settled = true
			}
			select {
			case output <- delta:
			case <-ctx.Done():
				return
			}
		}
	}()
	return output
}
