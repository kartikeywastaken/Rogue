package llm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"
)

type HTTPError struct {
	Provider string
	Status   int
	Message  string
}

func (failure *HTTPError) Error() string {
	return fmt.Sprintf("%s HTTP %d: %s", failure.Provider, failure.Status, failure.Message)
}

func transient(status int) bool {
	return status == 429 || status == 500 || status == 502 || status == 503 || status == 504 || status == 529
}

func retryDelay(header string, attempt int) time.Duration {
	delay := time.Duration(1<<attempt) * 200 * time.Millisecond
	if seconds, err := strconv.Atoi(header); err == nil && seconds >= 0 {
		delay = time.Duration(seconds) * time.Second
	} else if deadline, err := http.ParseTime(header); err == nil {
		delay = time.Until(deadline)
	}
	if delay < 0 {
		delay = 0
	}
	if delay > 10*time.Second {
		delay = 10 * time.Second
	}
	return delay
}

// post retries only before a response stream exists. Once the caller can see
// text or a tool call, the application must decide what to do; transport retry
// must never replay an already executed tool.
func post(ctx context.Context, client *http.Client, retries, outputLimit int, body []byte, build func() (*http.Request, error)) (*http.Response, *reservation, error) {
	// API credentials belong to this endpoint, never a redirected destination.
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	retries = min(max(retries, 0), 3)
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		request, err := build()
		if err != nil {
			return nil, nil, err
		}
		allowance, err := reserve(ctx, len(body), outputLimit)
		if err != nil {
			return nil, nil, err
		}
		response, err := copyClient.Do(request)
		if err != nil {
			allowance.finish(Usage{}, false)
			return nil, nil, err
		}
		if !transient(response.StatusCode) || attempt >= retries {
			return response, allowance, nil
		}
		response.Body.Close()
		allowance.finish(Usage{}, false)
		delay := retryDelay(response.Header.Get("Retry-After"), attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, ctx.Err()
		case <-timer.C:
		}
	}
}

type Fallback struct {
	Provider Provider
	Models   []string
}

func (fallback *Fallback) ChatStream(ctx context.Context, model string, messages []Message, tools []ToolDef) (<-chan StreamDelta, error) {
	choices := []string{model}
	for _, candidate := range fallback.Models {
		if !slices.Contains(choices, candidate) {
			choices = append(choices, candidate)
		}
	}
	var last error
	for index, candidate := range choices {
		stream, err := fallback.Provider.ChatStream(ctx, candidate, messages, tools)
		if err == nil {
			if index == 0 {
				return stream, nil
			}
			output := make(chan StreamDelta, 64)
			go func() {
				defer close(output)
				select {
				case output <- StreamDelta{Notice: "using configured fallback model " + candidate}:
				case <-ctx.Done():
					return
				}
				for delta := range stream {
					select {
					case output <- delta:
					case <-ctx.Done():
						return
					}
				}
			}()
			return output, nil
		}
		last = err
		var responseError *HTTPError
		if errors.Is(err, ErrBudget) || ctx.Err() != nil || (errors.As(err, &responseError) && (responseError.Status == 401 || responseError.Status == 403)) {
			break
		}
	}
	return nil, last
}
