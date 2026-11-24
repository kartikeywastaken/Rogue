package arsenal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

type TaskProposal struct {
	Title, Role, Target, BeforeTask string
	EvidenceIDs, RequiredTools      []string
}
type Services struct {
	Evidence   func([]string) (any, error)
	Propose    func(TaskProposal) (any, error)
	Credential func(string, string) (string, error)
	Candidates func() any
	Mission func()any
	Surface func()any
	Chains func()any
	ValidateEvidence func([]string,string)(any,error)
	RunChild func(context.Context,string,json.RawMessage)(*Result,error)
}
type servicesKey struct{}

func WithServices(ctx context.Context, services Services) context.Context {
	return context.WithValue(ctx, servicesKey{}, services)
}

func RegisterMissionTools(registry *Registry) {
	registry.Register(&Tool{Name: "cve_correlate", Category: "context", Internal: true, Description: "Correlate observed product/version evidence with this mission's published CVE descriptions. Returns review candidates, never confirmed applicability or exploitation.", Parameters: stringSchema(nil), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		services, _ := ctx.Value(servicesKey{}).(Services)
		if services.Candidates == nil {
			return nil, errors.New("mission candidate service unavailable")
		}
		return &Result{Success: true, Summary: "CVE candidates correlated; applicability requires review", Data: map[string]any{"candidates": services.Candidates()}}, nil
	}})
	registry.Register(&Tool{Name: "evidence_get", Category: "context", Internal: true, Description: "Retrieve up to eight exact observation IDs from this mission's protected vault. No cross-mission lookup. Credentials and original binary artifacts are excluded.", Parameters: stringSchema([]string{"ids"}, "ids"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ IDs string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		ids, err := boundedList(args.IDs, 8)
		if err != nil {
			return nil, err
		}
		services, _ := ctx.Value(servicesKey{}).(Services)
		if services.Evidence == nil {
			return nil, errors.New("mission evidence service unavailable")
		}
		data, err := services.Evidence(ids)
		if err != nil {
			return nil, err
		}
		return &Result{Success: true, Summary: "Retrieved recorded mission observations", Data: data}, nil
	}})
	registry.Register(&Tool{Name: "propose_task", Category: "control", Internal: true, Description: "Coordinator only: submit a JSON-encoded task proposal with Title, Role, Target, BeforeTask, EvidenceIDs and RequiredTools. Validated against observed evidence, role capabilities, scope, task limits and remaining mission budget. Does not change rules.", Parameters: stringSchema([]string{"proposal"}, "proposal"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct{ Proposal string }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		var proposal TaskProposal
		if len(args.Proposal) > 8192 {
			return nil, errors.New("proposal exceeds 8 KiB")
		}
		decoder := json.NewDecoder(strings.NewReader(args.Proposal))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&proposal); err != nil {
			return nil, err
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return nil, errors.New("proposal must contain one JSON object")
		}
		services, _ := ctx.Value(servicesKey{}).(Services)
		if services.Propose == nil {
			return nil, errors.New("supervisor service unavailable")
		}
		data, err := services.Propose(proposal)
		if err != nil {
			return nil, err
		}
		return &Result{Success: true, Summary: "Evidence-driven task accepted by mission control", Data: data}, nil
	}})
}
