package pdp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// opaQuery is the Rego query path for capiscio policy evaluation.
// All Rego modules must define rules under package capiscio.policy.
const opaQuery = "data.capiscio.policy"

// OPALocalClient implements pip.PDPClient using an embedded OPA evaluator.
// It evaluates policy decisions in-process using Rego modules and data
// pulled from the capiscio-server bundle endpoint.
//
// Thread-safety: Evaluate takes a read lock, LoadBundle takes a write lock.
// Multiple concurrent evaluations proceed without blocking each other.
type OPALocalClient struct {
	mu             sync.RWMutex
	preparedQuery  *rego.PreparedEvalQuery
	bundleLoadedAt time.Time
	logger         *slog.Logger
}

// OPALocalOption configures an OPALocalClient.
type OPALocalOption func(*OPALocalClient)

// WithOPALogger sets the logger for the OPA evaluator.
func WithOPALogger(l *slog.Logger) OPALocalOption {
	return func(c *OPALocalClient) {
		if l != nil {
			c.logger = l
		}
	}
}

// NewOPALocalClient creates a new local OPA evaluator.
// The client starts without a loaded policy — call LoadBundle before evaluating.
func NewOPALocalClient(opts ...OPALocalOption) *OPALocalClient {
	c := &OPALocalClient{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Evaluate sends a PIP decision request through the local OPA evaluator.
// Returns an error if no bundle is loaded (the PEP handles this per enforcement mode).
func (c *OPALocalClient) Evaluate(ctx context.Context, req *pip.DecisionRequest) (*pip.DecisionResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("pdp: nil decision request")
	}

	c.mu.RLock()
	pq := c.preparedQuery
	c.mu.RUnlock()

	if pq == nil {
		return nil, fmt.Errorf("pdp: no policy bundle loaded")
	}

	input := buildOPAInput(req)

	results, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("pdp: rego evaluation failed: %w", err)
	}

	return mapOPAResult(results)
}

// LoadBundle compiles Rego modules and data into a prepared query.
// This takes a write lock and atomically replaces the current prepared query.
// Callers should use BundleContents from a successful BundleClient.Fetch.
func (c *OPALocalClient) LoadBundle(ctx context.Context, modules map[string]string, data map[string]interface{}) error {
	if len(modules) == 0 {
		return fmt.Errorf("pdp: no rego modules provided")
	}

	opts := []func(*rego.Rego){
		rego.Query(opaQuery),
	}

	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}

	if data != nil {
		store, err := newInMemStore(data)
		if err != nil {
			return err
		}
		opts = append(opts, rego.Store(store))
	}

	r := rego.New(opts...)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("pdp: failed to compile policy: %w", err)
	}

	c.mu.Lock()
	c.preparedQuery = &pq
	c.bundleLoadedAt = time.Now()
	loadedAt := c.bundleLoadedAt
	c.mu.Unlock()

	c.logger.Info("policy bundle loaded",
		slog.Int("modules", len(modules)),
		slog.Time("loaded_at", loadedAt),
	)

	return nil
}

// BundleAge returns the duration since the last bundle was loaded.
// Returns 0 if no bundle has been loaded.
func (c *OPALocalClient) BundleAge() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.bundleLoadedAt.IsZero() {
		return 0
	}
	return time.Since(c.bundleLoadedAt)
}

// HasBundle reports whether a policy bundle is currently loaded.
func (c *OPALocalClient) HasBundle() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.preparedQuery != nil
}

// buildOPAInput maps a PIP DecisionRequest to the OPA input document.
// The structure matches RFC-005 Appendix B.2.
func buildOPAInput(req *pip.DecisionRequest) map[string]interface{} {
	input := map[string]interface{}{
		"subject": map[string]interface{}{
			"did":         req.Subject.DID,
			"badge_jti":   req.Subject.BadgeJTI,
			"ial":         req.Subject.IAL,
			"trust_level": req.Subject.TrustLevel,
		},
		"action": map[string]interface{}{
			"operation": req.Action.Operation,
		},
		"resource": map[string]interface{}{
			"identifier": req.Resource.Identifier,
		},
		"context": map[string]interface{}{
			"txn_id":           req.Context.TxnID,
			"enforcement_mode": req.Context.EnforcementMode,
		},
		"environment": map[string]interface{}{},
	}

	action := input["action"].(map[string]interface{})
	if req.Action.CapabilityClass != nil {
		action["capability_class"] = *req.Action.CapabilityClass
	}
	if req.Action.MCPTool != nil {
		action["mcp_tool"] = *req.Action.MCPTool
	}

	ctxMap := input["context"].(map[string]interface{})
	if req.Context.HopID != nil {
		ctxMap["hop_id"] = *req.Context.HopID
	}
	if req.Context.EnvelopeID != nil {
		ctxMap["envelope_id"] = *req.Context.EnvelopeID
	}
	if req.Context.DelegationDepth != nil {
		ctxMap["delegation_depth"] = *req.Context.DelegationDepth
	}

	env := input["environment"].(map[string]interface{})
	if req.Environment.Workspace != nil {
		env["workspace"] = *req.Environment.Workspace
	}
	if req.Environment.PEPID != nil {
		env["pep_id"] = *req.Environment.PEPID
	}
	if req.Environment.Time != nil {
		env["time"] = *req.Environment.Time
	}

	return input
}

// mapOPAResult converts OPA evaluation results to a PIP DecisionResponse.
func mapOPAResult(results rego.ResultSet) (*pip.DecisionResponse, error) {
	if len(results) == 0 {
		return nil, fmt.Errorf("pdp: rego evaluation returned no results")
	}

	expr := results[0].Expressions
	if len(expr) == 0 {
		return nil, fmt.Errorf("pdp: rego evaluation returned no expressions")
	}

	policyResult, ok := expr[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("pdp: unexpected result type: %T", expr[0].Value)
	}

	decision, ok := policyResult["decision"].(string)
	if !ok || !pip.ValidDecision(decision) {
		return nil, fmt.Errorf("pdp: invalid or missing decision in policy result")
	}

	decisionID := uuid.New().String()

	reason, _ := policyResult["reason"].(string)

	var obligations []pip.Obligation
	if oblSet, ok := policyResult["obligations"]; ok {
		obligations = extractObligations(oblSet)
	}
	if obligations == nil {
		obligations = []pip.Obligation{}
	}

	return &pip.DecisionResponse{
		Decision:    decision,
		DecisionID:  decisionID,
		Obligations: obligations,
		Reason:      reason,
	}, nil
}

// extractObligations converts OPA obligation output to PIP obligations.
func extractObligations(oblSet interface{}) []pip.Obligation {
	oblSlice, ok := oblSet.([]interface{})
	if !ok {
		return nil
	}

	var obligations []pip.Obligation
	for _, item := range oblSlice {
		oblMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		oblType, _ := oblMap["type"].(string)
		if oblType == "" {
			continue
		}

		var params json.RawMessage
		if p, ok := oblMap["params"]; ok {
			if b, err := json.Marshal(p); err == nil {
				params = b
			}
		}

		obligations = append(obligations, pip.Obligation{
			Type:   oblType,
			Params: params,
		})
	}

	return obligations
}

// newInMemStore creates an OPA in-memory store from a data map.
// Deep-copies via JSON round-trip to avoid shared mutation.
func newInMemStore(data map[string]interface{}) (storage.Store, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("pdp: marshal store data: %w", err)
	}
	var clean map[string]interface{}
	if err := json.Unmarshal(b, &clean); err != nil {
		return nil, fmt.Errorf("pdp: unmarshal store data: %w", err)
	}
	return inmem.NewFromObjectWithOpts(clean, inmem.OptRoundTripOnWrite(true)), nil
}
