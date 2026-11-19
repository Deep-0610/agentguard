package store

import "context"

func (s *Store) RecordPolicyDecision(ctx context.Context,p Principal,action,effect,ruleID,reason string)error{
	return s.audit(ctx,p,"policy.decision","policy",action,map[string]any{
		"action":action,
		"effect":effect,
		"rule_id":ruleID,
		"reason":reason,
	})
}
