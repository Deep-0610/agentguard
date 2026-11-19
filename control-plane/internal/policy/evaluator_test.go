package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvaluateSendsInputAndParsesDecision(t *testing.T){
	server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.URL.Path!="/v1/data/agentguard/authz/decision"{t.Fatalf("unexpected OPA path %s",r.URL.Path)}
		w.Header().Set("Content-Type","application/json")
		_,_=w.Write([]byte(`{"result":{"effect":"deny","rule_id":"default-deny","reason":"no match"}}`))
	}))
	defer server.Close()
	decision,err:=New(server.URL).Evaluate(context.Background(),map[string]any{"action":"unknown"})
	if err!=nil{t.Fatal(err)}
	if decision.Effect!="deny"||decision.RuleID!="default-deny"{t.Fatalf("unexpected decision: %+v",decision)}
}
func TestEvaluateFailsClosedWhenOPAUnavailable(t *testing.T){
	_,err:=New("").Evaluate(context.Background(),map[string]any{})
	if err==nil{t.Fatal("expected missing OPA to fail closed")}
}
