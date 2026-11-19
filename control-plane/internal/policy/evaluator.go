package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Decision struct {
	Effect string `json:"effect"`
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}
type Evaluator struct { endpoint string; client *http.Client }
func New(endpoint string)*Evaluator{
	return &Evaluator{endpoint:strings.TrimRight(endpoint,"/"),client:&http.Client{Timeout:750*time.Millisecond}}
}
func (e *Evaluator) Enabled()bool{return e!=nil&&e.endpoint!=""}
func (e *Evaluator) Evaluate(ctx context.Context,input map[string]any)(Decision,error){
	if !e.Enabled(){return Decision{},fmt.Errorf("OPA policy service is not configured")}
	body,err:=json.Marshal(map[string]any{"input":input});if err!=nil{return Decision{},err}
	req,err:=http.NewRequestWithContext(ctx,http.MethodPost,e.endpoint+"/v1/data/agentguard/authz/decision",bytes.NewReader(body));if err!=nil{return Decision{},err}
	req.Header.Set("Content-Type","application/json")
	resp,err:=e.client.Do(req);if err!=nil{return Decision{},fmt.Errorf("OPA evaluation unavailable: %w",err)}
	defer resp.Body.Close()
	if resp.StatusCode<200||resp.StatusCode>=300{return Decision{},fmt.Errorf("OPA returned HTTP %d",resp.StatusCode)}
	raw,err:=io.ReadAll(io.LimitReader(resp.Body,64<<10));if err!=nil{return Decision{},err}
	var envelope struct{Result *Decision `json:"result"`}
	if err=json.Unmarshal(raw,&envelope);err!=nil{return Decision{},fmt.Errorf("invalid OPA response: %w",err)}
	if envelope.Result==nil||!oneOf(envelope.Result.Effect,"allow","deny","approval_required"){return Decision{},fmt.Errorf("OPA response did not contain a valid decision")}
	return *envelope.Result,nil
}
func oneOf(v string,values ...string)bool{for _,candidate:=range values{if v==candidate{return true}};return false}

func (e *Evaluator) Ready(ctx context.Context) error {
	if !e.Enabled() { return fmt.Errorf("OPA policy service is not configured") }
	req,err:=http.NewRequestWithContext(ctx,http.MethodGet,e.endpoint+"/health",nil)
	if err!=nil{return err}
	resp,err:=e.client.Do(req)
	if err!=nil{return fmt.Errorf("OPA health check failed: %w",err)}
	defer resp.Body.Close()
	if resp.StatusCode<200||resp.StatusCode>=300{return fmt.Errorf("OPA health check returned HTTP %d",resp.StatusCode)}
	return nil
}
