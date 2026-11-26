package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"rogue/internal/agent"
	"rogue/internal/arsenal"
	"rogue/internal/domain"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/operator"
	"rogue/internal/research"
)

func(harness *Harness) runChild(ctx context.Context,state *RunState,task mission.Task,name string,args json.RawMessage)(*arsenal.Result,error){
	state.mu.Lock()
	if state.Control.Snapshot().Status!=mission.Active||ctx.Err()!=nil{state.mu.Unlock();return nil,errors.New("mission is not active")}
	if state.toolCalls>=harness.opts.MaxToolCalls{state.mu.Unlock();return nil,agent.ErrToolLimit};state.toolCalls++;state.mu.Unlock()
	profile:=operator.Profiles()[task.Archetype]
	call:=llm.ToolCall{ID:domain.ID(),Type:"function",Function:llm.FuncCall{Name:name,Arguments:string(args)}}
	if err:=state.recordIntent(task,profile,call);err!=nil{return nil,err}
	started:=time.Now().UTC();result,executionError:=harness.reg.Exec(ctx,name,args)
	if result==nil{message:="child tool returned no result";if executionError!=nil{message=executionError.Error()};result=&arsenal.Result{Success:false,Summary:message,Error:message}}
	if errors.Is(context.Cause(ctx),mission.ErrPaused){result=&arsenal.Result{Success:false,Summary:"Child operation interrupted by pause; outcome unknown",Error:mission.ErrPaused.Error()}}
	if err:=state.recordResult(task,profile,agent.Execution{Call:call,Result:result,StartedAt:started});err!=nil{return nil,err}
	for _,observation:=range state.Evidence.Observations(){if observation.TaskID==task.ID&&observation.ToolCallID==call.ID{
		data,ok:=result.Data.(map[string]any);if !ok{data=map[string]any{"result":result.Data}};data["evidence_id"]=observation.ID;result.Data=data;break
	}}
	return result,executionError
}

func validateEvidence(state *RunState,ids []string,assertion string)(any,error){
	allowed:=map[string]string{
		// Originally supported assertions
		"sql_error":            "new_database_error",
		"html_reflection":      "unescaped_html_marker_reflected",
		"authenticated_access": "authenticated_access_confirmed",
		"cleanup_absence":      "absence_verified_in_complete_response",
		// Extended assertions for real assessment coverage
		"server_error":         "server_error_observed",
		"redirect_observed":    "redirect_observed",
		"auth_bypass":          "auth_bypass_observed",
		"traversal_read":       "file_traversal_content_read",
		"ssrf_callback":        "ssrf_callback_observed",
		"command_output":       "command_output_observed",
		"ssti_evaluation":      "template_evaluation_observed",
		"xxe_data_read":        "xxe_data_read_observed",
		"open_redirect":        "open_redirect_observed",
		"idor_access":          "idor_access_observed",
		"jwt_forged":           "jwt_accepted_with_forged_claim",
		"cookie_missing_flag":  "cookie_security_flag_absent",
		"cors_misconfigured":   "cors_origin_reflected",
	}
	field,found:=allowed[assertion];if !found{return nil,fmt.Errorf("unsupported assertion %q; supported: %s; arbitrary exploitability and CVE applicability cannot be inferred",assertion,supportedAssertions(allowed))}
	type assessment struct{ID,Tool,Verdict string;Success bool}
	var results []assessment
	for _,id:=range ids{
		observation,err:=state.Evidence.Observation(id);if err!=nil{return nil,err}
		var envelope struct{Data map[string]json.RawMessage};if err=json.Unmarshal(observation.Output,&envelope);err!=nil{return nil,err}
		var value bool;_ = json.Unmarshal(envelope.Data[field],&value)
		verdict:="not_demonstrated";if observation.Success&&value{verdict="observed_primitive"}
		results=append(results,assessment{ID:id,Tool:observation.Tool,Verdict:verdict,Success:observation.Success})
	}
	return map[string]any{"assertion":assertion,"results":results,"exploit_confirmed":false,"limitation":"Validation confirms only the named recorded primitive, not an arbitrary exploit chain."},nil
}

func surfaceResearch(state *RunState)any{
	state.mu.Lock();defer state.mu.Unlock()
	snapshot:=state.Targets.Snapshot()
	type gap struct{Target,Question string;Evidence []string}
	var gaps []gap
	for _,host:=range snapshot.Hosts{for _,service:=range host.Services{
		if service.Product==""||service.Version==""{gaps=append(gaps,gap{Target:host.Name,Question:"Confirm product/version before CVE applicability review; a port-table service label is not identification.",Evidence:service.Evidence})}
	}}
	return map[string]any{"inventory":snapshot,"research_gaps":gaps,"zero_day_discovery_claimed":false}
}

func chainResearch(state *RunState)any{
	state.mu.Lock();defer state.mu.Unlock()
	evidence:=state.Evidence.PublicSnapshot();evidence.Observations=state.Evidence.Observations()
	return map[string]any{"observed_access_paths":observedPaths(Report{Evidence:evidence}),"candidate_chains":research.MatchChains(evidence.Findings),"reference_templates":research.Chains(),"exploit_chain_execution_claimed":false}
}

// supportedAssertions returns a sorted comma-separated list of valid assertion names.
func supportedAssertions(allowed map[string]string) string {
	keys := make([]string, 0, len(allowed))
	for k := range allowed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += k
	}
	return out
}
