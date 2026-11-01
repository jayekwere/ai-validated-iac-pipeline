"""Configure authorized repository review boundaries using the authenticated gh session."""
import json, subprocess
from pathlib import Path
REPO='jayekwere/ai-validated-iac-pipeline'
def api(path,method='GET',body=None):
    command=['gh','api','--method',method,'repos/'+REPO+path]
    if body is not None:command+=['--input','-']
    result=subprocess.run(command,input=json.dumps(body) if body is not None else None,text=True,capture_output=True,check=True,timeout=60)
    return json.loads(result.stdout) if result.stdout.strip() else None
def main():
    user=json.loads(subprocess.run(['gh','api','user'],check=True,capture_output=True,text=True).stdout)
    if user['login']!='jayekwere':raise SystemExit('Expected repository owner account')
    api('/branches/main/protection','PUT',{'required_status_checks':{'strict':True,'contexts':['tests','admission','trusted-candidate']},'enforce_admins':True,'required_pull_request_reviews':{'dismiss_stale_reviews':True,'require_code_owner_reviews':False,'required_approving_review_count':0},'restrictions':None,'required_linear_history':True,'allow_force_pushes':False,'allow_deletions':False,'required_conversation_resolution':True})
    for name in ['ai-generation','pr-publication']:
        api('/environments/'+name,'PUT',{'wait_timer':0,'prevent_self_review':False,'can_admins_bypass':False,'reviewers':[{'type':'User','id':user['id']}],'deployment_branch_policy':{'protected_branches':True,'custom_branch_policies':False}})
    api('/environments/maintainer-approval','PUT',{'wait_timer':0,'prevent_self_review':False,'can_admins_bypass':False,'reviewers':[{'type':'User','id':user['id']}],'deployment_branch_policy':{'protected_branches':False,'custom_branch_policies':True}})
    patterns=api('/environments/maintainer-approval/deployment-branch-policies')['branch_policies']
    for pattern in patterns:
        if pattern['name']!='refs/pull/*/merge' or pattern.get('type')!='branch':api('/environments/maintainer-approval/deployment-branch-policies/'+str(pattern['id']),'DELETE')
    if not any(p['name']=='refs/pull/*/merge' and p.get('type')=='branch' for p in patterns):api('/environments/maintainer-approval/deployment-branch-policies','POST',{'name':'refs/pull/*/merge','type':'branch'})
    if api('/environments/maintainer-approval/secrets').get('total_count')!=0:raise SystemExit('PR approval environment must have no secrets')
    api('','PATCH',{'allow_auto_merge':False,'delete_branch_on_merge':True,'security_and_analysis':{'secret_scanning':{'status':'enabled'},'secret_scanning_push_protection':{'status':'enabled'}}})
    policy=json.loads((Path(__file__).resolve().parents[1]/'.github/review-ruleset.json').read_text())
    current=[r for r in api('/rulesets') if r['name']==policy['name']]
    ruleset=api('/rulesets/'+str(current[0]['id']),'PUT',policy) if current else api('/rulesets','POST',policy)
    if ruleset.get('enforcement')!='active' or ruleset.get('bypass_actors')!=[]:raise SystemExit('Ruleset must be active with no bypass actors')
    api('/actions/permissions','PUT',{'enabled':True,'allowed_actions':'selected','sha_pinning_required':True})
    api('/actions/permissions/selected-actions','PUT',{'github_owned_allowed':True,'verified_allowed':False,'patterns_allowed':[]})
    # GitHub couples PR creation and approval in this repository toggle.
    # Only the protected publication job has pull-requests:write. Human
    # approval of the required deployment remains mandatory before merge.
    api('/actions/permissions/workflow','PUT',{'default_workflow_permissions':'read','can_approve_pull_request_reviews':True})
    print('Solo approval configured. The maintainer must manually approve PR merge, generation and publication gates; no check or approval is bypassed.')
if __name__=='__main__':main()
