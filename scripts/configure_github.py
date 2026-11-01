"""Configure authorized repository review boundaries using the authenticated gh session."""
import json, subprocess
REPO='jayekwere/ai-validated-iac-pipeline'
def api(path,method='GET',body=None):
    command=['gh','api','--method',method,'repos/'+REPO+path]
    if body is not None:command+=['--input','-']
    result=subprocess.run(command,input=json.dumps(body) if body is not None else None,text=True,capture_output=True,check=True,timeout=60)
    return json.loads(result.stdout) if result.stdout.strip() else None
def main():
    user=json.loads(subprocess.run(['gh','api','user'],check=True,capture_output=True,text=True).stdout)
    if user['login']!='jayekwere':raise SystemExit('Expected repository owner account')
    api('/branches/main/protection','PUT',{'required_status_checks':{'strict':True,'contexts':['tests','admission','trusted-candidate']},'enforce_admins':True,'required_pull_request_reviews':{'dismiss_stale_reviews':True,'require_code_owner_reviews':True,'required_approving_review_count':1},'restrictions':None,'required_linear_history':True,'allow_force_pushes':False,'allow_deletions':False,'required_conversation_resolution':True})
    for name in ['ai-generation','pr-publication']:
        api('/environments/'+name,'PUT',{'wait_timer':0,'prevent_self_review':True,'reviewers':[{'type':'User','id':user['id']}],'deployment_branch_policy':{'protected_branches':True,'custom_branch_policies':False}})
    api('','PATCH',{'allow_auto_merge':False,'delete_branch_on_merge':True,'security_and_analysis':{'secret_scanning':{'status':'enabled'},'secret_scanning_push_protection':{'status':'enabled'}}})
    print('Review boundaries configured. A different authorized reviewer must approve runs they did not initiate.')
if __name__=='__main__':main()
