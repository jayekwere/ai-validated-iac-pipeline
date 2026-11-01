"""Require remote review boundaries before secret-bearing generation or publication."""
import json, os, urllib.request
REPO='jayekwere/ai-validated-iac-pipeline'
QUERY='query { repository(owner:"jayekwere", name:"ai-validated-iac-pipeline") { ref(qualifiedName:"refs/heads/main") { branchProtectionRule { isAdminEnforced requiresApprovingReviews requiredApprovingReviewCount requiresCodeOwnerReviews dismissesStaleReviews requiresStatusChecks requiredStatusCheckContexts } } } }'
def branch_from_graphql(value):
    if value.get('errors'): raise ValueError('Protection query returned errors')
    rule=value.get('data',{}).get('repository',{}).get('ref',{}).get('branchProtectionRule')
    if not rule or rule.get('requiresApprovingReviews') is not True or rule.get('requiresStatusChecks') is not True:
        raise ValueError('Complete branch review and status protections required')
    return {'enforce_admins':{'enabled':rule.get('isAdminEnforced')},'required_pull_request_reviews':{'required_approving_review_count':rule.get('requiredApprovingReviewCount',0),'require_code_owner_reviews':rule.get('requiresCodeOwnerReviews'),'dismiss_stale_reviews':rule.get('dismissesStaleReviews')},'required_status_checks':{'contexts':rule.get('requiredStatusCheckContexts') or []}}

def check(branch,envs):
    assert branch.get('enforce_admins',{}).get('enabled') is True,'Administrator enforcement required'
    reviews=branch.get('required_pull_request_reviews',{})
    assert reviews.get('required_approving_review_count',0)>=1 and reviews.get('require_code_owner_reviews') and reviews.get('dismiss_stale_reviews'),'Protected human review required'
    statuses=branch.get('required_status_checks',{})
    names=set(statuses.get('contexts',[]))|{s['context'] for s in statuses.get('checks',[])}
    assert {'tests','admission','trusted-candidate'}<=names,'Required checks missing'
    for env in envs:
        assert env.get('can_admins_bypass') is False,'Environment administrator bypass must be disabled'
        rules=[r for r in env.get('protection_rules',[]) if r.get('type')=='required_reviewers']
        assert rules and rules[0].get('reviewers') and rules[0].get('prevent_self_review') is True,'Required environment reviewers and self-review prevention missing'
        policy=env.get('deployment_branch_policy')
        assert policy and policy.get('protected_branches') is True,'Protected branches only required'
def main():
    token=os.environ.get('GH_TOKEN','')
    if not token:raise SystemExit('GitHub authentication required')
    def get(path):
        req=urllib.request.Request('https://api.github.com/repos/'+REPO+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=30) as r:return json.load(r)
    # The REST branch protection endpoint needs Administration:read, which a
    # least-privilege GITHUB_TOKEN cannot hold. GraphQL exposes the matching
    # protection rule using repository read access; errors fail closed.
    req=urllib.request.Request('https://api.github.com/graphql',data=json.dumps({'query':QUERY}).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=30) as r: branch=branch_from_graphql(json.load(r))
    check(branch,[get('/environments/'+n) for n in ['ai-generation','pr-publication']]);print('Protected review boundaries verified')
if __name__=='__main__':main()
