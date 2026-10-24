from client import AgenticOAuth2JwtIntrospectionGuardClient
import json, sys
sys.stdout.reconfigure(encoding='utf-8')

def main():
    guard = AgenticOAuth2JwtIntrospectionGuardClient(secret_key="my_enterprise_secure_vault_key")
    print("=== AGENTIC OAUTH2 JWT INTROSPECTION GUARD ===")
    
    # 1. Valid token with ample time
    valid_token = guard.mint_test_token("agent_svc_99", ["read:db", "write:orders"], expires_in_sec=1800)
    res_valid = guard.introspect_token(valid_token, required_scopes=["read:db"])
    print(f"1. Valid Token: {res_valid['status']} (Action: {res_valid['recommended_action']}, TTL: {res_valid['remaining_seconds']}s)")

    # 2. Expiring soon token (triggers proactive refresh)
    expiring_token = guard.mint_test_token("agent_svc_99", ["read:db"], expires_in_sec=120) # 2 mins < 5 mins
    res_expiring = guard.introspect_token(expiring_token, required_scopes=["read:db"])
    print(f"2. Expiring Token: Proactive Refresh Recommended={res_expiring['proactive_refresh_recommended']} (Action: {res_expiring['recommended_action']})")

    # 3. Missing required scope
    res_scope = guard.introspect_token(valid_token, required_scopes=["admin:delete_all"])
    print(f"3. Scope Evaluation: Valid={res_scope['valid']} (Error: {res_scope.get('error_code')}, Missing: {res_scope.get('missing_scopes')})")

if __name__ == "__main__":
    main()
