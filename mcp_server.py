import sys, json
from client import AgenticOAuth2JwtIntrospectionGuardClient
sys.stdout.reconfigure(encoding='utf-8')

def handle_mcp():
    guard = AgenticOAuth2JwtIntrospectionGuardClient()
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps({"status": "ready", "skill": "genpark-agentic-oauth2-jwt-introspection-guard-skill"}))
        return
    req = json.loads(sys.stdin.read() or "{}")
    token = req.get("token", "")
    scopes = req.get("required_scopes", [])
    res = guard.introspect_token(token, required_scopes=scopes)
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    handle_mcp()
