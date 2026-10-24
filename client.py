import hmac, hashlib, base64, json, time, sys
sys.stdout.reconfigure(encoding='utf-8')

class AgenticOAuth2JwtIntrospectionGuardClient:
    """
    Zero-dependency JWT validator and OAuth2 token refresh guard.
    Verifies HMAC-SHA256 signatures, validates expiration with clock skew tolerance,
    inspects scope permissions, and triggers proactive refresh cycles.
    """
    def __init__(self, secret_key="genpark_default_secure_signing_key", clock_skew_sec=60, refresh_headroom_sec=300):
        self.secret_key = secret_key
        self.clock_skew_sec = clock_skew_sec
        self.refresh_headroom_sec = refresh_headroom_sec # 5 minutes

    def b64url_decode(self, text):
        rem = len(text) % 4
        if rem > 0:
            text += '=' * (4 - rem)
        return base64.urlsafe_b64decode(text.encode("ascii")).decode("utf-8")

    def b64url_encode(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip('=')

    def mint_test_token(self, sub, scopes, expires_in_sec=3600):
        header = {"alg": "HS256", "typ": "JWT"}
        now = int(time.time())
        payload = {
            "sub": sub,
            "scopes": scopes,
            "iat": now,
            "nbf": now - 5,
            "exp": now + expires_in_sec,
            "iss": "genpark.ai/auth"
        }
        h_b64 = self.b64url_encode(json.dumps(header))
        p_b64 = self.b64url_encode(json.dumps(payload))
        msg = f"{h_b64}.{p_b64}".encode("ascii")
        sig = hmac.new(self.secret_key.encode("utf-8"), msg, hashlib.sha256).digest()
        sig_b64 = self.b64url_encode(sig)
        return f"{h_b64}.{p_b64}.{sig_b64}"

    def introspect_token(self, token_str, required_scopes=None, current_timestamp=None):
        now = current_timestamp or int(time.time())
        parts = token_str.strip().split('.')
        if len(parts) != 3:
            return {"status": "error", "valid": False, "error_code": "MALFORMED_JWT", "message": "Expected 3 dot-delimited segments"}

        h_b64, p_b64, sig_b64 = parts
        try:
            header = json.loads(self.b64url_decode(h_b64))
            payload = json.loads(self.b64url_decode(p_b64))
        except Exception as e:
            return {"status": "error", "valid": False, "error_code": "DECODE_ERROR", "message": str(e)}

        # Verify signature
        msg = f"{h_b64}.{p_b64}".encode("ascii")
        expected_sig = hmac.new(self.secret_key.encode("utf-8"), msg, hashlib.sha256).digest()
        expected_sig_b64 = self.b64url_encode(expected_sig)
        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            return {"status": "error", "valid": False, "error_code": "INVALID_SIGNATURE", "message": "Cryptographic signature mismatch"}

        # Validate temporal claims
        exp = payload.get("exp", 0)
        nbf = payload.get("nbf", 0)

        if now > (exp + self.clock_skew_sec):
            return {"status": "error", "valid": False, "error_code": "TOKEN_EXPIRED", "expired_at": exp, "seconds_past": now - exp}
        if now < (nbf - self.clock_skew_sec):
            return {"status": "error", "valid": False, "error_code": "TOKEN_NOT_YET_VALID", "nbf": nbf}

        # Validate scopes
        token_scopes = set(payload.get("scopes", []))
        missing_scopes = []
        if required_scopes:
            for s in required_scopes:
                if s not in token_scopes:
                    missing_scopes.append(s)

        if missing_scopes:
            return {
                "status": "error",
                "valid": False,
                "error_code": "INSUFFICIENT_SCOPE",
                "missing_scopes": missing_scopes,
                "granted_scopes": list(token_scopes)
            }

        # Check proactive refresh threshold
        remaining_sec = exp - now
        needs_proactive_refresh = remaining_sec <= self.refresh_headroom_sec

        return {
            "status": "success",
            "valid": True,
            "subject": payload.get("sub"),
            "issuer": payload.get("iss"),
            "scopes": list(token_scopes),
            "remaining_seconds": remaining_sec,
            "proactive_refresh_recommended": needs_proactive_refresh,
            "recommended_action": "TRIGGER_BACKGROUND_TOKEN_REFRESH" if needs_proactive_refresh else "PERMIT_EXECUTION"
        }
