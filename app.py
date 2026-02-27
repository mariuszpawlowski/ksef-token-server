"""
KSeF 2.0 - serwer API do autoryzacji tokenem.
Wystawia endpoint /ksef/token, który Make.com wywołuje przez HTTP module.
Zwraca accessToken (JWT) do dalszego użycia w KSeF API.

Uruchomienie:
  pip install flask cryptography requests
  python ksef_server.py

Endpoint:
  POST /ksef/token
  Body (JSON):
    {
      "nip": "1234567890",
      "token": "token"
    }

  Odpowiedź (JSON):
    {
      "accessToken": "eyJhbG...",
      "accessTokenValidUntil": "2026-02-27T21:32:45+00:00",
      "refreshToken": "eyJhbG...",
      "refreshTokenValidUntil": "2026-03-06T21:17:45+00:00"
    }
"""

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import base64
import requests as http_requests
import time
import os

app = Flask(__name__)

KSEF_BASE_URL = "https://api.ksef.mf.gov.pl/v2"

# Klucz API do zabezpieczenia endpointów (ustaw w zmiennych środowiskowych)
API_KEY = os.environ.get("API_KEY", "")

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def _check_api_key():
    """Sprawdza nagłówek X-API-Key (pomijane jeśli API_KEY nie ustawiony)."""
    if not API_KEY:
        return None  # brak klucza = brak ochrony (dev mode)
    key = request.headers.get("X-API-Key", "")
    if key != API_KEY:
        return jsonify({"error": "Nieprawidłowy API key"}), 401
    return None


def _get_challenge(nip):
    resp = http_requests.post(
        f"{KSEF_BASE_URL}/auth/challenge",
        json={"contextIdentifier": {"type": "Nip", "value": nip}},
        headers=HEADERS,
    )
    resp.raise_for_status()
    return resp.json()


def _get_rsa_public_key():
    resp = http_requests.get(
        f"{KSEF_BASE_URL}/security/public-key-certificates",
        headers={"Accept": "application/json"},
    )
    resp.raise_for_status()
    for cert_info in resp.json():
        if "KsefTokenEncryption" in cert_info.get("usage", []):
            cert_der = base64.b64decode(cert_info["certificate"])
            cert = x509.load_der_x509_certificate(cert_der)
            return cert.public_key()
    raise RuntimeError("Brak certyfikatu KsefTokenEncryption")


def _encrypt_token(token, timestamp_ms, public_key):
    plain = f"{token}|{timestamp_ms}".encode("utf-8")
    cipher = public_key.encrypt(
        plain,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(cipher).decode("utf-8")


def _auth_ksef_token(nip, challenge, encrypted_token):
    resp = http_requests.post(
        f"{KSEF_BASE_URL}/auth/ksef-token",
        json={
            "challenge": challenge,
            "contextIdentifier": {"type": "Nip", "value": nip},
            "encryptedToken": encrypted_token,
        },
        headers=HEADERS,
    )
    resp.raise_for_status()
    return resp.json()


def _wait_for_auth(reference_number, operation_token, max_attempts=15):
    url = f"{KSEF_BASE_URL}/auth/{reference_number}"
    auth_headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {operation_token}",
    }
    for _ in range(max_attempts):
        time.sleep(2)
        resp = http_requests.get(url, headers=auth_headers)
        resp.raise_for_status()
        data = resp.json()
        code = data.get("status", {}).get("code", 0)
        if code == 200:
            return data
        if code >= 400:
            desc = data.get("status", {}).get("description", "")
            raise RuntimeError(f"Auth failed: {code} - {desc}")
    raise TimeoutError("Auth timeout")


def _redeem_tokens(operation_token):
    resp = http_requests.post(
        f"{KSEF_BASE_URL}/auth/token/redeem",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {operation_token}",
        },
    )
    resp.raise_for_status()
    return resp.json()


# =============================================================
#  ENDPOINT:  POST /ksef/token
# =============================================================
@app.route("/ksef/token", methods=["POST"])
def ksef_token():
    """
    Make.com wywołuje ten endpoint (HTTP module → POST).
    Zwraca accessToken i refreshToken.
    """
    auth_error = _check_api_key()
    if auth_error:
        return auth_error

    body = request.get_json(force=True)
    nip = body.get("nip")
    token = body.get("token")

    if not nip or not token:
        return jsonify({"error": "Wymagane pola: nip, token"}), 400

    try:
        # 1. Challenge
        challenge_data = _get_challenge(nip)

        # 2. Klucz publiczny RSA
        public_key = _get_rsa_public_key()

        # 3. Szyfrowanie
        encrypted = _encrypt_token(token, challenge_data["timestampMs"], public_key)

        # 4. Uwierzytelnienie
        auth_data = _auth_ksef_token(nip, challenge_data["challenge"], encrypted)
        operation_token = auth_data["authenticationToken"]["token"]
        reference_number = auth_data["referenceNumber"]

        # 5. Polling
        _wait_for_auth(reference_number, operation_token)

        # 6. Tokeny JWT
        tokens = _redeem_tokens(operation_token)

        return jsonify({
            "accessToken": tokens["accessToken"]["token"],
            "accessTokenValidUntil": tokens["accessToken"]["validUntil"],
            "refreshToken": tokens["refreshToken"]["token"],
            "refreshTokenValidUntil": tokens["refreshToken"]["validUntil"],
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================
#  ENDPOINT:  POST /ksef/refresh
# =============================================================
@app.route("/ksef/refresh", methods=["POST"])
def ksef_refresh():
    """
    Odświeża accessToken używając refreshToken.
    Body: { "refreshToken": "eyJ..." }
    """
    auth_error = _check_api_key()
    if auth_error:
        return auth_error

    body = request.get_json(force=True)
    refresh_token = body.get("refreshToken")

    if not refresh_token:
        return jsonify({"error": "Wymagane pole: refreshToken"}), 400

    try:
        resp = http_requests.post(
            f"{KSEF_BASE_URL}/auth/token/refresh",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {refresh_token}",
            },
        )
        resp.raise_for_status()
        data = resp.json()

        return jsonify({
            "accessToken": data["accessToken"]["token"],
            "accessTokenValidUntil": data["accessToken"]["validUntil"],
            "refreshToken": data["refreshToken"]["token"],
            "refreshTokenValidUntil": data["refreshToken"]["validUntil"],
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check dla Render."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print("=" * 60)
    print(f"KSeF Token Server - http://localhost:{port}")
    print("=" * 60)
    print("\nEndpointy:")
    print("  POST /ksef/token    - pobierz accessToken (nip + token)")
    print("  POST /ksef/refresh  - odśwież accessToken (refreshToken)")
    print("  GET  /health        - health check")
    if API_KEY:
        print(f"\n  API Key: ustawiony (nagłówek X-API-Key)")
    else:
        print(f"\n  ⚠️  API Key: nie ustawiony (brak ochrony!)")
    print()
    app.run(host="0.0.0.0", port=port, debug=False)
