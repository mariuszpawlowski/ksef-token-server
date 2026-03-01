"""
KSeF 2.0 - serwer API do autoryzacji tokenem.
Wystawia endpoint /ksef/token, który Make.com wywołuje przez HTTP module.
Zwraca accessToken (JWT) do dalszego użycia w KSeF API.

Uruchomienie:
  pip install flask cryptography requests
  python ksef_server.py

Endpoint:
  POST http://localhost:5000/ksef/token
  Body (JSON):
    {
      "nip": "5842761713",
      "token": "20260227-EC-..."
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
import re
import xml.etree.ElementTree as ET
from decimal import Decimal, ROUND_HALF_UP
from datetime import date

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


# =============================================================
#  KSeF XML → Elixir-0 (mBank) — funkcje pomocnicze
# =============================================================

def _xml_find(root, path, default=""):
    """Wyszukuje tekst elementu XML (po usunięciu namespace)."""
    el = root.find(path)
    return el.text.strip() if el is not None and el.text else default


def _strip_namespaces(xml_string):
    """Parsuje XML i usuwa namespace z tagów dla łatwiejszego XPath."""
    root = ET.fromstring(xml_string)
    for el in root.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
        # Usuń też namespace z atrybutów
        new_attrib = {}
        for k, v in el.attrib.items():
            if "}" in k:
                k = k.split("}", 1)[1]
            new_attrib[k] = v
        el.attrib = new_attrib
    return root


def _parse_ksef_invoice(xml_string):
    """
    Parsuje fakturę KSeF FA(2) i wyciąga dane potrzebne do Elixir-0.

    Podmiot1 = Sprzedawca (wystawca faktury) → odbiorca przelewu
    Podmiot2 = Nabywca (kupujący)            → nadawca przelewu
    """
    root = _strip_namespaces(xml_string)

    # --- Sprzedawca (Podmiot1) = odbiorca przelewu ---
    seller_nip = _xml_find(root, ".//Podmiot1/DaneIdentyfikacyjne/NIP")
    seller_name = _xml_find(root, ".//Podmiot1/DaneIdentyfikacyjne/Nazwa")
    seller_addr1 = _xml_find(root, ".//Podmiot1/Adres/AdresL1")
    seller_addr2 = _xml_find(root, ".//Podmiot1/Adres/AdresL2")

    # --- Nabywca (Podmiot2) = nadawca przelewu ---
    buyer_nip = _xml_find(root, ".//Podmiot2/DaneIdentyfikacyjne/NIP")
    buyer_name = _xml_find(root, ".//Podmiot2/DaneIdentyfikacyjne/Nazwa")
    buyer_addr1 = _xml_find(root, ".//Podmiot2/Adres/AdresL1")
    buyer_addr2 = _xml_find(root, ".//Podmiot2/Adres/AdresL2")

    # --- Dane faktury ---
    invoice_number = _xml_find(root, ".//Fa/P_2")
    invoice_date = _xml_find(root, ".//Fa/P_1")
    gross_total = _xml_find(root, ".//Fa/P_15", "0")

    # Termin płatności
    due_date = _xml_find(root, ".//Fa/Platnosc/TerminPlatnosci/Termin")

    # Rachunek bankowy sprzedawcy (odbiorca przelewu)
    seller_account = _xml_find(root, ".//Fa/Platnosc/RachunekBankowy/NrRB")

    # MPP – mechanizm podzielonej płatności
    # P_18A: "1" = MPP obowiązkowy, "2" = brak MPP
    mpp_flag = _xml_find(root, ".//Fa/Adnotacje/P_18A", "2")
    is_split_payment = (mpp_flag == "1")

    # Suma VAT = P_14_1 + P_14_2 + P_14_3 + P_14_4 + P_14_5
    vat_total = Decimal("0")
    for i in range(1, 6):
        val = _xml_find(root, f".//Fa/P_14_{i}")
        if val:
            vat_total += Decimal(val)

    return {
        "seller_nip": seller_nip,
        "seller_name": seller_name,
        "seller_addr1": seller_addr1,
        "seller_addr2": seller_addr2,
        "seller_account": seller_account,
        "buyer_nip": buyer_nip,
        "buyer_name": buyer_name,
        "buyer_addr1": buyer_addr1,
        "buyer_addr2": buyer_addr2,
        "invoice_number": invoice_number,
        "invoice_date": invoice_date,
        "due_date": due_date,
        "gross_total": gross_total,
        "vat_total": str(vat_total),
        "is_split_payment": is_split_payment,
    }


def _elixir_text(name, addr1="", addr2=""):
    """
    Formatuje nazwę + adres w stylu Elixir-0: do 4 sekcji × 35 znaków, separator '|'.
    """
    parts = [p[:35] for p in [name, addr1, addr2] if p]
    while len(parts) < 4:
        parts.append("")
    return "|".join(parts[:4])


def _elixir_title_with_pipes(title_text):
    """
    Wstawia separator '|' co 35 znaków w tytule przelewu (wymaganie formatu 4×35).
    """
    result = ""
    pos = 0
    for ch in title_text:
        if pos > 0 and pos % 35 == 0:
            result += "|"
        result += ch
        pos += 1
    return result


def _amount_to_grosze(amount_str):
    """Konwertuje kwotę (str z kropką dziesiętną) na grosze (int)."""
    d = Decimal(amount_str)
    return int((d * 100).to_integral_value(rounding=ROUND_HALF_UP))


def _bank_clearing(nrb):
    """Wyciąga 8-cyfrowy numer rozliczeniowy banku z 26-cyfrowego NRB."""
    nrb_clean = re.sub(r"[^0-9]", "", nrb)
    if len(nrb_clean) >= 10:
        return nrb_clean[2:10]
    return "0"


def _date_elixir(date_str):
    """Konwertuje datę ISO (YYYY-MM-DD) na format Elixir (YYYYMMDD)."""
    return date_str.replace("-", "")[:8] if date_str else ""


def _build_split_payment_title(vat_amount_str, seller_nip, invoice_number):
    """
    Buduje tytuł przelewu split payment (MPP) ze znacznikami /VAT/ /IDC/ /INV/.
    Kwota VAT z przecinkiem jako separator dziesiętny (polska konwencja).
    """
    vat = Decimal(vat_amount_str)
    vat_fmt = f"{vat:.2f}".replace(".", ",")
    raw = f"/VAT/{vat_fmt}/IDC/{seller_nip}/INV/{invoice_number}"
    return _elixir_title_with_pipes(raw)


def generate_elixir_line(invoice_data, sender_account, execution_date=None):
    """
    Generuje linię w formacie Elixir-0 (15 pól, standard mBank).

    Args:
        invoice_data: dict z _parse_ksef_invoice()
        sender_account: NRB rachunku nadawcy (kupującego), 26 cyfr
        execution_date: data realizacji YYYYMMDD lub YYYY-MM-DD
                        (domyślnie: termin płatności z faktury lub dziś)
    """
    # Data realizacji
    if execution_date:
        exec_date = _date_elixir(execution_date)
    elif invoice_data["due_date"]:
        exec_date = _date_elixir(invoice_data["due_date"])
    else:
        exec_date = date.today().strftime("%Y%m%d")

    # Kwota w groszach
    amount = _amount_to_grosze(invoice_data["gross_total"])

    # Numery rozliczeniowe banków
    sender_clearing = _bank_clearing(sender_account)
    recipient_account = invoice_data["seller_account"]
    recipient_clearing = _bank_clearing(recipient_account) if recipient_account else "0"

    # Nazwa + adres nadawcy (kupujący)
    sender_name = _elixir_text(
        invoice_data["buyer_name"],
        invoice_data["buyer_addr1"],
        invoice_data["buyer_addr2"],
    )

    # Nazwa + adres odbiorcy (sprzedawca)
    recipient_name = _elixir_text(
        invoice_data["seller_name"],
        invoice_data["seller_addr1"],
        invoice_data["seller_addr2"],
    )

    # Tytuł przelewu i typ transakcji
    if invoice_data["is_split_payment"]:
        title = _build_split_payment_title(
            invoice_data["vat_total"],
            invoice_data["seller_nip"],
            invoice_data["invoice_number"],
        )
        tx_type = "53"  # split payment / MPP
    else:
        raw_title = f"Zaplata za fakture {invoice_data['invoice_number']}"
        title = _elixir_title_with_pipes(raw_title)
        tx_type = "51"  # przelew zwykły

    # Budowanie rekordu Elixir-0 (15 pól)
    fields = [
        "110",                      # 1  typ komunikatu (polecenie przelewu)
        exec_date,                  # 2  data realizacji (YYYYMMDD)
        str(amount),                # 3  kwota w groszach
        sender_clearing,            # 4  nr rozliczeniowy banku nadawcy
        "0",                        # 5  numer klienta
        f'"{sender_account}"',      # 6  rachunek nadawcy (NRB 26 cyfr)
        f'"{recipient_account}"',   # 7  rachunek odbiorcy (NRB 26 cyfr)
        f'"{sender_name}"',         # 8  nazwa i adres nadawcy
        f'"{recipient_name}"',      # 9  nazwa i adres odbiorcy
        "0",                        # 10 dodatkowy identyfikator
        recipient_clearing,         # 11 nr rozliczeniowy banku odbiorcy
        f'"{title}"',               # 12 tytuł przelewu
        '""',                       # 13 puste (zarezerwowane)
        '""',                       # 14 puste (zarezerwowane)
        f'"{tx_type}"',             # 15 kod klasyfikacji (51/53)
    ]

    return ",".join(fields)


# =============================================================
#  ENDPOINT:  POST /ksef/invoice-to-elixir
# =============================================================
@app.route("/ksef/invoice-to-elixir", methods=["POST"])
def ksef_invoice_to_elixir():
    """
    Konwertuje fakturę KSeF (XML) na linię przelewu w formacie Elixir-0 (mBank).

    Body (JSON):
    {
      "xml": "<Faktura ...>...</Faktura>",
      "senderAccount": "12345678901234567890123456",   // NRB rachunku płatnika
      "executionDate": "2026-03-01"                    // opcjonalne
    }

    Odpowiedź (JSON):
    {
      "elixir": "110,20260301,15000,...,\"51\"",
      "invoiceNumber": "FV/2026/03/001",
      "grossTotal": "150.00",
      "vatTotal": "28.05",
      "isSplitPayment": false,
      "transactionType": "51"
    }
    """
    auth_error = _check_api_key()
    if auth_error:
        return auth_error

    body = request.get_json(force=True)
    xml_string = body.get("xml", "")
    sender_account = body.get("senderAccount", "")
    execution_date = body.get("executionDate")

    if not xml_string:
        return jsonify({"error": "Wymagane pole: xml (faktura KSeF)"}), 400
    if not sender_account:
        return jsonify({"error": "Wymagane pole: senderAccount (NRB rachunku płatnika)"}), 400

    # Walidacja NRB (26 cyfr)
    sender_clean = re.sub(r"[^0-9]", "", sender_account)
    if len(sender_clean) != 26:
        return jsonify({"error": f"senderAccount musi mieć 26 cyfr (podano {len(sender_clean)})"}), 400

    try:
        invoice_data = _parse_ksef_invoice(xml_string)

        if not invoice_data["seller_account"]:
            return jsonify({
                "error": "Brak rachunku bankowego sprzedawcy w fakturze "
                         "(Fa/Platnosc/RachunekBankowy/NrRB)"
            }), 422

        elixir_line = generate_elixir_line(
            invoice_data, sender_clean, execution_date
        )

        tx_type = "53" if invoice_data["is_split_payment"] else "51"

        return jsonify({
            "elixir": elixir_line,
            "invoiceNumber": invoice_data["invoice_number"],
            "grossTotal": invoice_data["gross_total"],
            "vatTotal": invoice_data["vat_total"],
            "isSplitPayment": invoice_data["is_split_payment"],
            "transactionType": tx_type,
            "sellerNip": invoice_data["seller_nip"],
            "sellerName": invoice_data["seller_name"],
            "sellerAccount": invoice_data["seller_account"],
        })

    except ET.ParseError as e:
        return jsonify({"error": f"Nieprawidłowy XML: {e}"}), 400
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
    print("  POST /ksef/token             - pobierz accessToken (nip + token)")
    print("  POST /ksef/refresh           - odśwież accessToken (refreshToken)")
    print("  POST /ksef/invoice-to-elixir - konwersja faktury XML → Elixir-0")
    print("  GET  /health                 - health check")
    if API_KEY:
        print(f"\n  API Key: ustawiony (nagłówek X-API-Key)")
    else:
        print(f"\n  ⚠️  API Key: nie ustawiony (brak ochrony!)")
    print()
    app.run(host="0.0.0.0", port=port, debug=False)
