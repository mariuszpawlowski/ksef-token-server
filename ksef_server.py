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

from flask import Flask, request, jsonify, send_file
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
import io

# PDF generation (reportlab)
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm as MM
from reportlab.lib import colors as rl_colors
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.platypus import Table, TableStyle, Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics import renderPDF
from reportlab.graphics.shapes import Drawing

app = Flask(__name__)

KSEF_BASE_URL = "https://api.ksef.mf.gov.pl/v2"

# Klucz API do zabezpieczenia endpointów (ustaw w zmiennych środowiskowych)
API_KEY = os.environ.get("API_KEY", "")

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# --- PDF: rejestracja czcionek z obsługą polskich znaków ---
_PDF_FONT = "Helvetica"
_PDF_FONT_BOLD = "Helvetica-Bold"


def _init_pdf_fonts():
    """Rejestruje czcionkę TTF z polskimi znakami (DejaVu Sans)."""
    global _PDF_FONT, _PDF_FONT_BOLD
    candidates = [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("/System/Library/Fonts/Supplemental/Arial.ttf",
         "/System/Library/Fonts/Supplemental/Arial Bold.ttf"),
    ]
    for regular, bold in candidates:
        if os.path.exists(regular):
            try:
                pdfmetrics.registerFont(TTFont("InvFont", regular))
                _PDF_FONT = "InvFont"
                if os.path.exists(bold):
                    pdfmetrics.registerFont(TTFont("InvFont-Bold", bold))
                    _PDF_FONT_BOLD = "InvFont-Bold"
                else:
                    _PDF_FONT_BOLD = "InvFont"
                return
            except Exception:
                continue


_init_pdf_fonts()


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


# =============================================================
#  KSeF XML → PDF — funkcje pomocnicze
# =============================================================

def _format_amount_pl(amount_str):
    """'38224.71' → '38 224,71' (polski format kwoty)."""
    d = Decimal(str(amount_str)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    text = f"{d:.2f}"
    int_part, dec_part = text.split(".")
    negative = int_part.startswith("-")
    int_part = int_part.lstrip("-")
    result = ""
    for i, ch in enumerate(reversed(int_part)):
        if i > 0 and i % 3 == 0:
            result = "\u00a0" + result  # non-breaking space
        result = ch + result
    if negative:
        result = "-" + result
    return f"{result},{dec_part}"


def _format_nrb(nrb):
    """'70114020040000300284647155' → '70 1140 2004 0000 3002 8464 7155'."""
    clean = re.sub(r"[^0-9]", "", nrb)
    if len(clean) != 26:
        return nrb
    return (f"{clean[:2]} {clean[2:6]} {clean[6:10]} {clean[10:14]} "
            f"{clean[14:18]} {clean[18:22]} {clean[22:26]}")


def _number_to_words_pl(n):
    """Konwertuje liczbę całkowitą (≥0) na słowa po polsku."""
    if n == 0:
        return "zero"
    ones = ["", "jeden", "dwa", "trzy", "cztery", "pięć",
            "sześć", "siedem", "osiem", "dziewięć"]
    teens = ["dziesięć", "jedenaście", "dwanaście", "trzynaście",
             "czternaście", "piętnaście", "szesnaście", "siedemnaście",
             "osiemnaście", "dziewiętnaście"]
    tens_w = ["", "dziesięć", "dwadzieścia", "trzydzieści", "czterdzieści",
              "pięćdziesiąt", "sześćdziesiąt", "siedemdziesiąt",
              "osiemdziesiąt", "dziewięćdziesiąt"]
    hundreds_w = ["", "sto", "dwieście", "trzysta", "czterysta", "pięćset",
                  "sześćset", "siedemset", "osiemset", "dziewięćset"]

    def _group(g):
        if g == 0:
            return ""
        parts = []
        if g // 100:
            parts.append(hundreds_w[g // 100])
        rest = g % 100
        if 10 <= rest < 20:
            parts.append(teens[rest - 10])
        else:
            if rest // 10:
                parts.append(tens_w[rest // 10])
            if rest % 10:
                parts.append(ones[rest % 10])
        return " ".join(parts)

    def _plural(count, s1, s24, s5p):
        if count == 1:
            return s1
        lt = count % 100
        lo = count % 10
        if 10 < lt < 20:
            return s5p
        if 2 <= lo <= 4:
            return s24
        return s5p

    scales = [
        (1_000_000_000, "miliard", "miliardy", "miliardów"),
        (1_000_000, "milion", "miliony", "milionów"),
        (1_000, "tysiąc", "tysiące", "tysięcy"),
    ]
    parts = []
    for divisor, s1, s24, s5p in scales:
        count = n // divisor
        n %= divisor
        if count == 0:
            continue
        form = _plural(count, s1, s24, s5p)
        if count == 1:
            parts.append(form)
        else:
            parts.append(f"{_group(count)} {form}")
    if n > 0:
        parts.append(_group(n))
    return " ".join(parts)


def _amount_to_words_pl(amount_str):
    """'38224.71' → 'trzydzieści osiem tysięcy dwieście dwadzieścia cztery PLN 71/100'."""
    d = Decimal(str(amount_str)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    integer = int(d)
    decimal = int(round(abs(d - integer) * 100))
    words = _number_to_words_pl(abs(integer))
    return f"{words} PLN {decimal:02d}/100"


def _parse_ksef_invoice_for_pdf(xml_string):
    """
    Rozszerzony parser faktury KSeF FA(2) — z pozycjami i podsumowaniem VAT.
    """
    root = _strip_namespaces(xml_string)

    seller_nip = _xml_find(root, ".//Podmiot1/DaneIdentyfikacyjne/NIP")
    seller_name = _xml_find(root, ".//Podmiot1/DaneIdentyfikacyjne/Nazwa")
    seller_addr1 = _xml_find(root, ".//Podmiot1/Adres/AdresL1")
    seller_addr2 = _xml_find(root, ".//Podmiot1/Adres/AdresL2")
    seller_phone = _xml_find(root, ".//Podmiot1/DaneKontaktowe/Telefon")

    buyer_nip = _xml_find(root, ".//Podmiot2/DaneIdentyfikacyjne/NIP")
    buyer_name = _xml_find(root, ".//Podmiot2/DaneIdentyfikacyjne/Nazwa")
    buyer_addr1 = _xml_find(root, ".//Podmiot2/Adres/AdresL1")
    buyer_addr2 = _xml_find(root, ".//Podmiot2/Adres/AdresL2")

    invoice_number = _xml_find(root, ".//Fa/P_2")
    invoice_date = _xml_find(root, ".//Fa/P_1")
    sale_date = _xml_find(root, ".//Fa/P_6") or invoice_date
    gross_total = _xml_find(root, ".//Fa/P_15", "0")
    due_date = _xml_find(root, ".//Fa/Platnosc/TerminPlatnosci/Termin")
    seller_account = _xml_find(root, ".//Fa/Platnosc/RachunekBankowy/NrRB")

    mpp_flag = _xml_find(root, ".//Fa/Adnotacje/P_18A", "2")
    is_split_payment = (mpp_flag == "1")

    vat_total = Decimal("0")
    for i in range(1, 6):
        val = _xml_find(root, f".//Fa/P_14_{i}")
        if val:
            vat_total += Decimal(val)

    # --- Pozycje (FaWiersz) ---
    line_items = []
    vat_summary = {}  # rate_display -> {net, vat, gross}

    for row in root.findall(".//Fa/FaWiersz"):
        nr = _xml_find(row, "NrWierszFa", str(len(line_items) + 1))
        name = _xml_find(row, "P_7")
        unit = _xml_find(row, "P_8A")
        qty = Decimal(_xml_find(row, "P_8B", "1"))
        price_net = Decimal(_xml_find(row, "P_9A", "0"))
        net = Decimal(_xml_find(row, "P_11", "0"))
        rate_str = _xml_find(row, "P_12", "0")

        try:
            rate = Decimal(rate_str)
            vat_amt = (net * rate / 100).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            rate_display = f"{int(rate)}%"
        except Exception:
            vat_amt = Decimal("0")
            rate_display = rate_str

        gross = net + vat_amt

        qty_display = str(int(qty)) if qty == int(qty) else _format_amount_pl(str(qty))

        line_items.append({
            "nr": nr, "name": name, "qty": qty_display, "unit": unit,
            "price_net": str(price_net), "net": str(net),
            "rate": rate_display, "vat": str(vat_amt), "gross": str(gross),
        })

        if rate_display not in vat_summary:
            vat_summary[rate_display] = {"net": Decimal("0"), "vat": Decimal("0"), "gross": Decimal("0")}
        vat_summary[rate_display]["net"] += net
        vat_summary[rate_display]["vat"] += vat_amt
        vat_summary[rate_display]["gross"] += gross

    net_total = sum(Decimal(it["net"]) for it in line_items) if line_items else Decimal("0")
    paid = Decimal(_xml_find(root, ".//Fa/Platnosc/Zaplacono") or "0")

    return {
        "seller_nip": seller_nip, "seller_name": seller_name,
        "seller_addr1": seller_addr1, "seller_addr2": seller_addr2,
        "seller_phone": seller_phone, "seller_account": seller_account,
        "buyer_nip": buyer_nip, "buyer_name": buyer_name,
        "buyer_addr1": buyer_addr1, "buyer_addr2": buyer_addr2,
        "invoice_number": invoice_number, "invoice_date": invoice_date,
        "sale_date": sale_date, "due_date": due_date,
        "gross_total": gross_total, "net_total": str(net_total),
        "vat_total": str(vat_total), "is_split_payment": is_split_payment,
        "line_items": line_items,
        "vat_summary": {k: {kk: str(vv) for kk, vv in v.items()} for k, v in vat_summary.items()},
        "paid": str(paid),
    }


# =============================================================
#  Generowanie PDF faktury
# =============================================================

def _generate_invoice_pdf(inv, ksef_number=None, issuer_name=None):
    """
    Generuje PDF faktury w polskim standardzie z kodem QR.

    Args:
        inv: dict z _parse_ksef_invoice_for_pdf()
        ksef_number: opcjonalny numer KSeF (do weryfikacji QR)
        issuer_name: imię i nazwisko wystawcy (podpis)

    Returns:
        bytes — dokument PDF
    """
    buf = io.BytesIO()
    W, H = A4
    c = pdf_canvas.Canvas(buf, pagesize=A4)

    F = _PDF_FONT
    FB = _PDF_FONT_BOLD
    LEFT = 15 * MM
    RIGHT = W - 15 * MM
    PW = RIGHT - LEFT

    y = H - 12 * MM

    # ─── QR CODE ─────────────────────────────────────────────
    qr_size = 25 * MM
    if ksef_number:
        qr_data = f"https://ksef.mf.gov.pl/web/verify/{ksef_number}"
    else:
        qr_data = (f"FV:{inv['invoice_number']}|NIP:{inv['seller_nip']}"
                   f"|KWOTA:{inv['gross_total']}")

    qr_w = QrCodeWidget(qr_data)
    qr_w.barWidth = qr_size
    qr_w.barHeight = qr_size
    drawing = Drawing(qr_size, qr_size)
    drawing.add(qr_w)
    renderPDF.draw(drawing, c, LEFT, y - qr_size)

    c.setFont(F, 6.5)
    qr_label = ksef_number if ksef_number else "OFFLINE"
    c.drawCentredString(LEFT + qr_size / 2, y - qr_size - 8, qr_label)

    # ─── HEADER: pieczęć firmy + Faktura + Nr / daty ─────────
    hdr_top = y
    stamp_x = LEFT + qr_size + 8 * MM
    stamp_w = 55 * MM
    stamp_h = 38 * MM

    # Gray "pieczęć firmy" box
    c.setFillColor(rl_colors.Color(0.93, 0.93, 0.93))
    c.rect(stamp_x, hdr_top - stamp_h, stamp_w, stamp_h, fill=1, stroke=0)

    c.setFillColor(rl_colors.black)
    c.setFont(FB, 22)
    c.drawCentredString(stamp_x + stamp_w / 2, hdr_top - stamp_h / 2, "Faktura")

    c.setFont(F, 7)
    c.setFillColor(rl_colors.Color(0.5, 0.5, 0.5))
    c.drawCentredString(stamp_x + stamp_w / 2, hdr_top - stamp_h + 5,
                        "pieczęć firmy")
    c.setFillColor(rl_colors.black)

    # Right boxes: Nr, Data wystawienia, Data sprzedaży
    rx = stamp_x + stamp_w + 4 * MM
    rw = RIGHT - rx
    bh = 12 * MM

    c.setStrokeColor(rl_colors.Color(0.75, 0.75, 0.75))
    c.setLineWidth(0.5)

    # Nr
    c.rect(rx, hdr_top - bh, rw, bh, stroke=1, fill=0)
    c.setFont(FB, 9)
    c.drawCentredString(rx + rw / 2, hdr_top - bh / 2 - 3,
                        f"Nr {inv['invoice_number']}")

    # Data wystawienia
    dy = hdr_top - bh - 1 * MM
    c.rect(rx, dy - bh, rw, bh, stroke=1, fill=0)
    c.setFont(FB, 9)
    c.drawCentredString(rx + rw / 2, dy - bh / 2 + 1, inv["invoice_date"])
    c.setFont(F, 6.5)
    c.drawCentredString(rx + rw / 2, dy - bh / 2 - 8, "Data wystawienia")

    # Data sprzedaży
    sy = dy - bh - 1 * MM
    c.rect(rx, sy - bh, rw, bh, stroke=1, fill=0)
    c.setFont(FB, 9)
    c.drawCentredString(rx + rw / 2, sy - bh / 2 + 1, inv["sale_date"])
    c.setFont(F, 6.5)
    c.drawCentredString(rx + rw / 2, sy - bh / 2 - 8, "Data sprzedaży")

    y = hdr_top - max(stamp_h + 10, 3 * bh + 4 * MM) - 6 * MM

    # ─── SELLER / BUYER ─────────────────────────────────────
    half_w = PW / 2 - 2 * MM
    box_h = 24 * MM

    c.setStrokeColor(rl_colors.Color(0.75, 0.75, 0.75))
    c.setLineWidth(0.5)

    # Seller (left)
    c.rect(LEFT, y - box_h, half_w, box_h, stroke=1, fill=0)
    tx = LEFT + 3 * MM
    ty = y - 5 * MM
    c.setFont(F, 8)
    c.drawString(tx, ty, f"Sprzedawca: {inv['seller_name']}")
    ty -= 10
    addr = inv['seller_addr1']
    if inv['seller_addr2']:
        addr += f", {inv['seller_addr2']}"
    c.drawString(tx, ty, f"Adres: {addr}")
    ty -= 10
    c.drawString(tx, ty, f"NIP: {inv['seller_nip']}")
    if inv.get('seller_phone'):
        ty -= 10
        c.drawString(tx, ty, f"Numer telefonu: {inv['seller_phone']}")

    # Buyer (right)
    bx = LEFT + half_w + 4 * MM
    c.rect(bx, y - box_h, half_w, box_h, stroke=1, fill=0)
    tx = bx + 3 * MM
    ty = y - 5 * MM
    c.setFont(F, 8)
    c.drawString(tx, ty, f"Nabywca: {inv['buyer_name']}")
    ty -= 10
    addr = inv['buyer_addr1']
    if inv['buyer_addr2']:
        addr += f", {inv['buyer_addr2']}"
    c.drawString(tx, ty, f"Adres: {addr}")
    ty -= 10
    c.drawString(tx, ty, f"NIP: {inv['buyer_nip']}")

    y -= box_h + 4 * MM

    # ─── PAYMENT INFO ───────────────────────────────────────
    pay_h = 16 * MM
    c.rect(LEFT, y - pay_h, PW, pay_h, stroke=1, fill=0)
    tx = LEFT + 3 * MM
    ty = y - 5 * MM

    c.setFont(F, 8)
    lbl = "Sposób płatności: "
    c.drawString(tx, ty, lbl)
    c.setFont(FB, 8)
    c.drawString(tx + c.stringWidth(lbl, F, 8), ty, "Przelew")

    lbl2 = "Termin płatności: "
    due_x = tx + 55 * MM
    c.setFont(F, 8)
    c.drawString(due_x, ty, lbl2)
    c.setFont(FB, 8)
    c.drawString(due_x + c.stringWidth(lbl2, F, 8), ty,
                 inv["due_date"] or "-")

    ty -= 12
    c.setFont(F, 8)
    if inv["seller_account"]:
        lbl3 = "Numer konta: "
        c.drawString(tx, ty, lbl3)
        c.setFont(FB, 8)
        c.drawString(tx + c.stringWidth(lbl3, F, 8), ty,
                     _format_nrb(inv["seller_account"]))

    y -= pay_h + 4 * MM

    # ─── LINE ITEMS TABLE ───────────────────────────────────
    col_mm = [10, 46, 14, 12, 22, 22, 14, 18, 22]
    col_w = [w * MM for w in col_mm]
    total_col = sum(col_w)
    scale = PW / total_col
    col_w = [w * scale for w in col_w]

    hdr_para = ParagraphStyle('H', fontName=FB, fontSize=7, leading=8.5,
                              alignment=TA_CENTER)
    cell_r = ParagraphStyle('CR', fontName=F, fontSize=7.5, leading=9,
                            alignment=TA_RIGHT)
    cell_l = ParagraphStyle('CL', fontName=F, fontSize=7.5, leading=9,
                            alignment=TA_LEFT)
    cell_c = ParagraphStyle('CC', fontName=F, fontSize=7.5, leading=9,
                            alignment=TA_CENTER)

    header_row = [
        Paragraph("Lp.", hdr_para),
        Paragraph("Nazwa", hdr_para),
        Paragraph("Ilość", hdr_para),
        Paragraph("Jm", hdr_para),
        Paragraph("Cena netto", hdr_para),
        Paragraph("Wartość<br/>netto", hdr_para),
        Paragraph("Stawka<br/>VAT", hdr_para),
        Paragraph("Kwota VAT", hdr_para),
        Paragraph("Wartość<br/>brutto", hdr_para),
    ]

    data_rows = []
    for item in inv["line_items"]:
        data_rows.append([
            Paragraph(item["nr"], cell_c),
            Paragraph(item["name"], cell_l),
            Paragraph(item["qty"], cell_r),
            Paragraph(item["unit"], cell_c),
            Paragraph(_format_amount_pl(item["price_net"]), cell_r),
            Paragraph(_format_amount_pl(item["net"]), cell_r),
            Paragraph(item["rate"], cell_c),
            Paragraph(_format_amount_pl(item["vat"]), cell_r),
            Paragraph(_format_amount_pl(item["gross"]), cell_r),
        ])

    tbl_data = [header_row] + data_rows
    t = Table(tbl_data, colWidths=col_w)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.Color(0.75, 0.75, 0.75)),
        ("BACKGROUND", (0, 0), (-1, 0), rl_colors.Color(0.93, 0.93, 0.93)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))

    tw, th = t.wrap(PW, 0)
    t.drawOn(c, LEFT, y - th)
    y -= th + 2 * MM

    # ─── SUMMARY ROWS (Razem / W tym) ───────────────────────
    sum_hdr = ParagraphStyle('SH', fontName=FB, fontSize=7.5, leading=9,
                             alignment=TA_RIGHT)
    sum_cell = ParagraphStyle('SC', fontName=F, fontSize=7.5, leading=9,
                              alignment=TA_RIGHT)
    sum_cell_c = ParagraphStyle('SCC', fontName=F, fontSize=7.5, leading=9,
                                alignment=TA_CENTER)

    net_d = Decimal(inv["net_total"])
    vat_d = Decimal(inv["vat_total"])

    sum_rows = [[
        Paragraph("Razem:", sum_hdr),
        Paragraph(_format_amount_pl(str(net_d)), sum_cell),
        Paragraph("X", sum_cell_c),
        Paragraph(_format_amount_pl(str(vat_d)), sum_cell),
        Paragraph(_format_amount_pl(inv["gross_total"]), sum_cell),
    ]]
    for rate_str in sorted(inv["vat_summary"].keys()):
        vals = inv["vat_summary"][rate_str]
        sum_rows.append([
            Paragraph("W tym:", sum_hdr),
            Paragraph(_format_amount_pl(vals["net"]), sum_cell),
            Paragraph(rate_str, sum_cell_c),
            Paragraph(_format_amount_pl(vals["vat"]), sum_cell),
            Paragraph(_format_amount_pl(vals["gross"]), sum_cell),
        ])

    sum_col_w = [18 * MM, 22 * MM, 14 * MM, 18 * MM, 22 * MM]
    st = Table(sum_rows, colWidths=sum_col_w)
    st.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.Color(0.75, 0.75, 0.75)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    stw, sth = st.wrap(0, 0)
    st.drawOn(c, RIGHT - stw, y - sth)
    y -= sth + 5 * MM

    # ─── RAZEM DO ZAPŁATY ───────────────────────────────────
    gross_d = Decimal(inv["gross_total"])
    paid = Decimal(inv.get("paid", "0"))
    remaining = gross_d - paid

    box_h3 = 20 * MM
    c.setStrokeColor(rl_colors.Color(0.75, 0.75, 0.75))
    c.rect(LEFT, y - box_h3, PW, box_h3, stroke=1, fill=0)

    tx = LEFT + 3 * MM
    ty = y - 6 * MM
    c.setFont(F, 9)
    lbl = "Razem do zapłaty: "
    c.drawString(tx, ty, lbl)
    c.setFont(FB, 12)
    c.drawString(tx + c.stringWidth(lbl, F, 9), ty,
                 f"{_format_amount_pl(inv['gross_total'])} PLN")

    ty -= 13
    c.setFont(F, 8)
    c.drawString(tx, ty,
                 f"Zapłacono: {_format_amount_pl(str(paid))} PLN")
    ty -= 10
    c.drawString(tx, ty,
                 f"Pozostało do zapłaty: {_format_amount_pl(str(remaining))} PLN")

    y -= box_h3 + 4 * MM

    # ─── SŁOWNIE ────────────────────────────────────────────
    words_h = 12 * MM
    c.rect(LEFT, y - words_h, PW, words_h, stroke=1, fill=0)
    tx = LEFT + 3 * MM
    ty = y - 5 * MM
    c.setFont(F, 8)
    words = _amount_to_words_pl(inv["gross_total"])
    c.drawString(tx, ty, f"Słownie: {words}")

    y -= words_h + 6 * MM

    # ─── PODPISY ────────────────────────────────────────────
    sig_h = 30 * MM
    half = PW / 2 - 3 * MM

    # Left signature
    c.rect(LEFT, y - sig_h, half, sig_h, stroke=1, fill=0)
    c.setFont(F, 6.5)
    c.drawCentredString(
        LEFT + half / 2, y - sig_h + 12,
        "imię, nazwisko i podpis osoby upoważnionej")
    c.drawCentredString(
        LEFT + half / 2, y - sig_h + 4,
        "do odebrania dokumentu")

    # Right signature
    rx2 = LEFT + half + 6 * MM
    c.rect(rx2, y - sig_h, half, sig_h, stroke=1, fill=0)
    if issuer_name:
        c.setFont(FB, 10)
        c.drawCentredString(rx2 + half / 2, y - sig_h / 2 + 2, issuer_name)
    c.setFont(F, 6.5)
    c.drawCentredString(
        rx2 + half / 2, y - sig_h + 12,
        "imię, nazwisko i podpis osoby upoważnionej do wystawienia")
    c.drawCentredString(rx2 + half / 2, y - sig_h + 4, "dokumentu")

    # ─── FINALIZACJA ────────────────────────────────────────
    c.showPage()
    c.save()
    buf.seek(0)
    return buf.getvalue()


# =============================================================
#  ENDPOINT:  POST /ksef/invoice-pdf
# =============================================================
@app.route("/ksef/invoice-pdf", methods=["POST"])
def ksef_invoice_pdf():
    """
    Generuje PDF faktury z kodem QR na podstawie XML faktury KSeF.

    Body (JSON):
    {
      "xml": "<Faktura ...>...</Faktura>",
      "ksefNumber": "1234567890-20260227-...",   // opcjonalny
      "issuerName": "Jan Kowalski"               // opcjonalny
    }

    Odpowiedź: application/pdf
    """
    auth_error = _check_api_key()
    if auth_error:
        return auth_error

    body = request.get_json(force=True)
    xml_string = body.get("xml", "")
    ksef_number = body.get("ksefNumber")
    issuer_name = body.get("issuerName")

    if not xml_string:
        return jsonify({"error": "Wymagane pole: xml (faktura KSeF)"}), 400

    try:
        inv = _parse_ksef_invoice_for_pdf(xml_string)
        pdf_bytes = _generate_invoice_pdf(inv, ksef_number, issuer_name)

        filename = f"faktura_{inv['invoice_number'].replace('/', '_')}.pdf"
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )
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
    print("  POST /ksef/invoice-pdf       - generuj PDF faktury z QR")
    print("  GET  /health                 - health check")
    if API_KEY:
        print(f"\n  API Key: ustawiony (nagłówek X-API-Key)")
    else:
        print(f"\n  ⚠️  API Key: nie ustawiony (brak ochrony!)")
    print()
    app.run(host="0.0.0.0", port=port, debug=False)
