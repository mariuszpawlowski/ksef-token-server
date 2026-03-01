# KSeF Token Server

Serwer API do integracji z **Krajowym Systemem e-Faktur (KSeF 2.0)**.

Udostępnia endpointy do:
- autoryzacji tokenem KSeF i pobierania tokenów JWT (accessToken / refreshToken),
- odświeżania accessToken,
- konwersji faktury KSeF (XML) na format przelewu **Elixir-0** (mBank i inne banki).

---

## Szybki start

### Wymagania

- Python 3.9+
- pip

### Instalacja

```bash
pip install -r requirements.txt
```

### Uruchomienie (dev)

```bash
python ksef_server.py
```

Serwer startuje na `http://localhost:5050`.

### Uruchomienie (produkcja / Render)

```bash
gunicorn ksef_server:app --bind 0.0.0.0:$PORT --timeout 120
```

Plik `render.yaml` zawiera gotową konfigurację deploy na [Render](https://render.com).

---

## Zmienne środowiskowe

| Zmienna   | Opis | Domyślnie |
|-----------|------|-----------|
| `API_KEY` | Klucz do autoryzacji requestów (nagłówek `X-API-Key`). Jeśli pusty — brak ochrony (tryb dev). | *(pusty)* |
| `PORT`    | Port serwera | `5050` |

---

## Endpointy

### `GET /health`

Health check.

**Odpowiedź:**
```json
{ "status": "ok" }
```

---

### `POST /ksef/token`

Pobiera `accessToken` i `refreshToken` z KSeF 2.0 na podstawie NIP i tokenu autoryzacyjnego.

**Nagłówki:**
```
X-API-Key: <twój klucz>    (wymagany jeśli API_KEY ustawiony)
```

**Body (JSON):**
```json
{
  "nip": "5842761713",
  "token": "20260227-EC-..."
}
```

| Pole    | Typ    | Wymagane | Opis |
|---------|--------|----------|------|
| `nip`   | string | ✅       | NIP podmiotu |
| `token` | string | ✅       | Token autoryzacyjny KSeF |

**Odpowiedź (200):**
```json
{
  "accessToken": "eyJhbG...",
  "accessTokenValidUntil": "2026-02-27T21:32:45+00:00",
  "refreshToken": "eyJhbG...",
  "refreshTokenValidUntil": "2026-03-06T21:17:45+00:00"
}
```

**Błędy:**
- `400` — brak wymaganych pól
- `401` — nieprawidłowy API key
- `500` — błąd komunikacji z KSeF

**Jak działa:**
1. Pobiera `challenge` z KSeF API
2. Pobiera klucz publiczny RSA (certyfikat `KsefTokenEncryption`)
3. Szyfruje token OAEP/SHA-256
4. Wywołuje `auth/ksef-token`
5. Polluje status autoryzacji (do 30 s)
6. Wymienia `operationToken` na tokeny JWT (`redeem`)

---

### `POST /ksef/refresh`

Odświeża `accessToken` używając `refreshToken`.

**Body (JSON):**
```json
{
  "refreshToken": "eyJhbG..."
}
```

| Pole           | Typ    | Wymagane | Opis |
|----------------|--------|----------|------|
| `refreshToken` | string | ✅       | Aktualny refreshToken |

**Odpowiedź (200):**
```json
{
  "accessToken": "eyJhbG...",
  "accessTokenValidUntil": "2026-03-01T21:32:45+00:00",
  "refreshToken": "eyJhbG...",
  "refreshTokenValidUntil": "2026-03-08T21:17:45+00:00"
}
```

---

### `POST /ksef/invoice-to-elixir`

Konwertuje fakturę KSeF (XML, schemat FA(2)) na linię przelewu w formacie **Elixir-0** (używany przez mBank i inne banki polskie).

Automatycznie rozróżnia **przelew zwykły** (`"51"`) i **split payment / MPP** (`"53"`) na podstawie pola `Fa/Adnotacje/P_18A` w XML.

**Body (JSON):**
```json
{
  "xml": "<Faktura xmlns=\"http://crd.gov.pl/wzor/2023/06/29/12648/\">...</Faktura>",
  "senderAccount": "12114020040000330200999999",
  "executionDate": "2026-03-15"
}
```

| Pole             | Typ    | Wymagane | Opis |
|------------------|--------|----------|------|
| `xml`            | string | ✅       | Pełny XML faktury KSeF (schemat FA(2)) |
| `senderAccount`  | string | ✅       | NRB rachunku płatnika (26 cyfr) |
| `executionDate`  | string | ❌       | Data realizacji przelewu (`YYYY-MM-DD`). Domyślnie: termin płatności z faktury lub dziś. |

**Odpowiedź (200):**
```json
{
  "elixir": "110,20260315,150000,11402004,0,\"12114020040000330200999999\",\"49114020040000330200112177\",\"NABYWCA TEST SP. Z O.O.|ul. Kupiecka 5/10|00-001 Warszawa|\",\"FIRMA SPRZEDAWCY SP. Z O.O.|ul. Handlowa 15|80-001 Gdansk|\",0,11402004,\"Zaplata za fakture FV/2026/02/0042\",\"\",\"\",\"51\"",
  "invoiceNumber": "FV/2026/02/0042",
  "grossTotal": "1500.00",
  "vatTotal": "280.49",
  "isSplitPayment": false,
  "transactionType": "51",
  "sellerNip": "5842761713",
  "sellerName": "FIRMA SPRZEDAWCY SP. Z O.O.",
  "sellerAccount": "49114020040000330200112177"
}
```

**Błędy:**
- `400` — brak XML, brak `senderAccount`, nieprawidłowy NRB lub błędny XML
- `401` — nieprawidłowy API key
- `422` — brak rachunku bankowego sprzedawcy w fakturze
- `500` — inny błąd

---

## Format Elixir-0 — opis pól

Rekord Elixir-0 to jedna linia CSV z 15 polami oddzielonymi przecinkami:

```
110,20260315,150000,11402004,0,"NRB_NADAWCY","NRB_ODBIORCY","NAZWA NADAWCY|ADRES","NAZWA ODBIORCY|ADRES",0,11402004,"TYTUL","","","51"
```

| Poz. | Pole | Format | Opis |
|------|------|--------|------|
| 1 | Typ komunikatu | `110` | Polecenie przelewu |
| 2 | Data realizacji | `YYYYMMDD` | Data wykonania przelewu |
| 3 | Kwota | integer | Kwota w **groszach** (1500.00 PLN → `150000`) |
| 4 | Nr rozliczeniowy banku nadawcy | 8 cyfr | Pierwsze 8 cyfr NRB nadawcy (po 2 cyfrach kontrolnych) |
| 5 | Nr klienta | `0` | Zarezerwowany |
| 6 | Rachunek nadawcy | `"26 cyfr"` | Pełny NRB płatnika |
| 7 | Rachunek odbiorcy | `"26 cyfr"` | Pełny NRB sprzedawcy (z faktury) |
| 8 | Nazwa nadawcy | `"4×35"` | Nazwa i adres płatnika, sekcje rozdzielone `\|` |
| 9 | Nazwa odbiorcy | `"4×35"` | Nazwa i adres sprzedawcy, sekcje rozdzielone `\|` |
| 10 | Identyfikator | `0` | Zarezerwowany |
| 11 | Nr rozliczeniowy banku odbiorcy | 8 cyfr | Pierwsze 8 cyfr NRB odbiorcy |
| 12 | Tytuł przelewu | `"4×35"` | Tytuł (patrz niżej) |
| 13 | Zarezerwowane | `""` | Puste |
| 14 | Zarezerwowane | `""` | Puste |
| 15 | Kod klasyfikacji | `"51"` / `"53"` | Typ transakcji |

### Tytuł przelewu

**Przelew zwykły (`"51"`):**
```
Zaplata za fakture FV/2026/02/0042
```

**Split payment / MPP (`"53"`):**
```
/VAT/280,49/IDC/5842761713/INV/FV/2026/02/0042
```

Znaczniki split payment:
- `/VAT/` — kwota VAT (z przecinkiem jako separator dziesiętny)
- `/IDC/` — NIP sprzedawcy
- `/INV/` — numer faktury

W obu przypadkach co 35 znaków wstawiany jest separator `|` (wymaganie formatu 4×35).

---

## Mapowanie KSeF XML → Elixir-0

Serwer odczytuje dane z faktury KSeF (schemat FA(2), namespace `http://crd.gov.pl/wzor/2023/06/29/12648/`):

| Pole Elixir | Źródło w XML |
|---|---|
| Rachunek odbiorcy | `Fa/Platnosc/RachunekBankowy/NrRB` |
| Nazwa odbiorcy | `Podmiot1/DaneIdentyfikacyjne/Nazwa` + `Podmiot1/Adres/AdresL1,L2` |
| NIP odbiorcy | `Podmiot1/DaneIdentyfikacyjne/NIP` |
| Nazwa nadawcy | `Podmiot2/DaneIdentyfikacyjne/Nazwa` + `Podmiot2/Adres/AdresL1,L2` |
| Numer faktury | `Fa/P_2` |
| Kwota brutto | `Fa/P_15` |
| Suma VAT | `Fa/P_14_1` + `P_14_2` + `P_14_3` + `P_14_4` + `P_14_5` |
| Termin płatności | `Fa/Platnosc/TerminPlatnosci/Termin` |
| Split payment | `Fa/Adnotacje/P_18A` (`1` = MPP, `2` = brak) |

> **Uwaga:** `Podmiot1` = sprzedawca (odbiorca przelewu), `Podmiot2` = nabywca (nadawca przelewu). Rachunek nadawcy (`senderAccount`) nie jest zawarty w fakturze — należy go podać w żądaniu.

---

## Stack technologiczny

- **Python 3.9+** / Flask
- **cryptography** — szyfrowanie RSA (OAEP/SHA-256) przy autoryzacji KSeF
- **gunicorn** — serwer WSGI (produkcja)
- Deploy: **Render** (free tier, konfiguracja w `render.yaml`)

---

## Licencja

MIT
