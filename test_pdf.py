"""Quick test for PDF generation."""
import ksef_server

xml = '''<?xml version="1.0" encoding="UTF-8"?>
<Faktura xmlns="http://crd.gov.pl/wzor/2023/06/29/12648/">
  <Naglowek>
    <KodFormularza kodSystemowy="FA (2)" wersjaSchemy="1-0E">FA</KodFormularza>
    <WariantFormularza>2</WariantFormularza>
    <DataWytworzeniaFa>2026-02-27T10:00:00</DataWytworzeniaFa>
    <SystemInfo>KSeF</SystemInfo>
  </Naglowek>
  <Podmiot1>
    <DaneIdentyfikacyjne>
      <NIP>5851503873</NIP>
      <Nazwa>MPJP Sp. z o.o.</Nazwa>
    </DaneIdentyfikacyjne>
    <Adres>
      <AdresL1>ul. Leśna 1</AdresL1>
      <AdresL2>81-876 Sopot</AdresL2>
    </Adres>
    <DaneKontaktowe>
      <Telefon>731805769</Telefon>
    </DaneKontaktowe>
  </Podmiot1>
  <Podmiot2>
    <DaneIdentyfikacyjne>
      <NIP>5842761713</NIP>
      <Nazwa>MERAPAR TECHNOLOGIES Sp. z o.o.</Nazwa>
    </DaneIdentyfikacyjne>
    <Adres>
      <AdresL1>ul. Arkońska 6</AdresL1>
      <AdresL2>80-387 Gdańsk</AdresL2>
    </Adres>
  </Podmiot2>
  <Fa>
    <P_1>2026-02-27</P_1>
    <P_2>1/02/2026</P_2>
    <P_6>2026-02-27</P_6>
    <P_15>38224.71</P_15>
    <P_14_1>7147.71</P_14_1>
    <Adnotacje>
      <P_18A>2</P_18A>
    </Adnotacje>
    <FaWiersz>
      <NrWierszFa>1</NrWierszFa>
      <P_7>Konsultacje programistyczne - Intiuss</P_7>
      <P_8A>dzień</P_8A>
      <P_8B>15</P_8B>
      <P_9A>1930.00</P_9A>
      <P_11>28950.00</P_11>
      <P_12>23</P_12>
    </FaWiersz>
    <FaWiersz>
      <NrWierszFa>2</NrWierszFa>
      <P_7>Dyżur telefoniczny</P_7>
      <P_8A>szt.</P_8A>
      <P_8B>1</P_8B>
      <P_9A>2127.00</P_9A>
      <P_11>2127.00</P_11>
      <P_12>23</P_12>
    </FaWiersz>
    <Platnosc>
      <TerminPlatnosci>
        <Termin>2026-03-06</Termin>
      </TerminPlatnosci>
      <RachunekBankowy>
        <NrRB>70114020040000300284647155</NrRB>
      </RachunekBankowy>
    </Platnosc>
  </Fa>
</Faktura>'''

inv = ksef_server._parse_ksef_invoice_for_pdf(xml)
pdf = ksef_server._generate_invoice_pdf(inv, issuer_name='Mariusz Pawłowski')

with open('/tmp/test_invoice.pdf', 'wb') as f:
    f.write(pdf)
print(f"PDF generated: {len(pdf)} bytes -> /tmp/test_invoice.pdf")
