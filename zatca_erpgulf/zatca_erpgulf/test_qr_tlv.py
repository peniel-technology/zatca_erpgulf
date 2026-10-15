# Copyright (c) 2026, ERPGulf and Contributors
# See license.txt

import unittest
from unittest.mock import patch

from zatca_erpgulf.zatca_erpgulf import sign_invoice_first as sif
from zatca_erpgulf.zatca_erpgulf.create_qr import _tlv_hex

XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
 xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
 xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
 xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
 xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2"
 xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2"
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
 <ext:UBLExtensions><ext:UBLExtension><ext:ExtensionContent>
  <sig:UBLDocumentSignatures><sac:SignatureInformation><ds:Signature>
   <ds:SignedInfo>
    <ds:Reference URI="#xadesSignedProperties"><ds:DigestValue>WRONGDIGEST</ds:DigestValue></ds:Reference>
    <ds:Reference Id="invoiceSignedData" URI=""><ds:DigestValue>INVOICEHASH</ds:DigestValue></ds:Reference>
   </ds:SignedInfo>
   <ds:SignatureValue>TESTSIGNATURE</ds:SignatureValue>
  </ds:Signature></sac:SignatureInformation></sig:UBLDocumentSignatures>
 </ext:ExtensionContent></ext:UBLExtension></ext:UBLExtensions>
 <cbc:IssueDate>2026-01-15</cbc:IssueDate>
 <cbc:IssueTime>10:30:00</cbc:IssueTime>
 <cbc:InvoiceTypeCode name="{type_name}">388</cbc:InvoiceTypeCode>
 <cbc:DocumentCurrencyCode>USD</cbc:DocumentCurrencyCode>
 <cac:AccountingSupplierParty><cac:Party>
  <cac:PartyLegalEntity><cbc:RegistrationName>Test Seller</cbc:RegistrationName></cac:PartyLegalEntity>
  <cac:PartyTaxScheme><cbc:CompanyID>300000000000003</cbc:CompanyID></cac:PartyTaxScheme>
 </cac:Party></cac:AccountingSupplierParty>
 <cac:TaxTotal><cbc:TaxAmount currencyID="SAR">56.25</cbc:TaxAmount></cac:TaxTotal>
 <cac:TaxTotal><cbc:TaxAmount currencyID="USD">15.00</cbc:TaxAmount></cac:TaxTotal>
 <cac:LegalMonetaryTotal><cbc:TaxInclusiveAmount currencyID="USD">115.00</cbc:TaxInclusiveAmount></cac:LegalMonetaryTotal>
 <cac:AdditionalDocumentReference><cbc:ID>QR</cbc:ID><cac:Attachment>
  <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">Q0xFQVJFRC1RUg==</cbc:EmbeddedDocumentBinaryObject>
 </cac:Attachment></cac:AdditionalDocumentReference>
</Invoice>"""


def build_tlv(type_name):
    with patch.object(sif, "tag8_publickey", return_value=b"\x01\x02pub"), patch.object(
        sif, "tag9_signature_ecdsa", return_value=b"\x03\x04sig"
    ):
        return sif.generate_tlv_xml(
            XML_TEMPLATE.format(type_name=type_name), "TST", None
        )


class TestQrTlvEncoding(unittest.TestCase):
    def test_short_length(self):
        self.assertEqual(sif.get_tlv_for_value(2, "300"), bytes([2, 3]) + b"300")

    def test_ber_length_0x81_and_0x82(self):
        value_200 = b"x" * 200
        self.assertEqual(
            sif.get_tlv_for_value(1, value_200), bytes([1, 0x81, 200]) + value_200
        )
        value_300 = b"y" * 300
        self.assertEqual(
            sif.get_tlv_for_value(1, value_300),
            bytes([1, 0x82, 0x01, 0x2C]) + value_300,
        )

    def test_utf8_byte_length_not_char_length(self):
        arabic_name = "ش" * 70  # 70 chars, 140 utf-8 bytes
        encoded = sif.get_tlv_for_value(1, arabic_name)
        self.assertEqual(encoded[:3], bytes([1, 0x81, 140]))
        self.assertEqual(encoded[3:], arabic_name.encode("utf-8"))

    def test_phase1_helper_uses_ber_length(self):
        self.assertEqual(
            _tlv_hex(1, b"z" * 200),
            (bytes([1, 0x81, 200]) + b"z" * 200).hex(),
        )


class TestPhase2TagSelection(unittest.TestCase):
    def test_simplified_has_nine_tags_with_correct_values(self):
        tlv = build_tlv("0200000")
        self.assertEqual(sorted(tlv), [1, 2, 3, 4, 5, 6, 7, 8, 9])
        self.assertEqual(tlv[6], "INVOICEHASH")
        self.assertEqual(tlv[7], "TESTSIGNATURE")
        self.assertEqual(tlv[5], "15.00")
        self.assertEqual(tlv[4], "115.00")
        self.assertEqual(tlv[3], "2026-01-15T10:30:00")
        self.assertEqual(tlv[9], b"\x03\x04sig")

    def test_standard_has_eight_tags_without_tag9(self):
        tlv = build_tlv("0100000")
        self.assertEqual(sorted(tlv), [1, 2, 3, 4, 5, 6, 7, 8])
        self.assertNotIn(9, tlv)

    def test_extract_qr_from_xml(self):
        xml = XML_TEMPLATE.format(type_name="0100000")
        self.assertEqual(sif.extract_qr_from_xml(xml), "Q0xFQVJFRC1RUg==")
        self.assertIsNone(sif.extract_qr_from_xml("<Invoice/>"))
        self.assertIsNone(sif.extract_qr_from_xml("not xml"))
        self.assertIsNone(sif.extract_qr_from_xml(None))


if __name__ == "__main__":
    unittest.main()
