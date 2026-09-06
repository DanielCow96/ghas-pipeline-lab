"""Legacy bulk-import endpoints kept alive for two large customers.

LAB NOTE: deliberate weaknesses. Expected CodeQL rules:
  py/unsafe-deserialization (CWE-502)
  py/xxe (CWE-611)
  py/unsafe-deserialization via yaml.load (CWE-502)
"""

import base64

import yaml
from lxml import etree


# --- VULN 14: unsafe deserialization (CWE-502) ----------------------------
# CodeQL: py/unsafe-deserialization
# pickle executes arbitrary code during load. Remote code execution, directly.
def load_saved_cart(blob_b64: str):
    blob = base64.b64decode(blob_b64)
    return load_saved_cart_safe(blob.decode())


# --- VULN 15: unsafe YAML load (CWE-502) ----------------------------------
# CodeQL: py/unsafe-deserialization
def load_import_profile(document: str):
    return yaml.load(document, Loader=yaml.Loader)  # noqa: S506


# --- VULN 16: XML external entity expansion (CWE-611) ---------------------
# CodeQL: py/xxe
# resolve_entities defaults to True; this parser also loads remote DTDs.
def parse_partner_feed(xml_text: str):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    return etree.fromstring(xml_text.encode(), parser)


# --- REFERENCE FIXES ------------------------------------------------------
import json  # noqa: E402


def load_saved_cart_safe(blob_json: str) -> dict:
    """Never deserialize attacker-controlled data into live objects.
    Use a data-only format and validate the shape."""
    data = json.loads(blob_json)
    if not isinstance(data, dict):
        raise ValueError("cart must be an object")
    return data


def load_import_profile_safe(document: str):
    return yaml.safe_load(document)


def parse_partner_feed_safe(xml_text: str):
    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,
    )
    return etree.fromstring(xml_text.encode(), parser)
