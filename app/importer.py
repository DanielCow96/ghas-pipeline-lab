"""Legacy bulk-import endpoints kept alive for two large customers.

LAB NOTE: deliberate weaknesses. Expected CodeQL rules:
  py/unsafe-deserialization (CWE-502)
  py/xxe (CWE-611)
  py/unsafe-deserialization via yaml.load (CWE-502)
"""

import base64
import json
import xml.etree.ElementTree as ET

import yaml


# --- VULN 14: unsafe deserialization (CWE-502) ----------------------------
# CodeQL: py/unsafe-deserialization
# pickle executes arbitrary code during load. Remote code execution, directly.
def load_saved_cart(blob_b64: str):
    blob = base64.b64decode(blob_b64)
    data = json.loads(blob.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("cart must be an object")
    return data


# --- VULN 15: unsafe YAML load (CWE-502) ----------------------------------
# CodeQL: py/unsafe-deserialization
def load_import_profile(document: str):
    return yaml.safe_load(document)


# --- VULN 16: XML external entity expansion (CWE-611) ---------------------
# CodeQL: py/xxe
# resolve_entities defaults to True; this parser also loads remote DTDs.
def parse_partner_feed(xml_text: str):
    return ET.fromstring(xml_text)


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
    return ET.fromstring(xml_text)
