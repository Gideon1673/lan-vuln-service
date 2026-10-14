"""Bước này chuẩn hóa thông tin phần mềm thành định dạng thống nhất"""
import re

PRODUCTS = {
    "openssh": ("a", "openbsd", "openssh"),
    "openssh server": ("a", "openbsd", "openssh"),
    "apache httpd": ("a", "apache", "http_server"),
    "apache http server": ("a", "apache", "http_server"),
    "openssl": ("a", "openssl", "openssl"),
}


def normalize(service):
    raw_product = service.get("product") or ""
    raw_version = service.get("version") or ""

    product_name = re.sub(r"\s+", " ", raw_product.strip().lower())
    version = raw_version.strip()

    identity = PRODUCTS.get(product_name)

    if not identity or not version: return None

    part, vendor, product = identity

    return {
        "service": service,
        "part": part,
        "vendor": vendor,
        "product": product,
        "version": version
    }
