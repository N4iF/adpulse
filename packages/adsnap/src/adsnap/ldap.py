"""Read the domain object over LDAPS with ldap3 (standard user, simple bind with the UPN over TLS)."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any, Protocol

from ldap3 import ALL, BASE, SIMPLE, Connection, Server, Tls

DOMAIN_ATTRIBUTES = ["objectGUID", "objectSid", "name", "minPwdLength", "pwdProperties", "lockoutThreshold"]


class DomainSource(Protocol):
    def read_domain(self) -> dict[str, Any]: ...


def read_ca(path: str) -> str | bytes:
    """A CA certificate file as ldap3 `ca_certs_data`: PEM text, or DER bytes as PowerShell exports them."""
    data = Path(path).read_bytes()
    if b"-----BEGIN" in data:
        return data.decode("utf-8-sig")  # PEM text, with or without the BOM Windows PowerShell 5.1 adds
    return data


class Ldap3DomainSource:
    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        *,
        ca_cert: str | None = None,
        insecure_lab: bool = False,
        timeout: int = 10,
    ) -> None:
        if insecure_lab:
            tls = Tls(validate=ssl.CERT_NONE)
        else:  # without a CA file the system trust store is used
            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=read_ca(ca_cert) if ca_cert else None)
        # get_info=ALL loads the schema, so objectGUID and objectSid arrive as text
        self._server = Server(host, port=636, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=timeout)
        self._conn = Connection(
            self._server, user=user, password=password, authentication=SIMPLE,
            auto_bind=True, raise_exceptions=True, receive_timeout=timeout,
        )

    def read_domain(self) -> dict[str, Any]:
        base = str(self._server.info.other["defaultNamingContext"][0])
        self._conn.search(base, "(objectClass=domainDNS)", search_scope=BASE, attributes=DOMAIN_ATTRIBUTES)
        entries = [e for e in self._conn.response if e.get("type") == "searchResEntry"]
        if not entries:
            raise LookupError(f"domain object {base} not found")
        return {"dn": entries[0]["dn"], **entries[0]["attributes"]}
