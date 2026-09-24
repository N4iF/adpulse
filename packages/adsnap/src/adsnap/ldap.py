"""Read the directory over LDAPS with ldap3 (standard user, simple bind with the UPN over TLS)."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any, Literal, Protocol

from ldap3 import ALL, BASE, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException


class DirectoryError(RuntimeError):
    """A directory search failed (the connection itself worked)."""


Scope = Literal["base", "subtree"]


class DirectorySource(Protocol):
    def base_dn(self) -> str: ...

    def search(self, base: str, ldap_filter: str, attributes: list[str], scope: Scope = "subtree") -> list[dict[str, Any]]: ...


def entries_to_rows(entries: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """ldap3 response dicts -> rows; referrals (searchResRef) and other message types are skipped."""
    return [{"dn": e["dn"], **e["attributes"]} for e in entries or [] if e.get("type") == "searchResEntry"]


def read_ca(path: str) -> str | bytes:
    """A CA certificate file as ldap3 `ca_certs_data`: PEM text, or DER bytes as PowerShell exports them."""
    data = Path(path).read_bytes()
    if b"-----BEGIN" in data:
        return data.decode("utf-8-sig")  # PEM text, with or without the BOM Windows PowerShell 5.1 adds
    return data


class Ldap3Source:
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

    def base_dn(self) -> str:
        return str(self._server.info.other["defaultNamingContext"][0])

    def search(self, base: str, ldap_filter: str, attributes: list[str], scope: Scope = "subtree") -> list[dict[str, Any]]:
        if scope not in ("base", "subtree"):
            raise ValueError(f"unsupported search scope {scope!r}")
        try:
            if scope == "base":
                self._conn.search(base, ldap_filter, search_scope=BASE, attributes=attributes)
                entries = self._conn.response
            else:
                entries = self._conn.extend.standard.paged_search(
                    base, ldap_filter, search_scope=SUBTREE, attributes=attributes, paged_size=500, generator=False,
                )
        except LDAPException as exc:
            raise DirectoryError(f"search {ldap_filter} failed: {exc}") from exc
        return entries_to_rows(entries)
