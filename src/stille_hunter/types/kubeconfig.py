# SPDX-License-Identifier: Apache-2.0
"""Canary type: kubeconfig - a Kubernetes kubeconfig with fake credentials.

Kubeconfigs carry cluster credentials and leak through repos, backups, CI logs
and laptops. This type emits a complete-looking kubeconfig (cluster, context,
user) with an inert bearer token, to seed where a real one would sit. If it
later shows up in public code, a paste or a dump, searching for the token finds
it, and the ledger says which seeded location it came from.

Everything in it is INERT. This is a SEARCH canary (detect=search):
  * token: kubeadm bootstrap-token format, `[a-z0-9]{6}.[a-z0-9]{16}`, whose
    first part IS our 6-hex canary token. (A service-account JWT would look
    real too, but is hundreds of characters long - too long to search for.)
  * server: an RFC 1918 private address on port 6443, so it can never point
    at anyone's real, internet-reachable cluster.
  * certificate-authority-data: a PEM-shaped, base64-encoded blob of random
    bytes - it looks like a CA certificate but does not parse as one.
"""
from __future__ import annotations

import argparse
import base64
import secrets
import textwrap
from typing import Iterable

from ..generate import CanaryType, new_token, register_type

_LOWER_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"

_CLUSTERS = ["prod-cluster", "k8s-prod-01", "staging-cluster", "platform-prod",
             "apps-prod", "k8s-main", "data-cluster", "edge-cluster"]
_USERS = ["kubernetes-admin", "deploy-bot", "ci-deployer", "ops-admin",
          "cluster-admin", "gitops-sync"]


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _private_server() -> str:
    """https://<RFC 1918 address>:6443 - never a public, reachable host."""
    octet = secrets.randbelow(256)
    host = secrets.randbelow(254) + 1
    block = secrets.randbelow(3)
    if block == 0:
        ip = f"10.{secrets.randbelow(256)}.{octet}.{host}"
    elif block == 1:
        ip = f"172.{16 + secrets.randbelow(16)}.{octet}.{host}"
    else:
        ip = f"192.168.{octet}.{host}"
    return f"https://{ip}:6443"


def _fake_ca_data() -> str:
    """base64 of a PEM-shaped block of random bytes (not a real certificate)."""
    body = "\n".join(textwrap.wrap(base64.b64encode(secrets.token_bytes(780)).decode(), 64))
    pem = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"
    return base64.b64encode(pem.encode()).decode()


def _kubeconfig(cluster: str, user: str, server: str, ca_data: str, kube_token: str) -> str:
    # Keys in the order `kubectl config view` prints them.
    context = f"{user}@{cluster}"
    return (
        "apiVersion: v1\n"
        "clusters:\n"
        "- cluster:\n"
        f"    certificate-authority-data: {ca_data}\n"
        f"    server: {server}\n"
        f"  name: {cluster}\n"
        "contexts:\n"
        "- context:\n"
        f"    cluster: {cluster}\n"
        f"    user: {user}\n"
        f"  name: {context}\n"
        f"current-context: {context}\n"
        "kind: Config\n"
        "preferences: {}\n"
        "users:\n"
        f"- name: {user}\n"
        "  user:\n"
        f"    token: {kube_token}\n"
    )


@register_type
class KubeconfigType(CanaryType):
    name = "kubeconfig"
    description = "Fake Kubernetes kubeconfig with an inert token and a private server."

    def add_arguments(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("--cluster-name", default=None,
                       help="Cluster name to use (default: a plausible random name).")

    def generate(self, args, count: int) -> Iterable[dict]:
        for _ in range(count):
            yield self._one(args.cluster_name)

    def _one(self, cluster_name) -> dict:
        token = new_token()                                # 6 hex: fits [a-z0-9]{6}
        kube_token = f"{token}.{_rand(_LOWER_ALNUM, 16)}"  # bootstrap-token format
        cluster = cluster_name or secrets.choice(_CLUSTERS)
        user = secrets.choice(_USERS)
        server = _private_server()
        return {
            "record_id": token,
            "cluster_name": cluster,
            "kube_token": kube_token,
            "kubeconfig": _kubeconfig(cluster, user, server, _fake_ca_data(), kube_token),
            "_detect": "search",
            "_ledger": {
                "cluster_name": cluster,
                "kube_token": kube_token,
            },
        }
