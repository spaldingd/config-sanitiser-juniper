#!/usr/bin/env python3
"""
juniper_sanitise.py  —  Juniper Configuration Sanitiser
Supports Junos (EX, QFX, MX, SRX, PTX) in both set-format and curly-brace format.

What it sanitises
─────────────────
Credentials    : authentication passwords / encrypted secrets, plain-text passwords,
                 RADIUS / TACACS+ secret keys, SNMP authentication/privacy keys,
                 BGP authentication keys, IS-IS/OSPF authentication keys,
                 IKE pre-shared-keys, SSH host-key blobs, certificate data,
                 NTP authentication keys
IP addresses   : all IPv4 host addresses → consistent IPv4-xxxx tokens,
                 all IPv6 host addresses → consistent IPv6-xxxx tokens,
                 subnet masks / prefix-lengths left unchanged;
                 link-local, loopback, multicast, and unspecified IPv6
                 addresses are preserved
AS numbers     : routing-options autonomous-system, bgp group remote-as,
                 VRF/instance rd / route-targets, community values,
                 confederation AS — consistent AS-xxxx tokens
SNMP           : community names → consistent tokens (traceable across config),
                 SNMP trap-group targets, SNMP location, SNMP contact
Banners        : login announcement / message body → <REMOVED>
Named objects  : hostnames, domain names, usernames, routing-instances (VRF),
                 routing-policies, firewall filters, prefix-lists/sets,
                 community terms, policy-statements, class-of-service (CoS)
                 schedulers/classifiers/forwarding-classes, BGP groups,
                 IKE proposals/policies/gateways, IPsec proposals/policies/VPNs,
                 security zones, address-books, NAT rule-sets,
                 aaa access-profiles
Descriptions   : all free-text description lines → desc-xxxx tokens

Junos format support
─────────────────────
Both config formats produced by Junos are handled:
  set-format   (one statement per line, "set system host-name ROUTER-A")
  curly-brace  (hierarchical block syntax, indented with { } delimiters)
Many real configs mix both or are exported in one form; the script handles either.

Usage
─────
  python juniper_sanitise.py -i ./configs/ -o ./clean/ --seed myproject
  python juniper_sanitise.py -i router.conf -o router_clean.conf --dump-map map.json
  python juniper_sanitise.py -i router.conf --dry-run
  python juniper_sanitise.py -i ./configs/ -o ./clean/ --no-ips --no-descriptions
"""

import re
import sys
import json
import hashlib
import argparse
import ipaddress
from datetime import datetime, timezone
from pathlib import Path


# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

RESERVED_KEYWORDS = {
    # Junos syntax keywords that must never be treated as object names
    "default", "any", "all", "none", "permit", "deny", "in", "out",
    "input", "output", "both", "true", "false", "enable", "disable",
    "active", "inactive", "static", "dynamic", "unicast", "multicast",
    "inet", "inet6", "mpls", "iso", "evpn", "vpls", "l2vpn",
    "internal", "external", "local", "management", "null", "reject",
    "discard", "next", "accept", "then", "from", "to", "term",
    "through", "upto", "prefix-length-range", "neighbor", "interface",
    "instance", "master", "primary", "secondary", "backup",
    "encrypted", "plain-text", "md5", "sha-1", "sha-256", "hmac-sha-1",
    "hmac-md5", "yes", "no", "always", "never", "optional",
    "inet-unicast", "inet6-unicast", "inet-vpn", "inet6-vpn",
    "inet-mdt", "inet6-labeled-unicast", "inet-labeled-unicast",
    "inet-mvpn", "inet6-mvpn", "l2vpn-signalling",
    "export", "import", "bgp", "ospf", "ospf3", "isis", "rip", "ripng",
    "aggregate", "direct", "pim",
}

CATEGORY_PREFIXES = {
    "hostname":           "host",
    "username":           "user",
    "domain":             "dom",
    "routing_instance":   "vrf",
    "routing_policy":     "rpol",
    "firewall_filter":    "ff",
    "prefix_list":        "pfx",
    "community":          "cmty",
    "snmp_community":     "snmp",
    "bgp_group":          "bgrp",
    "aaa_profile":        "aaa",
    "ike_proposal":       "ikep",
    "ike_policy":         "ikepol",
    "ike_gateway":        "ikegw",
    "ipsec_proposal":     "isap",
    "ipsec_policy":       "isapol",
    "ipsec_vpn":          "vpn",
    "security_zone":      "zone",
    "address_book":       "abook",
    "nat_ruleset":        "nat",
    "cos_scheduler":      "sched",
    "cos_classifier":     "cls",
    "cos_fwdclass":       "fwdc",
    "cos_policy":         "cospol",
    "keychain":           "kc",
    "description":        "desc",
    "as_number":          "AS",
    "ip_address":         "IPv4",
    "ipv6_address":       "IPv6",
}

# Standard subnet masks (255.x.x.x or 0.x.x.x patterns with only valid mask octets)
_SUBNET_MASK_RE = re.compile(
    r'\b(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)\b'
)

_IP_RE = re.compile(
    r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# IPv6 address regex — union of all RFC 5952 compressed forms.
# Bounded by negative lookbehind/lookahead so it stops at '/' (prefix length),
# whitespace, and other delimiters.  Each candidate is validated with
# ipaddress.ip_address() to eliminate false positives (e.g. MAC addresses).
_IPV6_RE = re.compile(r"""(?<![:\w./])(
    (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}             |
    (?:[0-9a-fA-F]{1,4}:){1,7}:                           |
    (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}          |
    (?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2} |
    (?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3} |
    (?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4} |
    (?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5} |
    [0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}          |
    ::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}         |
    ::
)(?![:\w])""", re.X | re.I)


def _collect_skip_spans(text: str) -> set[tuple[int, int]]:
    """Return spans of all IP-like values that must NOT be anonymised."""
    skip: set[tuple[int, int]] = set()

    # Standard subnet masks (well-formed mask octets only)
    # Junos uses CIDR prefix notation rather than wildcard masks, so only
    # subnet masks need to be excluded here (no ACE wildcard or network
    # statement handling required).
    for m in _SUBNET_MASK_RE.finditer(text):
        skip.add(m.span())

    return skip


# ══════════════════════════════════════════════════════════════════════════════
#  SANITISER CONFIGURATION  —  item / pass / group selection
# ══════════════════════════════════════════════════════════════════════════════

# ── Hierarchy definition ──────────────────────────────────────────────────────
#
# Three-level tree: GROUP → PASS → ITEM
# Items are the atomic units checked inside pass methods via cfg.enabled(item).
# Passes are named collections of items.
# Groups are named collections of passes.
#
# Key:  group_id  →  { pass_id  →  [item_id, ...] }

SANITISE_HIERARCHY: dict[str, dict[str, list[str]]] = {
    "credentials": {
        "local-auth": [
            "root-password",
            "user-passwords",
            "ssh-keys",
        ],
        "routing-auth": [
            "bgp-keys",
            "ospf-keys",
            "isis-keys",
            "ntp-keys",
        ],
        "aaa-keys": [
            "radius-secrets",
            "tacacs-secrets",
        ],
        "vpn-keys": [
            "ike-psk",
        ],
        "snmpv3-keys": [
            "snmpv3-passwords",
        ],
        "pki": [
            "certificate-data",
        ],
        "informational": [
            "login-banner",
            "snmp-contact",
            "snmp-location",
        ],
    },
    "snmp": {
        "snmp": [
            "snmp-communities",
            "snmp-location",
            "snmp-contact",
        ],
    },
    "bgp-topology": {
        "as-numbers": [
            "bgp-asn",
            "vrf-rd-rt",
            "community-values",
            "bgp-confederation",
        ],
    },
    "named-objects": {
        "identity": [
            "hostname",
            "domain-name",
            "usernames",
        ],
        "routing-policy": [
            "policy-statements",
            "firewall-filters",
            "prefix-lists",
            "communities",
        ],
        "bgp-objects": [
            "bgp-groups",
        ],
        "network-objects": [
            "routing-instances",
            "security-zones",
            "address-books",
            "nat-rulesets",
        ],
        "aaa-objects": [
            "aaa-profiles",
        ],
        "vpn-objects": [
            "ike-proposals",
            "ike-policies",
            "ike-gateways",
            "ipsec-proposals",
            "ipsec-policies",
            "ipsec-vpns",
        ],
        "cos-objects": [
            "cos-schedulers",
            "cos-classifiers",
            "cos-forwarding-classes",
            "cos-scheduler-maps",
        ],
    },
    "ntp-objects": {
        "ntp-objects": [
            "ntp-key-ids",
        ],
    },
    "addressing": {
        "ipv4": [
            "ipv4-addresses",
        ],
        "ipv6": [
            "ipv6-addresses",
        ],
    },
    "descriptions": {
        "descriptions": [
            "set-descriptions",
            "block-descriptions",
        ],
    },
}

# Convenience flat lookups built once at import time
_ALL_ITEMS:  frozenset[str] = frozenset(
    item
    for passes in SANITISE_HIERARCHY.values()
    for items in passes.values()
    for item in items
)
_ALL_PASSES: frozenset[str] = frozenset(
    pass_id
    for passes in SANITISE_HIERARCHY.values()
    for pass_id in passes
)
_ALL_GROUPS: frozenset[str] = frozenset(SANITISE_HIERARCHY)

# Maps pass_id → frozenset of item_ids within it
_PASS_TO_ITEMS: dict[str, frozenset[str]] = {
    pass_id: frozenset(items)
    for passes in SANITISE_HIERARCHY.values()
    for pass_id, items in passes.items()
}

# Maps group_id → frozenset of item_ids within it
_GROUP_TO_ITEMS: dict[str, frozenset[str]] = {
    group_id: frozenset(
        item
        for pass_items in passes.values()
        for item in pass_items
    )
    for group_id, passes in SANITISE_HIERARCHY.items()
}

# Maps item_id → (group_id, pass_id) for membership queries
_ITEM_TO_PATH: dict[str, tuple[str, str]] = {
    item: (group_id, pass_id)
    for group_id, passes in SANITISE_HIERARCHY.items()
    for pass_id, items in passes.items()
    for item in items
}


class SanitiserConfig:
    """
    Resolves CLI selection flags into a frozenset of enabled item IDs.

    Precedence (highest wins):  item  >  pass  >  group

    Resolution order applied to the full item set:
      1. Start with all items enabled
      2. Apply --skip-group  (disable all items in named groups)
      3. Apply --only-group  (disable items NOT in named groups)
      4. Apply --skip-pass   (disable all items in named passes)
      5. Apply --only-pass   (disable items NOT in named passes)
      6. Apply --skip        (disable named items individually)
      7. Apply --only        (disable all items not explicitly named)

    --skip and --only are mutually exclusive at each level.
    """

    def __init__(
        self,
        skip_groups:  list[str] | None = None,
        only_groups:  list[str] | None = None,
        skip_passes:  list[str] | None = None,
        only_passes:  list[str] | None = None,
        skip_items:   list[str] | None = None,
        only_items:   list[str] | None = None,
    ) -> None:
        enabled = set(_ALL_ITEMS)

        for g in (skip_groups or []):        # step 2
            enabled -= _GROUP_TO_ITEMS.get(g, frozenset())

        if only_groups:                      # step 3
            keep = frozenset().union(*(_GROUP_TO_ITEMS.get(g, frozenset())
                                       for g in only_groups))
            enabled &= keep

        for p in (skip_passes or []):        # step 4
            enabled -= _PASS_TO_ITEMS.get(p, frozenset())

        if only_passes:                      # step 5
            keep = frozenset().union(*(_PASS_TO_ITEMS.get(p, frozenset())
                                       for p in only_passes))
            enabled &= keep

        for i in (skip_items or []):         # step 6
            enabled.discard(i)

        if only_items:                       # step 7
            enabled &= frozenset(only_items)

        self._enabled: frozenset[str] = frozenset(enabled)

    # ── Querying ──────────────────────────────────────────────────────────

    def enabled(self, item_id: str) -> bool:
        """Return True if the named item is active."""
        return item_id in self._enabled

    def pass_has_any(self, pass_id: str) -> bool:
        """Return True if at least one item in the pass is enabled."""
        return bool(_PASS_TO_ITEMS.get(pass_id, frozenset()) & self._enabled)

    def group_has_any(self, group_id: str) -> bool:
        """Return True if at least one item in the group is enabled."""
        return bool(_GROUP_TO_ITEMS.get(group_id, frozenset()) & self._enabled)

    # ── Introspection (used by banner and startup summary) ────────────────

    def disabled_items(self) -> frozenset[str]:
        return _ALL_ITEMS - self._enabled

    def disabled_passes(self) -> frozenset[str]:
        """Passes where ALL items are disabled."""
        return frozenset(
            p for p in _ALL_PASSES
            if not (_PASS_TO_ITEMS[p] & self._enabled)
        )

    def disabled_groups(self) -> frozenset[str]:
        """Groups where ALL items are disabled."""
        return frozenset(
            g for g in _ALL_GROUPS
            if not (_GROUP_TO_ITEMS[g] & self._enabled)
        )

    def summary_lines(self) -> list[str]:
        """
        Human-readable summary of what is disabled, used in the startup
        header. Reports at the coarsest granularity possible: whole groups
        first, then whole passes, then individual items.
        """
        lines = []
        reported_items: set[str] = set()

        for g in sorted(self.disabled_groups()):
            lines.append(f"  Skipped group  : {g}")
            reported_items |= _GROUP_TO_ITEMS[g]

        for p in sorted(self.disabled_passes()):
            if _PASS_TO_ITEMS[p] <= reported_items:
                continue   # already covered by a group
            lines.append(f"  Skipped pass   : {p}")
            reported_items |= _PASS_TO_ITEMS[p]

        for i in sorted(self.disabled_items()):
            if i not in reported_items:
                lines.append(f"  Skipped item   : {i}")

        return lines

    # ── Validation ────────────────────────────────────────────────────────

    @staticmethod
    def validate(
        skip_groups:  list[str],
        only_groups:  list[str],
        skip_passes:  list[str],
        only_passes:  list[str],
        skip_items:   list[str],
        only_items:   list[str],
    ) -> list[str]:
        """Return a list of error strings (empty = valid)."""
        errors: list[str] = []
        for name in skip_groups + only_groups:
            if name not in _ALL_GROUPS:
                errors.append(
                    f"Unknown group '{name}'. "
                    f"Valid: {', '.join(sorted(_ALL_GROUPS))}")
        for name in skip_passes + only_passes:
            if name not in _ALL_PASSES:
                errors.append(
                    f"Unknown pass '{name}'. "
                    f"Valid: {', '.join(sorted(_ALL_PASSES))}")
        for name in skip_items + only_items:
            if name not in _ALL_ITEMS:
                errors.append(
                    f"Unknown item '{name}'. "
                    f"Valid: {', '.join(sorted(_ALL_ITEMS))}")
        if skip_groups and only_groups:
            errors.append("--skip-group and --only-group cannot be combined.")
        if skip_passes and only_passes:
            errors.append("--skip-pass and --only-pass cannot be combined.")
        if skip_items and only_items:
            errors.append("--skip and --only cannot be combined.")
        return errors

    @classmethod
    def default(cls) -> "SanitiserConfig":
        """All items enabled — equivalent to running with no selection flags."""
        return cls()

    @classmethod
    def from_args(cls, args: "argparse.Namespace") -> "SanitiserConfig":
        """
        Construct from parsed CLI args, handling legacy flag aliases.
        --no-ips          →  --skip-group addressing
        --no-descriptions →  --skip-pass  descriptions
        """
        skip_groups = list(args.skip_group)
        only_groups = list(args.only_group)
        skip_passes = list(args.skip_pass)
        only_passes = list(args.only_pass)
        skip_items  = list(args.skip)
        only_items  = list(args.only)

        if getattr(args, "no_ips", False):
            skip_groups.append("addressing")
        if getattr(args, "no_descriptions", False):
            skip_passes.append("descriptions")

        errors = cls.validate(
            skip_groups, only_groups,
            skip_passes, only_passes,
            skip_items,  only_items,
        )
        if errors:
            for e in errors:
                print(f"  ERROR: {e}", file=sys.stderr)
            sys.exit(2)

        return cls(
            skip_groups=skip_groups,
            only_groups=only_groups,
            skip_passes=skip_passes,
            only_passes=only_passes,
            skip_items=skip_items,
            only_items=only_items,
        )


# ══════════════════════════════════════════════════════════════════════════════
#  TOKEN GENERATOR  —  deterministic, collision-safe, double-anonymisation-safe
# ══════════════════════════════════════════════════════════════════════════════

class TokenGenerator:
    def __init__(self, seed: str = "juniper-sanitise"):
        self.seed = seed
        self._maps: dict[str, dict[str, str]] = {}
        # Reverse maps: category → set of output tokens (for already_token check)
        self._reverse: dict[str, set[str]] = {}

    def get(self, category: str, original: str) -> str:
        """Return a stable anonymised token for (category, original)."""
        cat_map = self._maps.setdefault(category, {})
        rev_set = self._reverse.setdefault(category, set())
        if original in cat_map:
            return cat_map[original]
        h = hashlib.sha256(
            f"{self.seed}:{category}:{original}".encode()
        ).hexdigest()
        prefix = CATEGORY_PREFIXES.get(category, "obj")
        token = f"{prefix}-{h[:4]}"
        offset = 4
        while token in rev_set:
            token = f"{prefix}-{h[offset:offset + 4]}"
            offset += 1
        cat_map[original] = token
        rev_set.add(token)
        return token

    def already_token(self, category: str, value: str) -> bool:
        """True if value is already an output token for this category."""
        return value in self._reverse.get(category, set())

    def all_mappings(self) -> dict[str, dict[str, str]]:
        return {k: dict(v) for k, v in self._maps.items()}

    def total(self) -> int:
        return sum(len(v) for v in self._maps.values())


# ══════════════════════════════════════════════════════════════════════════════
#  IP ANONYMISER  —  IPv4-xxxx / IPv6-xxxx token scheme, masks/CIDR preserved
# ══════════════════════════════════════════════════════════════════════════════

class IPAnonymiser:
    # IPv4 addresses always kept verbatim
    PRESERVE_V4 = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}

    def __init__(self, tokens: TokenGenerator):
        self.tokens = tokens

    # ── IPv4 ──────────────────────────────────────────────────────────────────

    def _anon_v4(self, original: str) -> str:
        """Return consistent IPv4-xxxx token for a host address."""
        try:
            addr = ipaddress.ip_address(original)
        except ValueError:
            return original
        if addr.is_loopback or original in self.PRESERVE_V4:
            return original
        return self.tokens.get("ip_address", original)

    def anonymise(self, text: str) -> str:
        """Replace IPv4 host addresses with IPv4-xxxx tokens; leave masks and CIDR alone."""
        skip_spans = _collect_skip_spans(text)

        ip_re = re.compile(
            r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        )
        parts: list[str] = []
        prev = 0
        for m in ip_re.finditer(text):
            if m.span() in skip_spans:
                parts.append(text[prev:m.end()])
            else:
                parts.append(text[prev:m.start()])
                parts.append(self._anon_v4(m.group(0)))
            prev = m.end()
        parts.append(text[prev:])
        return "".join(parts)

    # ── IPv6 ──────────────────────────────────────────────────────────────────

    def _anon_v6(self, original: str) -> str:
        """Return consistent IPv6-xxxx token for a host address."""
        try:
            addr = ipaddress.ip_address(original)
        except ValueError:
            return original
        # Preserve protocol-reserved addresses — carry no topology information
        if (addr.is_loopback or addr.is_unspecified
                or addr.is_link_local or addr.is_multicast):
            return original
        return self.tokens.get("ipv6_address", original)

    def anonymise_v6(self, text: str) -> str:
        """Replace IPv6 host addresses with IPv6-xxxx tokens.

        Junos uses CIDR notation exclusively — there are no separate wildcard
        address fields — so no skip-span logic is needed beyond the negative
        lookbehind on '/' in _IPV6_RE.  Each regex candidate is validated with
        ipaddress.ip_address() to eliminate false positives such as MAC addresses.
        """
        parts: list[str] = []
        prev = 0
        for m in _IPV6_RE.finditer(text):
            candidate = m.group(1)
            replacement = self._anon_v6(candidate)
            parts.append(text[prev:m.start(1)])
            parts.append(replacement)
            prev = m.end(1)
        parts.append(text[prev:])
        return "".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
#  UNIFIED SANITISER
# ══════════════════════════════════════════════════════════════════════════════

class JuniperSanitiser:
    def __init__(self, seed: str = "juniper-sanitise",
                 cfg: SanitiserConfig | None = None):
        self.tokens = TokenGenerator(seed=seed)
        self._cfg   = cfg if cfg is not None else SanitiserConfig.default()
        self.ip_anon = (
            IPAnonymiser(self.tokens)
            if self._cfg.group_has_any("addressing") else None
        )
        self._log: list[str] = []

    # ─────────────────────────────────────────── public ──────────────────

    def process(self, text: str) -> str:
        self._log = []
        text = self._pass_credentials(text)
        if self._cfg.pass_has_any("snmp"):
            text = self._pass_snmp(text)
        if self._cfg.pass_has_any("as-numbers"):
            text = self._pass_as_numbers(text)
        if self._cfg.group_has_any("named-objects") or self._cfg.group_has_any("ntp-objects"):
            text = self._pass_named_objects(text)
        if self._cfg.pass_has_any("descriptions"):
            text = self._pass_descriptions(text)
        if self.ip_anon:
            if self._cfg.enabled("ipv4-addresses"):
                text = self.ip_anon.anonymise(text)
                self._log.append("  [IP]  IPv4 host addresses anonymised")
            if self._cfg.enabled("ipv6-addresses"):
                text = self.ip_anon.anonymise_v6(text)
                self._log.append("  [IP]  IPv6 host addresses anonymised")
        return text

    @property
    def log(self) -> list[str]:
        return list(self._log)

    # ─────────────────────────────────────────── helpers ─────────────────

    def _sub(self, pattern: re.Pattern, repl, text: str, label: str) -> str:
        result, n = pattern.subn(repl, text)
        if n:
            self._log.append(f"  [{n:>3}x] {label}")
        return result

    def _name(self, category: str, original: str) -> str:
        """Return token; pass through reserved keywords and existing tokens."""
        if original.lower() in RESERVED_KEYWORDS:
            return original
        if self.tokens.already_token(category, original):
            return original   # prevents double-anonymisation
        return self.tokens.get(category, original)

    def _repl(self, m: re.Match, category: str) -> str:
        """Generic replacement handler for patterns with named group 'n'."""
        original = m.group("n")
        token = self._name(category, original)
        s = m.start("n") - m.start()
        e = m.end("n") - m.start()
        full = m.group(0)
        return full[:s] + token + full[e:]

    def _sub_name(self, pattern: re.Pattern, category: str,
                  label: str, text: str) -> str:
        return self._sub(
            pattern,
            lambda m, cat=category: self._repl(m, cat),
            text, label
        )

    # ──────────────────────────────── pass 1: credentials ────────────────

    def _pass_credentials(self, text: str) -> str:
        S = self._sub
        C = self._cfg.enabled

        # ── local-auth ────────────────────────────────────────────────────

        if C("root-password"):
            text = S(re.compile(
                r'^(set\s+system\s+root-authentication\s+'
                r'(?:encrypted-password|plain-text-password-value)\s+)\S+',
                re.M), r'\1<REMOVED>', text, "root-authentication password (set)")

            text = S(re.compile(
                r'^(\s*(?:encrypted-password|plain-text-password-value)\s+)\S+\s*;',
                re.M), r'\1<REMOVED>;', text,
                "encrypted-password / plain-text-password (block)")

            text = S(re.compile(
                r'^(set\s+system\s+login\s+user\s+\S+\s+authentication\s+'
                r'(?:encrypted-password|plain-text-password-value)\s+)\S+',
                re.M), r'\1<REMOVED>', text,
                "login user authentication password (set)")

        if C("ssh-keys"):
            text = S(re.compile(
                r'^(set\s+system\s+login\s+user\s+\S+\s+authentication\s+'
                r'(?:ssh-rsa|ssh-dsa|ssh-ecdsa|ssh-ed25519)\s+)\S+',
                re.M), r'\1<REMOVED>', text, "login user SSH public-key (set)")

            text = S(re.compile(
                r'^(\s*(?:ssh-rsa|ssh-dsa|ssh-ecdsa|ssh-ed25519)\s+)\S+\s*;',
                re.M), r'\1<REMOVED>;', text, "SSH public-key (block)")

        # ── aaa-keys ──────────────────────────────────────────────────────

        if C("radius-secrets"):
            text = S(re.compile(
                r'^(set\s+access\s+radius-server\s+\S+(?:\s+\S+)*?\s+secret\s+)\S+',
                re.M), r'\1<REMOVED>', text, "RADIUS server secret (set)")

            text = S(re.compile(
                r'^(\s*secret\s+)\S+\s*;',
                re.M), r'\1<REMOVED>;', text, "AAA server secret (block)")

        if C("tacacs-secrets"):
            text = S(re.compile(
                r'^(set\s+access\s+tacplus-server\s+\S+(?:\s+\S+)*?\s+secret\s+)\S+',
                re.M), r'\1<REMOVED>', text, "TACACS+ server secret (set)")

        # ── routing-auth ──────────────────────────────────────────────────

        if C("bgp-keys"):
            text = S(re.compile(
                r'^(set\s+protocols\s+bgp\s+.*?authentication-key\s+)\S+',
                re.M), r'\1<REMOVED>', text, "BGP authentication-key (set)")

            text = S(re.compile(
                r'^(\s*authentication-key\s+)\S+\s*;',
                re.M), r'\1<REMOVED>;', text, "BGP authentication-key (block)")

        if C("ospf-keys"):
            text = S(re.compile(
                r'^(set\s+protocols\s+ospf3?\s+.*?\s+key\s+)\S+',
                re.M), r'\1<REMOVED>', text, "OSPF authentication key (set)")

            text = S(re.compile(
                r'^(\s*key\s+)(?!\d+\s*[{;])(\S+)\s*;',
                re.M), r'\1<REMOVED>;', text, "authentication key (block)")

        if C("isis-keys"):
            text = S(re.compile(
                r'^(set\s+protocols\s+isis\s+.*?authentication-key\s+)\S+',
                re.M), r'\1<REMOVED>', text, "IS-IS authentication-key (set)")

        if C("ntp-keys"):
            text = S(re.compile(
                r'^(set[^\S\n]+system[^\S\n]+ntp[^\S\n]+authentication-key[^\S\n]+\d+[^\S\n]+'
                r'(?:\S+[^\S\n]+)+value[^\S\n]+)\S+',
                re.M), r'\1<REMOVED>', text, "NTP authentication-key value (set)")

            text = S(re.compile(
                r'^(\s*value\s+)\S+\s*;',
                re.M), r'\1<REMOVED>;', text, "NTP authentication-key value (block)")

        # ── vpn-keys ──────────────────────────────────────────────────────

        if C("ike-psk"):
            text = S(re.compile(
                r'^(set\s+security\s+ike\s+policy\s+\S+\s+pre-shared-key\s+'
                r'(?:ascii-text|hexadecimal)\s+)\S+',
                re.M), r'\1<REMOVED>', text, "IKE pre-shared-key (set)")

            text = S(re.compile(
                r'^(\s*(?:ascii-text|hexadecimal)\s+)\S+\s*;',
                re.M), r'\1<REMOVED>;', text, "IKE pre-shared-key (block)")

        # ── snmpv3-keys ───────────────────────────────────────────────────

        if C("snmpv3-passwords"):
            text = S(re.compile(
                r'^(set\s+snmp\s+.*?(?:authentication-password|privacy-password)\s+)\S+',
                re.M), r'\1<REMOVED>', text, "SNMPv3 auth/priv password (set)")

            text = S(re.compile(
                r'^(\s*(?:authentication-password|privacy-password)\s+)\S+\s*;',
                re.M), r'\1<REMOVED>;', text, "SNMPv3 auth/priv password (block)")

        # ── pki ───────────────────────────────────────────────────────────

        if C("certificate-data"):
            text = S(re.compile(
                r'(\bcertificate\s+\{[^}]*\})',
                re.M | re.DOTALL),
                r'certificate { <REMOVED> }', text, "certificate block")

            text = S(re.compile(
                r'^(set\s+security\s+pki\s+local-certificate\s+\S+\s+certificate\s+)\S+',
                re.M), r'\1<REMOVED>', text, "PKI local-certificate data (set)")

        # ── informational ─────────────────────────────────────────────────

        if C("login-banner"):
            text = S(re.compile(
                r'^(set\s+system\s+login\s+(?:announcement|message)\s+)\S.*$',
                re.M), r'\1<REMOVED>', text, "login announcement/message (set)")

            text = S(re.compile(
                r'^(\s*(?:announcement|message)\s+)\S.*?;$',
                re.M), r'\1<REMOVED>;', text, "login announcement/message (block)")

        if C("snmp-contact"):
            text = S(re.compile(r'^(set\s+snmp\s+contact\s+).+$', re.M),
                r'\1<REMOVED>', text, "SNMP contact (set)")

            text = S(re.compile(r'^(\s*contact\s+).+;$', re.M),
                r'\1<REMOVED>;', text, "SNMP contact (block)")

        if C("snmp-location"):
            text = S(re.compile(r'^(set\s+snmp\s+location\s+).+$', re.M),
                r'\1<REMOVED>', text, "SNMP location (set)")

            text = S(re.compile(r'^(\s*location\s+).+;$', re.M),
                r'\1<REMOVED>;', text, "SNMP location (block)")

        return text

    # ──────────────────────────────── pass 2: SNMP ───────────────────────

    def _pass_snmp(self, text: str) -> str:
        N = self._sub_name
        C = self._cfg.enabled

        if C("snmp-communities"):
            text = N(re.compile(r'^(set\s+snmp\s+community\s+)(?P<n>\S+)', re.M),
                     "snmp_community", "SNMP community def (set)", text)

            text = N(re.compile(
                r'^(\s*community\s+)'
                r'(?P<n>(?!authorization\b|clients\b|routing-instance\b|view\b|restrict\b)\S+)'
                r'\s*\{', re.M),
                     "snmp_community", "SNMP community def (block)", text)

            text = N(re.compile(r'^(set\s+snmp\s+trap-group\s+)(?P<n>\S+)', re.M),
                     "snmp_community", "SNMP trap-group name", text)

        # snmp-contact and snmp-location are handled in pass 1 (credentials/informational).
        # They share the same item IDs so the guard there covers them.

        return text

    # ──────────────────────────────── pass 3: AS numbers ─────────────────

    def _pass_as_numbers(self, text: str) -> str:
        C = self._cfg.enabled

        def replace_as(m: re.Match) -> str:
            return m.group(1) + self.tokens.get("as_number", m.group(2))

        def replace_rt(m: re.Match) -> str:
            return (m.group(1)
                    + self.tokens.get("as_number", m.group(2))
                    + m.group(3))

        if C("bgp-asn"):
            text = self._sub(
                re.compile(
                    r'^(set\s+routing-options\s+autonomous-system\s+)(\d+(?:\.\d+)?)',
                    re.M),
                replace_as, text, "routing-options autonomous-system (set)")

            text = self._sub(
                re.compile(r'^(\s*autonomous-system\s+)(\d+(?:\.\d+)?)\s*;', re.M),
                lambda m: replace_as(m) + ';', text, "autonomous-system (block)")

            text = self._sub(
                re.compile(
                    r'^(set\s+protocols\s+bgp\s+.*?local-as\s+)(\d+(?:\.\d+)?)',
                    re.M),
                replace_as, text, "BGP local-as (set)")

            text = self._sub(
                re.compile(r'^(\s*local-as\s+)(\d+(?:\.\d+)?)\s*;', re.M),
                lambda m: replace_as(m) + ';', text, "BGP local-as (block)")

            text = self._sub(
                re.compile(
                    r'^(set\s+protocols\s+bgp\s+.*?peer-as\s+)(\d+(?:\.\d+)?)',
                    re.M),
                replace_as, text, "BGP peer-as (set)")

            text = self._sub(
                re.compile(r'^(\s*peer-as\s+)(\d+(?:\.\d+)?)\s*;', re.M),
                lambda m: replace_as(m) + ';', text, "BGP peer-as (block)")

        if C("bgp-confederation"):
            text = self._sub(
                re.compile(
                    r'^(set\s+routing-options\s+confederation\s+)(\d+(?:\.\d+)?)',
                    re.M),
                replace_as, text, "confederation AS (set)")

            def replace_confederation_peers(m: re.Match) -> str:
                prefix = m.group(1)
                peers = re.sub(
                    r'\d+(?:\.\d+)?',
                    lambda a: self.tokens.get("as_number", a.group(0)),
                    m.group(2))
                return prefix + peers
            text = self._sub(
                re.compile(
                    r'^(set\s+routing-options\s+confederation\s+peers\s+)(.+)$',
                    re.M),
                replace_confederation_peers, text, "confederation peers (set)")

        if C("vrf-rd-rt"):
            text = self._sub(
                re.compile(
                    r'((?:set\s+)?(?:\s*)route-distinguisher\s+)(\d+(?:\.\d+)?)(:\d+)',
                    re.M),
                replace_rt, text, "route-distinguisher AS:tag")

            text = self._sub(
                re.compile(
                    r'((?:set\s+)?(?:.*?\s+)?(?:vrf-target|target)\s+)(\d+(?:\.\d+)?)(:\d+)',
                    re.M),
                replace_rt, text, "route-target / vrf-target AS:tag")

        if C("community-values"):
            text = self._sub(
                re.compile(r'(\btarget:)(\d+(?:\.\d+)?)(:\d+)', re.M),
                replace_rt, text, "community target: AS:tag")

            text = self._sub(
                re.compile(r'(\borigin:)(\d+(?:\.\d+)?)(:\d+)', re.M),
                replace_rt, text, "community origin: AS:tag")

            text = self._sub(
                re.compile(r'(\bmembers\s+\[\s*)(\d+(?:\.\d+)?)(:\d+)', re.M),
                replace_rt, text, "community members AS:tag")

            text = self._sub(
                re.compile(r'(\s)(\d{4,5})(:\d+)(?=\s|;|\])', re.M),
                replace_rt, text, "community value AS:tag (inline)")

        return text

    # ──────────────────────────────── pass 4: named objects ──────────────

    def _pass_named_objects(self, text: str) -> str:
        N = self._sub_name
        C = self._cfg.enabled

        # ── identity ──────────────────────────────────────────────────────

        if C("hostname"):
            text = N(re.compile(r'^(set\s+system\s+host-name\s+)(?P<n>\S+)', re.M),
                     "hostname", "host-name (set)", text)
            text = N(re.compile(r'^(\s*host-name\s+)(?P<n>\S+)\s*;', re.M),
                     "hostname", "host-name (block)", text)

        if C("domain-name"):
            text = N(re.compile(r'^(set\s+system\s+domain-name\s+)(?P<n>\S+)', re.M),
                     "domain", "domain-name (set)", text)
            text = N(re.compile(r'^(\s*domain-name\s+)(?P<n>\S+)\s*;', re.M),
                     "domain", "domain-name (block)", text)
            text = N(re.compile(r'^(set\s+system\s+domain-search\s+)(?P<n>\S+)', re.M),
                     "domain", "domain-search (set)", text)

        if C("usernames"):
            text = N(re.compile(r'^(set\s+system\s+login\s+user\s+)(?P<n>\S+)', re.M),
                     "username", "login user (set)", text)
            text = N(re.compile(r'^(\s*user\s+)(?P<n>(?!name\b)\S+)\s*\{', re.M),
                     "username", "login user (block)", text)

        # ── aaa-objects ───────────────────────────────────────────────────

        if C("aaa-profiles"):
            text = N(re.compile(r'^(set\s+access\s+profile\s+)(?P<n>\S+)', re.M),
                     "aaa_profile", "access profile name (set)", text)

        # ── network-objects ───────────────────────────────────────────────

        if C("routing-instances"):
            text = N(re.compile(r'^(set\s+routing-instances\s+)(?P<n>\S+)', re.M),
                     "routing_instance", "routing-instance (set)", text)
            text = N(re.compile(r'^(\s*instance\s+)(?P<n>\S+)\s*\{', re.M),
                     "routing_instance", "routing-instance (block)", text)
            text = N(re.compile(
                r'(\binstance\s+)(?P<n>(?!type\b|master\b)\S+)(?=\s*[;{])', re.M),
                     "routing_instance", "routing-instance ref (block)", text)

        if C("security-zones"):
            text = N(re.compile(
                r'^(set\s+security\s+zones\s+security-zone\s+)(?P<n>\S+)', re.M),
                     "security_zone", "security-zone def (set)", text)
            text = N(re.compile(r'^(\s*security-zone\s+)(?P<n>\S+)\s*\{', re.M),
                     "security_zone", "security-zone def (block)", text)
            text = N(re.compile(r'(\bfrom-zone\s+)(?P<n>\S+)(?=\s)', re.M),
                     "security_zone", "from-zone ref", text)
            text = N(re.compile(r'(\bto-zone\s+)(?P<n>\S+)(?=\s)', re.M),
                     "security_zone", "to-zone ref", text)

        if C("address-books"):
            text = N(re.compile(
                r'^(set\s+security\s+address-book\s+)(?P<n>(?!global\b)\S+)', re.M),
                     "address_book", "address-book def (set)", text)

        if C("nat-rulesets"):
            text = N(re.compile(
                r'^(set\s+security\s+nat\s+\S+\s+rule-set\s+)(?P<n>\S+)', re.M),
                     "nat_ruleset", "NAT rule-set def (set)", text)

        # ── routing-policy ────────────────────────────────────────────────

        if C("policy-statements"):
            text = N(re.compile(
                r'^(set\s+policy-options\s+policy-statement\s+)(?P<n>\S+)', re.M),
                     "routing_policy", "policy-statement def (set)", text)
            text = N(re.compile(r'^(\s*policy-statement\s+)(?P<n>\S+)\s*\{', re.M),
                     "routing_policy", "policy-statement def (block)", text)
            text = N(re.compile(
                r'^(set\s+(?:routing-instances\s+\S+\s+)?protocols\s+\S+.*?\s+'
                r'(?:export|import)\s+)(?P<n>[A-Za-z]\S*)', re.M),
                     "routing_policy",
                     "routing protocol export/import policy ref (set)", text)
            text = N(re.compile(
                r'^(set\s+routing-options\s+(?:static\s+\S+\s+)?'
                r'(?:export|import)\s+)(?P<n>[A-Za-z]\S*)', re.M),
                     "routing_policy", "routing-options policy ref (set)", text)
            text = N(re.compile(
                r'(\b(?:export|import)\s+)(?P<n>(?!\[)[A-Za-z]\S*)(?=\s*[;])',
                re.M),
                     "routing_policy", "export/import policy ref (block)", text)

        if C("firewall-filters"):
            text = N(re.compile(
                r'^(set\s+firewall\s+(?:family\s+\S+\s+)?filter\s+)(?P<n>\S+)',
                re.M),
                     "firewall_filter", "firewall filter def (set)", text)
            text = N(re.compile(
                r'^(\s*filter\s+)'
                r'(?P<n>(?!input\b|output\b|input-list\b|output-list\b)\S+)\s*\{',
                re.M),
                     "firewall_filter", "firewall filter def (block)", text)
            text = N(re.compile(
                r'^(set\s+interfaces\s+\S+\s+.*?filter\s+(?:input|output)\s+)'
                r'(?P<n>\S+)', re.M),
                     "firewall_filter", "firewall filter ref (interface, set)", text)
            text = N(re.compile(
                r'(\bfilter\s+(?:input|output)\s+)(?P<n>\S+)(?=\s*;)', re.M),
                     "firewall_filter", "firewall filter ref (block)", text)

        if C("prefix-lists"):
            text = N(re.compile(
                r'^(set\s+policy-options\s+prefix-list\s+)(?P<n>\S+)', re.M),
                     "prefix_list", "prefix-list def (set)", text)
            text = N(re.compile(r'^(\s*prefix-list\s+)(?P<n>\S+)\s*\{', re.M),
                     "prefix_list", "prefix-list def (block)", text)
            text = N(re.compile(r'(\bprefix-list\s+)(?P<n>\S+)(?=\s*;)', re.M),
                     "prefix_list", "prefix-list ref", text)

        if C("communities"):
            text = N(re.compile(
                r'^(set\s+policy-options\s+community\s+)(?P<n>\S+)', re.M),
                     "community", "community def (set)", text)
            text = N(re.compile(
                r'^(\s*community\s+)(?P<n>(?!delete\b|add\b|set\b)\S+)\s*\{',
                re.M),
                     "community", "community def (block)", text)
            text = N(re.compile(
                r'(\bcommunity\s+(?:add\s+|delete\s+|set\s+)?)'
                r'(?P<n>[A-Za-z]\S*)(?=\s*;)', re.M),
                     "community", "community ref", text)

        # ── bgp-objects ───────────────────────────────────────────────────

        if C("bgp-groups"):
            text = N(re.compile(
                r'^(set\s+protocols\s+bgp\s+group\s+)(?P<n>\S+)', re.M),
                     "bgp_group", "BGP group def (set)", text)
            text = N(re.compile(r'^(\s*group\s+)(?P<n>(?!bgp\b)\S+)\s*\{', re.M),
                     "bgp_group", "BGP group def (block)", text)

        # ── vpn-objects ───────────────────────────────────────────────────

        if C("ike-proposals") or C("ipsec-proposals"):
            # The block pattern 'proposal NAME {' is shared across IKE and IPsec stanzas.
            # It fires if either guard is enabled, consistent with set-format behaviour.
            text = N(re.compile(r'^(\s*proposal\s+)(?P<n>\S+)\s*\{', re.M),
                         "ike_proposal", "IKE/IPsec proposal def (block)", text)

        if C("ike-proposals"):
            text = N(re.compile(
                r'^(set\s+security\s+ike\s+proposal\s+)(?P<n>\S+)', re.M),
                     "ike_proposal", "IKE proposal def (set)", text)

        if C("ike-policies") or C("ipsec-policies"):
            # The block pattern 'policy NAME {' is shared across IKE and IPsec stanzas.
            text = N(re.compile(
                r'^(\s*policy\s+)(?P<n>(?!default\b)\S+)\s*\{', re.M),
                     "ike_policy", "IKE/IPsec policy def (block)", text)

        if C("ike-policies"):
            text = N(re.compile(
                r'^(set\s+security\s+ike\s+policy\s+)(?P<n>\S+)', re.M),
                     "ike_policy", "IKE policy def (set)", text)

        if C("ike-gateways"):
            text = N(re.compile(
                r'^(set\s+security\s+ike\s+gateway\s+)(?P<n>\S+)', re.M),
                     "ike_gateway", "IKE gateway def (set)", text)
            text = N(re.compile(r'^(\s*gateway\s+)(?P<n>\S+)\s*\{', re.M),
                     "ike_gateway", "IKE gateway def (block)", text)

        if C("ipsec-proposals"):
            text = N(re.compile(
                r'^(set\s+security\s+ipsec\s+proposal\s+)(?P<n>\S+)', re.M),
                     "ipsec_proposal", "IPsec proposal def (set)", text)

        if C("ipsec-policies"):
            text = N(re.compile(
                r'^(set\s+security\s+ipsec\s+policy\s+)(?P<n>\S+)', re.M),
                     "ipsec_policy", "IPsec policy def (set)", text)

        if C("ipsec-vpns"):
            text = N(re.compile(
                r'^(set\s+security\s+ipsec\s+vpn\s+)(?P<n>\S+)', re.M),
                     "ipsec_vpn", "IPsec VPN def (set)", text)
            text = N(re.compile(r'^(\s*vpn\s+)(?P<n>\S+)\s*\{', re.M),
                     "ipsec_vpn", "IPsec VPN def (block)", text)

        # ── cos-objects ───────────────────────────────────────────────────

        if C("cos-schedulers"):
            text = N(re.compile(
                r'^(set\s+class-of-service\s+schedulers\s+)(?P<n>\S+)', re.M),
                     "cos_scheduler", "CoS scheduler def (set)", text)

        if C("cos-classifiers"):
            text = N(re.compile(
                r'^(set\s+class-of-service\s+classifiers\s+\S+\s+)(?P<n>\S+)',
                re.M),
                     "cos_classifier", "CoS classifier def (set)", text)

        if C("cos-forwarding-classes"):
            text = N(re.compile(
                r'^(set\s+class-of-service\s+forwarding-classes\s+class\s+)'
                r'(?P<n>\S+)', re.M),
                     "cos_fwdclass", "CoS forwarding-class def (set)", text)

        if C("cos-scheduler-maps"):
            text = N(re.compile(
                r'^(set\s+class-of-service\s+interfaces\s+\S+\s+scheduler-map\s+)'
                r'(?P<n>\S+)', re.M),
                     "cos_policy", "CoS scheduler-map ref (set)", text)
            text = N(re.compile(
                r'^(set\s+class-of-service\s+scheduler-maps\s+)(?P<n>\S+)', re.M),
                     "cos_policy", "CoS scheduler-map def (set)", text)

        # ── ntp-objects ───────────────────────────────────────────────────

        if C("ntp-key-ids"):
            text = N(re.compile(
                r'^(set\s+system\s+ntp\s+authentication-key\s+)(?P<n>\d+)', re.M),
                     "keychain", "NTP authentication-key ID (set)", text)
            text = N(re.compile(
                r'^(set\s+system\s+ntp\s+trusted-key\s+)(?P<n>\d+)', re.M),
                     "keychain", "NTP trusted-key ref (set)", text)

        return text

    # ──────────────────────────────── pass 5: descriptions ───────────────

    def _pass_descriptions(self, text: str) -> str:
        cfg = self._cfg

        def repl(m: re.Match) -> str:
            prefix = m.group(1)
            desc = m.group(2)
            if self.tokens.already_token("description", desc):
                return m.group(0)
            return prefix + self.tokens.get("description", desc)

        if cfg.enabled("set-descriptions"):
            text = self._sub(
                re.compile(r'^(set\s+.*?\s+description\s+)(.+)$', re.M),
                repl, text, "set-format description lines")

        if cfg.enabled("block-descriptions"):
            def repl_block(m: re.Match) -> str:
                prefix = m.group(1)
                desc = m.group(2)
                if self.tokens.already_token("description", desc):
                    return m.group(0)
                return prefix + self.tokens.get("description", desc) + ";"
            text = self._sub(
                re.compile(r'^(\s*description\s+)(.+?)\s*;$', re.M),
                repl_block, text, "block-format description lines")

        return text

    # ──────────────────────────────── mapping report ─────────────────────

    def mapping_report(self, as_json: bool = False) -> str:
        mappings = self.tokens.all_mappings()
        if not mappings:
            return "  Nothing was anonymised."
        if as_json:
            return json.dumps(mappings, indent=2)
        lines = []
        for category, m in sorted(mappings.items()):
            if not m:
                continue
            lines.append(f"\n  [{category}]")
            for orig, token in sorted(m.items()):
                lines.append(f"    {orig:<50} →  {token}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sanitise Juniper Junos configuration files (set-format and curly-brace).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Selection flags (can be combined; item > pass > group precedence):
  --skip-group credentials      skip the entire credentials group
  --only-group named-objects    run only the named-objects group
  --skip-pass  vpn-keys         skip the vpn-keys pass
  --only-pass  routing-auth     run only the routing-auth pass
  --skip       login-banner,ntp-keys  skip specific items
  --only       hostname,ipv4-addresses  run only these items

Available groups : credentials, snmp, bgp-topology, named-objects,
                   ntp-objects, addressing, descriptions
Available passes : local-auth, routing-auth, aaa-keys, vpn-keys, snmpv3-keys,
                   pki, informational, snmp, as-numbers, identity,
                   routing-policy, bgp-objects, network-objects, aaa-objects,
                   vpn-objects, cos-objects, ntp-objects, ipv4, ipv6,
                   descriptions
Run with --list-items to see all available item IDs.

Legacy flags (still supported):
  --no-ips          equivalent to --skip-group addressing
  --no-descriptions equivalent to --skip-pass  descriptions

Examples:
  python juniper_sanitise.py -i ./configs/ -o ./clean/ --seed myproject
  python juniper_sanitise.py -i router.conf --dry-run
  python juniper_sanitise.py -i router.conf --skip-group addressing,descriptions
  python juniper_sanitise.py -i router.conf --only-group credentials,snmp
  python juniper_sanitise.py -i router.conf --skip login-banner,ntp-keys
        """
    )
    p.add_argument("-i", "--input",       required=False,
                   help="Input file or directory")
    p.add_argument("-o", "--output",      required=False,
                   help="Output file or directory")
    p.add_argument("--seed",              default="juniper-sanitise",
                   help="Determinism seed — same seed = same tokens every run")
    p.add_argument("--dump-map",          metavar="FILE",
                   help="Write full original→token mapping to a JSON file")
    p.add_argument("--dry-run",           action="store_true",
                   help="Print sanitised output to stdout; do not write files")
    p.add_argument("--extensions",        default=".conf,.txt,.cfg,.log",
                   help="Comma-separated file extensions to process when input is a directory")
    p.add_argument("--list-items",        action="store_true",
                   help="Print all valid group / pass / item IDs and exit")

    # Selection flags
    sel = p.add_argument_group("selection (group level)")
    sel.add_argument("--skip-group", metavar="GROUP[,GROUP...]", default="",
                     help="Disable all items in the named group(s)")
    sel.add_argument("--only-group", metavar="GROUP[,GROUP...]", default="",
                     help="Enable only the named group(s); disable everything else")

    sel2 = p.add_argument_group("selection (pass level)")
    sel2.add_argument("--skip-pass", metavar="PASS[,PASS...]", default="",
                      help="Disable all items in the named pass(es)")
    sel2.add_argument("--only-pass", metavar="PASS[,PASS...]", default="",
                      help="Enable only the named pass(es); disable everything else")

    sel3 = p.add_argument_group("selection (item level)")
    sel3.add_argument("--skip", metavar="ITEM[,ITEM...]", default="",
                      help="Disable the named item(s)")
    sel3.add_argument("--only", metavar="ITEM[,ITEM...]", default="",
                      help="Enable only the named item(s); disable everything else")

    # Legacy aliases (kept for backward compatibility)
    leg = p.add_argument_group("legacy flags (deprecated aliases)")
    leg.add_argument("--no-ips",          action="store_true",
                     help="Skip IP address anonymisation (alias: --skip-group addressing)")
    leg.add_argument("--no-descriptions", action="store_true",
                     help="Skip description anonymisation (alias: --skip-pass descriptions)")

    args = p.parse_args()

    # --list-items: print hierarchy and exit
    if args.list_items:
        print("\nAvailable groups, passes, and items:\n")
        for group_id, passes in SANITISE_HIERARCHY.items():
            print(f"  GROUP: {group_id}")
            for pass_id, items in passes.items():
                print(f"    PASS: {pass_id}")
                for item in items:
                    print(f"      item: {item}")
        print()
        sys.exit(0)

    if not args.input:
        p.error("the following arguments are required: -i/--input")

    # Normalise comma-separated values to lists
    def _split(s: str) -> list[str]:
        return [x.strip() for x in s.split(",") if x.strip()]

    args.skip_group = _split(args.skip_group)
    args.only_group = _split(args.only_group)
    args.skip_pass  = _split(args.skip_pass)
    args.only_pass  = _split(args.only_pass)
    args.skip       = _split(args.skip)
    args.only       = _split(args.only)

    return args


# Repository URL — update this when the project is published.
# This value is embedded in the sanitised-configuration banner.
REPO_URL = "https://github.com/YOUR-ORG/YOUR-REPO"


def _seed_fingerprint(seed: str) -> str:
    """
    Return a 16-character hex fingerprint of the seed (first 64 bits of
    SHA-256). This is published in the sanitised-output banner so that two
    files can be verified as sharing the same seed (and therefore having
    consistent tokens) without exposing the seed itself.

    The seed is intentionally kept secret because, combined with the script,
    it enables forward-lookup against guessable values — most critically,
    IP addresses, where exhaustive enumeration of RFC 1918 space is trivial.
    A fingerprint preserves the diff-ability use-case while eliminating that
    risk.
    """
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def _sanitised_banner(seed: str, cfg: SanitiserConfig) -> str:
    """
    Return a comment block to prepend to every sanitised output file.
    Uses '#' as the comment character, which is valid on Junos.
    The action list is derived from SanitiserConfig so it accurately reflects
    what was actually run.
    The seed fingerprint (not the seed itself) is included so that two sanitised
    files can be confirmed as sharing the same seed without exposing it.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    fingerprint = _seed_fingerprint(seed)

    # Build action lines at the most specific accurate level.
    # Each entry is (condition, label).
    action_map = [
        (cfg.group_has_any("credentials"),
         "credentials and keys replaced with <REMOVED>"),
        (cfg.group_has_any("snmp"),
         "SNMP communities, location, and contact sanitised"),
        (cfg.group_has_any("bgp-topology"),
         "BGP AS numbers and community values replaced with opaque tokens"),
        (cfg.group_has_any("named-objects"),
         "named objects (hostnames, routing-instances, firewall filters, etc.) replaced with"
         " opaque tokens"),
        (cfg.group_has_any("addressing"),
         "IP addresses (IPv4 and IPv6) replaced with opaque tokens"),
        (cfg.pass_has_any("descriptions"),
         "description text replaced with opaque tokens"),
    ]
    actions = [label for condition, label in action_map if condition]

    # Note any entirely-skipped groups so the reader knows what was NOT done
    skipped = sorted(cfg.disabled_groups())

    sep = "#" + "=" * 69
    out_lines = [
        sep,
        "# SANITISED CONFIGURATION",
        "# This file has been processed by juniper_sanitise.py.",
        "# Original sensitive data has been replaced as follows:",
        "#",
    ]
    for action in actions:
        out_lines.append(f"#   - {action}")
    if skipped:
        out_lines.append("#")
        out_lines.append("# The following sanitisation groups were skipped:")
        for g in skipped:
            out_lines.append(f"#   - {g}")
    out_lines += [
        "#",
        f"# Sanitised   : {now}",
        f"# Seed hash   : {fingerprint}  (SHA-256 fingerprint — not the seed itself)",
        f"# Script      : {REPO_URL}",
        sep,
        "",
    ]
    return "\n".join(out_lines) + "\n"


def process_file(path: Path, dest: "Path | None",
                 sanitiser: JuniperSanitiser, dry_run: bool) -> bool:
    print(f"\n{'─' * 60}")
    print(f"  Input : {path}")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  ERROR reading: {e}")
        return False

    result = sanitiser.process(text)
    result = _sanitised_banner(sanitiser.tokens.seed, sanitiser._cfg) + result
    for entry in sanitiser.log:
        print(entry)

    if dry_run:
        print(f"\n{'═' * 60}  DRY RUN  {'═' * 60}")
        print(result)
        print(f"{'═' * 60}")
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(result, encoding="utf-8")
        print(f"  Output: {dest}")
    return True


def main() -> None:
    args = parse_args()
    cfg = SanitiserConfig.from_args(args)
    sanitiser = JuniperSanitiser(seed=args.seed, cfg=cfg)
    exts = tuple(e if e.startswith(".") else f".{e}"
                 for e in args.extensions.split(","))
    inp = Path(args.input)
    out = Path(args.output) if args.output else None

    print("╔══════════════════════════════════════════════════════════╗")
    print("║       Juniper Configuration Sanitiser                   ║")
    print("║  Junos  ·  set-format  ·  curly-brace format            ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Seed     : {args.seed}")
    print(f"  Dry run  : {'Yes' if args.dry_run else 'No'}")
    for line in cfg.summary_lines():
        print(line)
    if not cfg.summary_lines():
        print("  Selection: all items enabled (default)")

    success = failure = 0

    if inp.is_file():
        dest = (out or inp.parent / (inp.stem + "_sanitised" + inp.suffix)
                ) if not args.dry_run else None
        ok = process_file(inp, dest, sanitiser, args.dry_run)
        success += int(ok)
        failure += int(not ok)

    elif inp.is_dir():
        files = [f for f in inp.rglob("*")
                 if f.is_file() and f.suffix.lower() in exts]
        if not files:
            print(f"\n  No files matching {exts} found in {inp}")
            sys.exit(1)
        base_out = (out or inp.parent / (inp.name + "_sanitised")
                    ) if not args.dry_run else None
        for f in sorted(files):
            dest = (base_out / f.relative_to(inp)) if not args.dry_run else None
            ok = process_file(f, dest, sanitiser, args.dry_run)
            success += int(ok)
            failure += int(not ok)
    else:
        print(f"\n  ERROR: '{inp}' is not a valid file or directory.")
        sys.exit(1)

    print(f"\n{'═' * 60}")
    print(f"  Done. {success} file(s) sanitised, {failure} error(s).")
    print(f"  Unique objects anonymised: {sanitiser.tokens.total()}")
    print("\n  Full mapping:")
    print(sanitiser.mapping_report())

    if args.dump_map:
        map_path = Path(args.dump_map)
        map_path.write_text(sanitiser.mapping_report(as_json=True), encoding="utf-8")
        print(f"\n  Mapping saved to: {map_path}")


if __name__ == "__main__":
    main()
