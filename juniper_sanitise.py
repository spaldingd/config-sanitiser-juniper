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
Syslog         : syslog host targets (IP anonymised by IP pass)
Banners        : login announcement / message body → <REMOVED>
Named objects  : hostnames, domain names, usernames, routing-instances (VRF),
                 routing-policies, firewall filters, prefix-lists/sets,
                 community terms, policy-statements, class-of-service (CoS)
                 schedulers/classifiers/forwarding-classes, BGP groups,
                 IKE proposals/policies/gateways, IPsec proposals/policies/VPNs,
                 security zones, address-books, interfaces (logical names left;
                 addresses anonymised), LLDP chassis-id (anonymised with IP pass),
                 NTP authentication keys, keychains, RADIUS/TACACS+ server names,
                 aaa access-profiles, NAT rule-sets
Descriptions   : all free-text description / remark lines → desc-xxxx tokens

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
    "static", "aggregate", "direct", "local", "pim",
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
    "aaa_server":         "srv",
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

# Standard subnet/prefix masks
_SUBNET_MASK_RE = re.compile(
    r'\b(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)\b'
)

_IP_RE = re.compile(
    r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Junos firewall term from/to lines with address match (second IP is not a wildcard
# in Junos — all masks are CIDR — so no wildcard-skip logic needed for IPv4 in Junos)

# IPv6 regex — same as Cisco script (RFC 5952 all compressed forms)
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


def _collect_skip_spans_v4(text: str) -> set[tuple[int, int]]:
    """Spans of IPv4-like values that must NOT be anonymised (subnet masks only).
    Junos uses CIDR exclusively — no wildcard mask fields — so only standard
    subnet masks need skipping."""
    skip: set[tuple[int, int]] = set()
    for m in _SUBNET_MASK_RE.finditer(text):
        skip.add(m.span())
    return skip


# ══════════════════════════════════════════════════════════════════════════════
#  TOKEN GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class TokenGenerator:
    def __init__(self, seed: str = "juniper-sanitise"):
        self.seed = seed
        self._maps: dict[str, dict[str, str]] = {}
        self._reverse: dict[str, set[str]] = {}

    def get(self, category: str, original: str) -> str:
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
        return value in self._reverse.get(category, set())

    def all_mappings(self) -> dict[str, dict[str, str]]:
        return {k: dict(v) for k, v in self._maps.items()}

    def total(self) -> int:
        return sum(len(v) for v in self._maps.values())


# ══════════════════════════════════════════════════════════════════════════════
#  IP ANONYMISER
# ══════════════════════════════════════════════════════════════════════════════

class IPAnonymiser:
    PRESERVE_V4 = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}

    def __init__(self, tokens: TokenGenerator):
        self.tokens = tokens

    def _anon_v4(self, original: str) -> str:
        try:
            addr = ipaddress.ip_address(original)
        except ValueError:
            return original
        if addr.is_loopback or original in self.PRESERVE_V4:
            return original
        return self.tokens.get("ip_address", original)

    def anonymise(self, text: str) -> str:
        skip_spans = _collect_skip_spans_v4(text)
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

    def _anon_v6(self, original: str) -> str:
        try:
            addr = ipaddress.ip_address(original)
        except ValueError:
            return original
        if (addr.is_loopback or addr.is_unspecified
                or addr.is_link_local or addr.is_multicast):
            return original
        return self.tokens.get("ipv6_address", original)

    def anonymise_v6(self, text: str) -> str:
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
                 anonymise_ips: bool = True,
                 anonymise_descriptions: bool = True):
        self.tokens = TokenGenerator(seed=seed)
        self.ip_anon = IPAnonymiser(self.tokens) if anonymise_ips else None
        self.anonymise_descriptions = anonymise_descriptions
        self._log: list[str] = []

    # ─────────────────────────────────────────── public ──────────────────

    def process(self, text: str) -> str:
        self._log = []
        text = self._pass_credentials(text)
        text = self._pass_snmp(text)
        text = self._pass_as_numbers(text)
        text = self._pass_named_objects(text)
        if self.anonymise_descriptions:
            text = self._pass_descriptions(text)
        if self.ip_anon:
            text = self.ip_anon.anonymise(text)
            self._log.append("  [IP]  IPv4 host addresses anonymised")
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
        if original.lower() in RESERVED_KEYWORDS:
            return original
        if self.tokens.already_token(category, original):
            return original
        return self.tokens.get(category, original)

    def _repl(self, m: re.Match, category: str) -> str:
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

        # ── Authentication passwords ───────────────────────────────────────

        # set system root-authentication encrypted-password "..."
        # set system root-authentication plain-text-password-value "..."
        text = S(re.compile(
            r'^(set\s+system\s+root-authentication\s+(?:encrypted-password|plain-text-password-value)\s+)\S+',
            re.M), r'\1<REMOVED>', text, "root-authentication password (set)")

        # curly-brace: encrypted-password "$...";
        # plain-text-password-value "...";
        text = S(re.compile(
            r'^(\s*(?:encrypted-password|plain-text-password-value)\s+)\S+\s*;',
            re.M), r'\1<REMOVED>;', text, "encrypted-password / plain-text-password (block)")

        # set system login user NAME authentication encrypted-password "..."
        # set system login user NAME authentication plain-text-password-value "..."
        text = S(re.compile(
            r'^(set\s+system\s+login\s+user\s+\S+\s+authentication\s+'
            r'(?:encrypted-password|plain-text-password-value)\s+)\S+',
            re.M), r'\1<REMOVED>', text, "login user authentication password (set)")

        # SSH public-key blob (rsa-public-key, dsa-public-key, ecdsa-sha2-nistp256-public-key, ed25519-public-key)
        # set system login user NAME authentication ssh-rsa "..."
        text = S(re.compile(
            r'^(set\s+system\s+login\s+user\s+\S+\s+authentication\s+'
            r'(?:ssh-rsa|ssh-dsa|ssh-ecdsa|ssh-ed25519)\s+)\S+',
            re.M), r'\1<REMOVED>', text, "login user SSH public-key (set)")

        # block: ssh-rsa "..."; / ssh-dsa "..."; etc.
        text = S(re.compile(
            r'^(\s*(?:ssh-rsa|ssh-dsa|ssh-ecdsa|ssh-ed25519)\s+)\S+\s*;',
            re.M), r'\1<REMOVED>;', text, "SSH public-key (block)")

        # RADIUS secret: set access radius-server IP [port N] secret "..."
        # Optional intermediate tokens (port N, timeout N, etc.) before secret keyword
        text = S(re.compile(
            r'^(set\s+access\s+radius-server\s+\S+(?:\s+\S+)*?\s+secret\s+)\S+',
            re.M), r'\1<REMOVED>', text, "RADIUS server secret (set)")

        # block: secret "...";  (inside radius-server or tacacs-plus-server stanza)
        text = S(re.compile(
            r'^(\s*secret\s+)\S+\s*;',
            re.M), r'\1<REMOVED>;', text, "AAA server secret (block)")

        # TACACS+ secret: set access tacplus-server IP [port N] secret "..."
        text = S(re.compile(
            r'^(set\s+access\s+tacplus-server\s+\S+(?:\s+\S+)*?\s+secret\s+)\S+',
            re.M), r'\1<REMOVED>', text, "TACACS+ server secret (set)")

        # BGP authentication key
        # set protocols bgp group NAME neighbor IP authentication-key "..."
        text = S(re.compile(
            r'^(set\s+protocols\s+bgp\s+.*?authentication-key\s+)\S+',
            re.M), r'\1<REMOVED>', text, "BGP authentication-key (set)")

        # block: authentication-key "...";
        text = S(re.compile(
            r'^(\s*authentication-key\s+)\S+\s*;',
            re.M), r'\1<REMOVED>;', text, "BGP authentication-key (block)")

        # OSPF / OSPF3 authentication
        # set protocols ospf area X interface IF authentication md5 KEY-ID key "..."
        text = S(re.compile(
            r'^(set\s+protocols\s+ospf3?\s+.*?\s+key\s+)\S+',
            re.M), r'\1<REMOVED>', text, "OSPF authentication key (set)")

        # block: key "...";  (inside authentication md5 stanza)
        # Use negative lookbehind to avoid matching "key-id N {" lines
        text = S(re.compile(
            r'^(\s*key\s+)(?!\d+\s*[{;])(\S+)\s*;',
            re.M), r'\1<REMOVED>;', text, "authentication key (block)")

        # IS-IS authentication
        # set protocols isis interface IF level 1 authentication-key "..."
        # set protocols isis authentication-key "..."
        text = S(re.compile(
            r'^(set\s+protocols\s+isis\s+.*?authentication-key\s+)\S+',
            re.M), r'\1<REMOVED>', text, "IS-IS authentication-key (set)")

        # NTP authentication-key: set system ntp authentication-key N type md5 value "..."
        text = S(re.compile(
            r'^(set\s+system\s+ntp\s+authentication-key\s+\d+\s+\S+\s+value\s+)\S+',
            re.M), r'\1<REMOVED>', text, "NTP authentication-key value (set)")

        # block: value "...";  (inside ntp authentication-key stanza)
        text = S(re.compile(
            r'^(\s*value\s+)\S+\s*;',
            re.M), r'\1<REMOVED>;', text, "NTP authentication-key value (block)")

        # IKE pre-shared-key
        # set security ike policy NAME pre-shared-key ascii-text "..."
        # set security ike policy NAME pre-shared-key hexadecimal "..."
        text = S(re.compile(
            r'^(set\s+security\s+ike\s+policy\s+\S+\s+pre-shared-key\s+(?:ascii-text|hexadecimal)\s+)\S+',
            re.M), r'\1<REMOVED>', text, "IKE pre-shared-key (set)")

        # block: ascii-text "...";  hexadecimal "...";  (inside pre-shared-key stanza)
        text = S(re.compile(
            r'^(\s*(?:ascii-text|hexadecimal)\s+)\S+\s*;',
            re.M), r'\1<REMOVED>;', text, "IKE pre-shared-key (block)")

        # SNMP authentication / privacy passwords
        # set snmp v3 usm local-engine user NAME authentication-sha authentication-password "..."
        # set snmp v3 usm local-engine user NAME privacy-3des privacy-password "..."
        text = S(re.compile(
            r'^(set\s+snmp\s+.*?(?:authentication-password|privacy-password)\s+)\S+',
            re.M), r'\1<REMOVED>', text, "SNMPv3 auth/priv password (set)")

        # block: authentication-password "..."; / privacy-password "...";
        text = S(re.compile(
            r'^(\s*(?:authentication-password|privacy-password)\s+)\S+\s*;',
            re.M), r'\1<REMOVED>;', text, "SNMPv3 auth/priv password (block)")

        # SSL certificate / key data blocks (curly-brace format only)
        # certificate { ... } blocks containing Base64 data
        text = S(re.compile(
            r'(\bcertificate\s+\{[^}]*\})',
            re.M | re.DOTALL),
            r'certificate { <REMOVED> }', text, "certificate block")

        # set security pki local-certificate CERT-NAME ... (inline cert references)
        text = S(re.compile(
            r'^(set\s+security\s+pki\s+local-certificate\s+\S+\s+certificate\s+)\S+',
            re.M), r'\1<REMOVED>', text, "PKI local-certificate data (set)")

        # Login announcement / banner
        # set system login announcement "..."
        # set system login message "..."
        text = S(re.compile(
            r'^(set\s+system\s+login\s+(?:announcement|message)\s+)\S.*$',
            re.M), r'\1<REMOVED>', text, "login announcement/message (set)")

        # block: announcement "..."; / message "...";
        text = S(re.compile(
            r'^(\s*(?:announcement|message)\s+)\S.*?;$',
            re.M), r'\1<REMOVED>;', text, "login announcement/message (block)")

        # ── Contact / location (sensitive free text) ───────────────────────

        # set snmp contact "..."
        text = S(re.compile(r'^(set\s+snmp\s+contact\s+).+$', re.M),
            r'\1<REMOVED>', text, "SNMP contact (set)")

        # set snmp location "..."
        text = S(re.compile(r'^(set\s+snmp\s+location\s+).+$', re.M),
            r'\1<REMOVED>', text, "SNMP location (set)")

        # block: contact "...";  location "...";
        text = S(re.compile(r'^(\s*contact\s+).+;$', re.M),
            r'\1<REMOVED>;', text, "SNMP contact (block)")

        text = S(re.compile(r'^(\s*location\s+).+;$', re.M),
            r'\1<REMOVED>;', text, "SNMP location (block)")

        return text

    # ──────────────────────────────── pass 2: SNMP ───────────────────────

    def _pass_snmp(self, text: str) -> str:
        N = self._sub_name
        S = self._sub

        # set-format community definitions
        # set snmp community NAME authorization read-only
        # set snmp community NAME authorization read-write
        text = N(re.compile(r'^(set\s+snmp\s+community\s+)(?P<n>\S+)', re.M),
                 "snmp_community", "SNMP community def (set)", text)

        # block: community NAME { ... }
        text = N(re.compile(r'^(\s*community\s+)(?P<n>(?!authorization\b|clients\b|routing-instance\b|view\b|restrict\b)\S+)\s*\{',
                            re.M),
                 "snmp_community", "SNMP community def (block)", text)

        # set snmp trap-group GROUP targets IP  — community ref in trap-group
        # set snmp trap-group GROUP version v2  — group name
        text = N(re.compile(r'^(set\s+snmp\s+trap-group\s+)(?P<n>\S+)', re.M),
                 "snmp_community", "SNMP trap-group name", text)

        # Community ref inside trap-group: set snmp trap-group NAME routing-instance ...
        # (community name already tokenised above; this catches lingering refs)
        # Trap target IPs are handled by the IP pass

        return text

    # ──────────────────────────────── pass 3: AS numbers ─────────────────

    def _pass_as_numbers(self, text: str) -> str:

        def replace_as(m: re.Match) -> str:
            return m.group(1) + self.tokens.get("as_number", m.group(2))

        def replace_rt(m: re.Match) -> str:
            return (m.group(1)
                    + self.tokens.get("as_number", m.group(2))
                    + m.group(3))

        # routing-options autonomous-system N
        text = self._sub(
            re.compile(r'^(set\s+routing-options\s+autonomous-system\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "routing-options autonomous-system (set)")

        text = self._sub(
            re.compile(r'^(\s*autonomous-system\s+)(\d+(?:\.\d+)?)\s*;', re.M),
            lambda m: replace_as(m) + ';', text,
            "autonomous-system (block)")

        # confederation
        text = self._sub(
            re.compile(r'^(set\s+routing-options\s+confederation\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "confederation AS (set)")

        # confederation peers
        def replace_confederation_peers(m: re.Match) -> str:
            prefix = m.group(1)
            peers = re.sub(
                r'\d+(?:\.\d+)?',
                lambda a: self.tokens.get("as_number", a.group(0)),
                m.group(2))
            return prefix + peers
        text = self._sub(
            re.compile(r'^(set\s+routing-options\s+confederation\s+peers\s+)(.+)$', re.M),
            replace_confederation_peers, text, "confederation peers (set)")

        # local-as inside bgp group
        text = self._sub(
            re.compile(r'^(set\s+protocols\s+bgp\s+.*?local-as\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "BGP local-as (set)")

        text = self._sub(
            re.compile(r'^(\s*local-as\s+)(\d+(?:\.\d+)?)\s*;', re.M),
            lambda m: replace_as(m) + ';', text, "BGP local-as (block)")

        # neighbor / group remote-as
        text = self._sub(
            re.compile(r'^(set\s+protocols\s+bgp\s+.*?peer-as\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "BGP peer-as (set)")

        text = self._sub(
            re.compile(r'^(\s*peer-as\s+)(\d+(?:\.\d+)?)\s*;', re.M),
            lambda m: replace_as(m) + ';', text, "BGP peer-as (block)")

        # routing-instance rd N:tag
        text = self._sub(
            re.compile(r'((?:set\s+)?(?:\s*)route-distinguisher\s+)(\d+(?:\.\d+)?)(:\d+)', re.M),
            replace_rt, text, "route-distinguisher AS:tag")

        # route-target (vrf-target / vrf-import / vrf-export)
        text = self._sub(
            re.compile(
                r'((?:set\s+)?(?:.*?\s+)?(?:vrf-target|target)\s+)(\d+(?:\.\d+)?)(:\d+)',
                re.M),
            replace_rt, text, "route-target / vrf-target AS:tag")

        # community values — "target:AS:tag" or bare "AS:tag"
        text = self._sub(
            re.compile(r'(\btarget:)(\d+(?:\.\d+)?)(:\d+)', re.M),
            replace_rt, text, "community target: AS:tag")

        text = self._sub(
            re.compile(r'(\borigin:)(\d+(?:\.\d+)?)(:\d+)', re.M),
            replace_rt, text, "community origin: AS:tag")

        # bare community members: "members [ 65001:100 65001:200 ]"
        text = self._sub(
            re.compile(r'(\bmembers\s+\[\s*)(\d+(?:\.\d+)?)(:\d+)', re.M),
            replace_rt, text, "community members AS:tag")

        # inline community value after "community NAME members"
        text = self._sub(
            re.compile(r'(\s)(\d{4,5})(:\d+)(?=\s|;|\])', re.M),
            replace_rt, text, "community value AS:tag (inline)")

        return text

    # ──────────────────────────────── pass 4: named objects ──────────────

    def _pass_named_objects(self, text: str) -> str:
        N = self._sub_name

        # ── Hostname ──────────────────────────────────────────────────────
        text = N(re.compile(r'^(set\s+system\s+host-name\s+)(?P<n>\S+)', re.M),
                 "hostname", "host-name (set)", text)

        text = N(re.compile(r'^(\s*host-name\s+)(?P<n>\S+)\s*;', re.M),
                 "hostname", "host-name (block)", text)

        # ── Domain name ───────────────────────────────────────────────────
        text = N(re.compile(r'^(set\s+system\s+domain-name\s+)(?P<n>\S+)', re.M),
                 "domain", "domain-name (set)", text)

        text = N(re.compile(r'^(\s*domain-name\s+)(?P<n>\S+)\s*;', re.M),
                 "domain", "domain-name (block)", text)

        text = N(re.compile(r'^(set\s+system\s+domain-search\s+)(?P<n>\S+)', re.M),
                 "domain", "domain-search (set)", text)

        # ── Usernames ─────────────────────────────────────────────────────
        text = N(re.compile(r'^(set\s+system\s+login\s+user\s+)(?P<n>\S+)', re.M),
                 "username", "login user (set)", text)

        # block: "user NAME { ..."
        text = N(re.compile(r'^(\s*user\s+)(?P<n>(?!name\b)\S+)\s*\{', re.M),
                 "username", "login user (block)", text)

        # ── RADIUS / TACACS+ server names ─────────────────────────────────
        # set access profile NAME ...
        text = N(re.compile(r'^(set\s+access\s+profile\s+)(?P<n>\S+)', re.M),
                 "aaa_profile", "access profile name (set)", text)

        # set access radius-server IP ... (IP anonymised by IP pass; label the stanza)
        # set access tacplus-server IP ...
        # Server IPs are handled by the IP pass — no named tokens needed here

        # ── Routing instances (VRF equivalent) ────────────────────────────
        text = N(re.compile(r'^(set\s+routing-instances\s+)(?P<n>\S+)', re.M),
                 "routing_instance", "routing-instance (set)", text)

        text = N(re.compile(r'^(\s*instance\s+)(?P<n>\S+)\s*\{', re.M),
                 "routing_instance", "routing-instance (block)", text)

        # routing-instance refs (export / import policy application)
        text = N(re.compile(
            r'(\binstance\s+)(?P<n>(?!type\b|master\b)\S+)(?=\s*[;{])', re.M),
                 "routing_instance", "routing-instance ref (block)", text)

        # ── Routing policies ──────────────────────────────────────────────
        text = N(re.compile(r'^(set\s+policy-options\s+policy-statement\s+)(?P<n>\S+)', re.M),
                 "routing_policy", "policy-statement def (set)", text)

        text = N(re.compile(r'^(\s*policy-statement\s+)(?P<n>\S+)\s*\{', re.M),
                 "routing_policy", "policy-statement def (block)", text)

        # export / import policy refs
        text = N(re.compile(
            r'^(set\s+(?:routing-instances\s+\S+\s+)?protocols\s+\S+.*?\s+'
            r'(?:export|import)\s+)(?P<n>[A-Za-z]\S*)', re.M),
                 "routing_policy", "routing protocol export/import policy ref (set)", text)

        text = N(re.compile(
            r'^(set\s+routing-options\s+(?:static\s+\S+\s+)?(?:export|import)\s+)(?P<n>[A-Za-z]\S*)', re.M),
                 "routing_policy", "routing-options policy ref (set)", text)

        # generic policy refs in block format: export [ POLICY1 POLICY2 ];
        text = N(re.compile(
            r'(\b(?:export|import)\s+)(?P<n>(?!\[)[A-Za-z]\S*)(?=\s*[;])', re.M),
                 "routing_policy", "export/import policy ref (block)", text)

        # ── Firewall filters (ACL equivalent) ─────────────────────────────
        text = N(re.compile(r'^(set\s+firewall\s+(?:family\s+\S+\s+)?filter\s+)(?P<n>\S+)', re.M),
                 "firewall_filter", "firewall filter def (set)", text)

        text = N(re.compile(r'^(\s*filter\s+)(?P<n>(?!input\b|output\b|input-list\b|output-list\b)\S+)\s*\{', re.M),
                 "firewall_filter", "firewall filter def (block)", text)

        # filter refs: "set interfaces xe-0/0/0 unit 0 family inet filter input FILTER-NAME"
        text = N(re.compile(
            r'^(set\s+interfaces\s+\S+\s+.*?filter\s+(?:input|output)\s+)(?P<n>\S+)', re.M),
                 "firewall_filter", "firewall filter ref (interface, set)", text)

        # block: filter { input FILTER-NAME; }
        text = N(re.compile(
            r'(\bfilter\s+(?:input|output)\s+)(?P<n>\S+)(?=\s*;)', re.M),
                 "firewall_filter", "firewall filter ref (block)", text)

        # ── Prefix lists ──────────────────────────────────────────────────
        text = N(re.compile(r'^(set\s+policy-options\s+prefix-list\s+)(?P<n>\S+)', re.M),
                 "prefix_list", "prefix-list def (set)", text)

        text = N(re.compile(r'^(\s*prefix-list\s+)(?P<n>\S+)\s*\{', re.M),
                 "prefix_list", "prefix-list def (block)", text)

        # ref: "from prefix-list NAME"
        text = N(re.compile(r'(\bprefix-list\s+)(?P<n>\S+)(?=\s*;)', re.M),
                 "prefix_list", "prefix-list ref", text)

        # ── Communities ───────────────────────────────────────────────────
        text = N(re.compile(r'^(set\s+policy-options\s+community\s+)(?P<n>\S+)', re.M),
                 "community", "community def (set)", text)

        text = N(re.compile(r'^(\s*community\s+)(?P<n>(?!delete\b|add\b|set\b)\S+)\s*\{', re.M),
                 "community", "community def (block)", text)

        # community refs: "from community NAME" / "then community add NAME"
        text = N(re.compile(
            r'(\bcommunity\s+(?:add\s+|delete\s+|set\s+)?)(?P<n>[A-Za-z]\S*)(?=\s*;)', re.M),
                 "community", "community ref", text)

        # ── BGP groups ────────────────────────────────────────────────────
        text = N(re.compile(r'^(set\s+protocols\s+bgp\s+group\s+)(?P<n>\S+)', re.M),
                 "bgp_group", "BGP group def (set)", text)

        text = N(re.compile(r'^(\s*group\s+)(?P<n>(?!bgp\b)\S+)\s*\{', re.M),
                 "bgp_group", "BGP group def (block)", text)

        # ── IKE proposals, policies, gateways ────────────────────────────
        text = N(re.compile(r'^(set\s+security\s+ike\s+proposal\s+)(?P<n>\S+)', re.M),
                 "ike_proposal", "IKE proposal def (set)", text)

        text = N(re.compile(r'^(set\s+security\s+ike\s+policy\s+)(?P<n>\S+)', re.M),
                 "ike_policy", "IKE policy def (set)", text)

        text = N(re.compile(r'^(set\s+security\s+ike\s+gateway\s+)(?P<n>\S+)', re.M),
                 "ike_gateway", "IKE gateway def (set)", text)

        # block variants
        text = N(re.compile(r'^(\s*proposal\s+)(?P<n>\S+)\s*\{', re.M),
                 "ike_proposal", "IKE/IPsec proposal def (block)", text)

        text = N(re.compile(r'^(\s*policy\s+)(?P<n>(?!default\b)\S+)\s*\{', re.M),
                 "ike_policy", "IKE policy def (block)", text)

        text = N(re.compile(r'^(\s*gateway\s+)(?P<n>\S+)\s*\{', re.M),
                 "ike_gateway", "IKE gateway def (block)", text)

        # ── IPsec proposals, policies, VPNs ──────────────────────────────
        text = N(re.compile(r'^(set\s+security\s+ipsec\s+proposal\s+)(?P<n>\S+)', re.M),
                 "ipsec_proposal", "IPsec proposal def (set)", text)

        text = N(re.compile(r'^(set\s+security\s+ipsec\s+policy\s+)(?P<n>\S+)', re.M),
                 "ipsec_policy", "IPsec policy def (set)", text)

        text = N(re.compile(r'^(set\s+security\s+ipsec\s+vpn\s+)(?P<n>\S+)', re.M),
                 "ipsec_vpn", "IPsec VPN def (set)", text)

        # ── Security zones ────────────────────────────────────────────────
        text = N(re.compile(r'^(set\s+security\s+zones\s+security-zone\s+)(?P<n>\S+)', re.M),
                 "security_zone", "security-zone def (set)", text)

        text = N(re.compile(r'^(\s*security-zone\s+)(?P<n>\S+)\s*\{', re.M),
                 "security_zone", "security-zone def (block)", text)

        # from-zone / to-zone refs
        text = N(re.compile(r'(\bfrom-zone\s+)(?P<n>\S+)(?=\s)', re.M),
                 "security_zone", "from-zone ref", text)

        text = N(re.compile(r'(\bto-zone\s+)(?P<n>\S+)(?=\s)', re.M),
                 "security_zone", "to-zone ref", text)

        # ── Address books ─────────────────────────────────────────────────
        text = N(re.compile(
            r'^(set\s+security\s+address-book\s+)(?P<n>(?!global\b)\S+)', re.M),
                 "address_book", "address-book def (set)", text)

        # ── NAT rule-sets ─────────────────────────────────────────────────
        text = N(re.compile(
            r'^(set\s+security\s+nat\s+\S+\s+rule-set\s+)(?P<n>\S+)', re.M),
                 "nat_ruleset", "NAT rule-set def (set)", text)

        # ── Class of Service (CoS) ────────────────────────────────────────
        text = N(re.compile(r'^(set\s+class-of-service\s+schedulers\s+)(?P<n>\S+)', re.M),
                 "cos_scheduler", "CoS scheduler def (set)", text)

        text = N(re.compile(r'^(set\s+class-of-service\s+classifiers\s+\S+\s+)(?P<n>\S+)', re.M),
                 "cos_classifier", "CoS classifier def (set)", text)

        text = N(re.compile(r'^(set\s+class-of-service\s+forwarding-classes\s+class\s+)(?P<n>\S+)', re.M),
                 "cos_fwdclass", "CoS forwarding-class def (set)", text)

        text = N(re.compile(r'^(set\s+class-of-service\s+interfaces\s+\S+\s+scheduler-map\s+)(?P<n>\S+)', re.M),
                 "cos_policy", "CoS scheduler-map ref (set)", text)

        text = N(re.compile(r'^(set\s+class-of-service\s+scheduler-maps\s+)(?P<n>\S+)', re.M),
                 "cos_policy", "CoS scheduler-map def (set)", text)

        # ── NTP authentication key IDs ────────────────────────────────────
        # set system ntp authentication-key N type md5 value "..."
        # Key ID is a number; tokenise so it's consistent (value redacted in pass 1)
        text = N(re.compile(r'^(set\s+system\s+ntp\s+authentication-key\s+)(?P<n>\d+)', re.M),
                 "keychain", "NTP authentication-key ID (set)", text)

        # NTP trusted-key ref
        text = N(re.compile(r'^(set\s+system\s+ntp\s+trusted-key\s+)(?P<n>\d+)', re.M),
                 "keychain", "NTP trusted-key ref (set)", text)

        return text

    # ──────────────────────────────── pass 5: descriptions ───────────────

    def _pass_descriptions(self, text: str) -> str:
        def repl(m: re.Match) -> str:
            prefix = m.group(1)
            desc = m.group(2)
            if self.tokens.already_token("description", desc):
                return m.group(0)
            return prefix + self.tokens.get("description", desc)

        # set-format: set ... description "..."  or  set ... description text
        text = self._sub(
            re.compile(r'^(set\s+.*?\s+description\s+)(.+)$', re.M),
            repl, text, "set-format description lines")

        # block-format: description "...";  or  description text;
        text = self._sub(
            re.compile(r'^(\s*description\s+)(.+?)\s*;$', re.M),
            lambda m: repl(m) + ';' if not repl(m).endswith(';') else repl(m),
            text, "block-format description lines")

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
Examples:
  python juniper_sanitise.py -i ./configs/ -o ./clean/ --seed myproject
  python juniper_sanitise.py -i router.conf -o router_clean.conf --dump-map map.json
  python juniper_sanitise.py -i router.conf --dry-run
  python juniper_sanitise.py -i ./configs/ -o ./clean/ --no-ips --no-descriptions
        """
    )
    p.add_argument("-i", "--input",     required=True,
                   help="Input file or directory")
    p.add_argument("-o", "--output",    required=False,
                   help="Output file or directory")
    p.add_argument("--seed",            default="juniper-sanitise",
                   help="Determinism seed — same seed = same tokens every run")
    p.add_argument("--no-ips",          action="store_true",
                   help="Skip IP address anonymisation")
    p.add_argument("--no-descriptions", action="store_true",
                   help="Skip description line anonymisation")
    p.add_argument("--dump-map",        metavar="FILE",
                   help="Write full original→token mapping to a JSON file")
    p.add_argument("--dry-run",         action="store_true",
                   help="Print sanitised output to stdout; do not write files")
    p.add_argument("--extensions",      default=".conf,.txt,.cfg,.log",
                   help="Comma-separated file extensions to process")
    return p.parse_args()


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
    sanitiser = JuniperSanitiser(
        seed=args.seed,
        anonymise_ips=not args.no_ips,
        anonymise_descriptions=not args.no_descriptions,
    )
    exts = tuple(e if e.startswith(".") else f".{e}"
                 for e in args.extensions.split(","))
    inp = Path(args.input)
    out = Path(args.output) if args.output else None

    print("╔══════════════════════════════════════════════════════════╗")
    print("║       Juniper Configuration Sanitiser                   ║")
    print("║  Junos  ·  set-format  ·  curly-brace format            ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Seed            : {args.seed}")
    print(f"  Anonymise IPs   : {'No' if args.no_ips else 'Yes (IPv4-xxxx / IPv6-xxxx tokens)'}")
    print(f"  Anonymise descs : {'No' if args.no_descriptions else 'Yes'}")
    print(f"  Dry run         : {'Yes' if args.dry_run else 'No'}")

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
