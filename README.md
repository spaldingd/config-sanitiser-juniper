# juniper_sanitise.py

A single-file Python script that sanitises Juniper Junos configuration files for
safe sharing — with engineers, vendors, or support teams — without exposing
credentials, internal addressing, or network topology.

Both Junos config formats are supported: **set-format** (one statement per line)
and **curly-brace / hierarchical** format. Real-world configs in either form, or
mixed, are handled correctly.

---

## Features

- **Credentials redacted** — root and user authentication passwords, encrypted
  hashes, plain-text password values, SSH public-key blobs, RADIUS and TACACS+
  server secrets, BGP authentication keys, OSPF MD5 keys, IS-IS authentication
  keys, IKE pre-shared keys (ASCII and hex), SNMPv3 authentication and privacy
  passwords, NTP authentication-key values, login announcement and message text,
  certificate block data
- **IPv4 addresses tokenised** — host addresses replaced with consistent `IPv4-xxxx`
  tokens; subnet masks and CIDR prefixes are left unchanged. Junos uses CIDR
  notation exclusively — there are no wildcard mask fields — so no wildcard-skip
  logic is required
- **IPv6 addresses tokenised** — host addresses replaced with consistent `IPv6-xxxx`
  tokens; link-local (`fe80::/10`), loopback (`::1`), multicast (`ff00::/8`), and
  unspecified (`::`) addresses are preserved; CIDR prefix lengths are left unchanged
- **AS numbers tokenised** — `autonomous-system`, `peer-as`, `local-as`,
  confederation, `route-distinguisher`, `vrf-target` / `target:` community values,
  and `origin:` community values all replaced with consistent `AS-xxxx` tokens
- **SNMP community strings tokenised** — not just redacted, so `community` definitions
  and `trap-group` references carry the same `snmp-xxxx` token; `snmp location` and
  `snmp contact` are redacted
- **Login announcement and message redacted** — `announcement` and `message` fields
  under `system login` replaced with `<REMOVED>` while preserving config structure
- **Named objects tokenised** — hostnames, usernames, domain names, routing-instances
  (VRF equivalent), policy-statements, firewall filters, prefix-lists, community
  terms, BGP groups, IKE proposals/policies/gateways, IPsec proposals/policies/VPNs,
  security zones, address-books, NAT rule-sets, CoS schedulers/classifiers/
  forwarding-classes/scheduler-maps, NTP key IDs, and access profiles
- **Descriptions anonymised** — all `description` text replaced with `desc-xxxx`
  tokens, covering both set-format inline descriptions and block-format
  `description "...";` lines
- **Selectable actions** — every sanitisation action belongs to a three-level
  group → pass → item hierarchy; any level can be targeted with `--skip-*` /
  `--only-*` flags for full granular control
- **Deterministic** — the same seed always produces the same tokens, so outputs are
  reproducible and comparable across runs
- **Traceable** — every substitution is recorded; an optional JSON mapping file maps
  every original value back to its token
- **Cross-platform compatible with cisco_sanitise.py** — the categories `ip_address`,
  `ipv6_address`, `as_number`, `hostname`, `username`, `domain`, `snmp_community`,
  `description`, and `prefix_list` use identical internal keys and token prefixes in
  both scripts, so the same original value maps to the same token when both scripts
  are run with the same seed

---

## Requirements

- Python 3.10 or later
- No third-party dependencies — standard library only (`re`, `hashlib`, `argparse`,
  `ipaddress`, `json`, `pathlib`, `dataclasses`)

---

## Installation

No installation required. Copy `juniper_sanitise.py` to any convenient location and
run it directly with Python.

```bash
chmod +x juniper_sanitise.py   # optional
```

---

## Usage

```
python juniper_sanitise.py -i INPUT [-o OUTPUT] [options]
```

### Core arguments

| Argument | Description |
|----------|-------------|
| `-i`, `--input` | Input file or directory (required unless using `--list-items`) |
| `-o`, `--output` | Output file or directory. Defaults to `<input>_sanitised` alongside the source |
| `--seed TEXT` | Determinism seed. Same seed = same tokens every run. Default: `juniper-sanitise` |
| `--dump-map FILE` | Write the full `original → token` mapping to a JSON file |
| `--dry-run` | Print sanitised output to stdout; do not write any files |
| `--extensions` | Comma-separated file extensions to process. Default: `.conf,.txt,.cfg,.log` |

### Selection flags

All selection flags accept comma-separated lists. Run `--list-items` to see all
valid group, pass, and item IDs.

| Flag | Description |
|------|-------------|
| `--skip-group GROUPS` | Skip entire groups |
| `--only-group GROUPS` | Run only these groups; skip all others |
| `--skip-pass PASSES` | Skip specific passes |
| `--only-pass PASSES` | Run only these passes; skip all others |
| `--skip ITEMS` | Skip specific items |
| `--only ITEMS` | Run only these items; skip all others |
| `--list-items` | Print the full group → pass → item hierarchy and exit |

### Legacy flags (retained for backward compatibility)

| Flag | Equivalent | Description |
|------|-----------|-------------|
| `--no-ips` | `--skip-group addressing` | Skip all IP address anonymisation |
| `--no-descriptions` | `--skip-pass descriptions` | Skip all description anonymisation |

### Examples

```bash
# Sanitise a directory with a project-specific seed
python juniper_sanitise.py -i ./configs/ -o ./sanitised/ --seed myproject

# Sanitise a single file and save the token mapping
python juniper_sanitise.py -i router.conf -o router_clean.conf --dump-map map.json

# Preview sanitised output without writing any files
python juniper_sanitise.py -i router.conf --dry-run --seed myproject

# Show all selectable group, pass, and item IDs
python juniper_sanitise.py --list-items

# Skip all credentials — keep named objects, IPs, and AS numbers
python juniper_sanitise.py -i router.conf --skip-group credentials

# Skip only routing protocol authentication keys
python juniper_sanitise.py -i router.conf --skip-pass routing-auth

# Skip individual items
python juniper_sanitise.py -i router.conf --skip ntp-keys,login-banner

# Run only named-object and addressing passes — skip everything else
python juniper_sanitise.py -i router.conf --only-group named-objects,addressing

# Run only identity and BGP group named objects
python juniper_sanitise.py -i router.conf --only-pass identity,bgp-objects

# Run only specific items
python juniper_sanitise.py -i router.conf --only hostname,ipv4-addresses,bgp-keys
```

---

## Selectable Actions Hierarchy

The full group → pass → item hierarchy. Any level can be targeted with selection
flags. Run `--list-items` for the same output from the command line.

```
GROUP: credentials
  PASS: local-auth
    root-password          root-authentication encrypted/plain-text password
    user-passwords         login user encrypted-password and plain-text-password-value
    ssh-keys               login user ssh-rsa / ssh-dsa / ssh-ecdsa / ssh-ed25519 blobs
  PASS: routing-auth
    bgp-keys               BGP authentication-key (all neighbors and groups)
    ospf-keys              OSPF MD5 key (set-format and block-format)
    isis-keys              IS-IS authentication-key (interface and global)
    ntp-keys               NTP authentication-key value
  PASS: aaa-keys
    radius-secrets         RADIUS server secret (set and block)
    tacacs-secrets         TACACS+ server secret (set and block)
  PASS: vpn-keys
    ike-psk                IKE pre-shared-key ascii-text / hexadecimal
  PASS: snmpv3-keys
    snmpv3-passwords       SNMPv3 authentication-password and privacy-password
  PASS: pki
    certificate-data       certificate { } blocks and inline PKI certificate data
  PASS: informational
    login-banner           system login announcement and message
    snmp-contact           snmp contact free text
    snmp-location          snmp location free text

GROUP: snmp
  PASS: snmp
    snmp-communities       SNMP community name def and trap-group name (tokenised)
    snmp-location          snmp location → <REMOVED>  [shared with credentials/informational]
    snmp-contact           snmp contact  → <REMOVED>  [shared with credentials/informational]

GROUP: bgp-topology
  PASS: as-numbers
    bgp-asn                routing-options autonomous-system, BGP local-as, peer-as
    vrf-rd-rt              route-distinguisher and vrf-target AS:tag values
    community-values       target: / origin: / members AS:tag values (inline)
    bgp-confederation      confederation identifier and peers

GROUP: named-objects
  PASS: identity
    hostname               system host-name
    domain-name            system domain-name and domain-search
    usernames              system login user NAME
  PASS: routing-policy
    policy-statements      policy-options policy-statement (def + export/import refs)
    firewall-filters       firewall filter (def + interface input/output refs)
    prefix-lists           policy-options prefix-list (def + from prefix-list refs)
    communities            policy-options community (def + from/then community refs)
  PASS: bgp-objects
    bgp-groups             protocols bgp group (def only; neighbor IPs via addressing)
  PASS: network-objects
    routing-instances      routing-instances NAME — VRF equivalent (def + refs)
    security-zones         security zones security-zone (def + from-zone/to-zone refs)
    address-books          security address-book NAME
    nat-rulesets           security nat source/dest/static rule-set NAME
  PASS: aaa-objects
    aaa-profiles           access profile NAME
  PASS: vpn-objects
    ike-proposals          security ike proposal NAME
    ike-policies           security ike policy NAME
    ike-gateways           security ike gateway NAME
    ipsec-proposals        security ipsec proposal NAME
    ipsec-policies         security ipsec policy NAME
    ipsec-vpns             security ipsec vpn NAME
  PASS: cos-objects
    cos-schedulers         class-of-service schedulers NAME
    cos-classifiers        class-of-service classifiers dscp NAME
    cos-forwarding-classes class-of-service forwarding-classes class NAME
    cos-scheduler-maps     class-of-service scheduler-maps NAME (def + interface ref)

GROUP: ntp-objects
  PASS: ntp-objects
    ntp-key-ids            system ntp authentication-key N ID

GROUP: addressing
  PASS: ipv4
    ipv4-addresses         all IPv4 host addresses → IPv4-xxxx tokens
  PASS: ipv6
    ipv6-addresses         all IPv6 host addresses → IPv6-xxxx tokens

GROUP: descriptions
  PASS: descriptions
    set-descriptions       set ... description text  (set-format lines)
    block-descriptions     description text;          (block-format lines)
```

### Precedence rules

Flags are applied in this order (lowest to highest priority):

1. Start with all items enabled
2. `--skip-group` — disable all items in named groups
3. `--only-group` — disable all items not in named groups
4. `--skip-pass`  — disable all items in named passes
5. `--only-pass`  — disable all items not in named passes
6. `--skip`       — disable named items individually
7. `--only`       — disable all items not explicitly named

`--skip` and `--only` are mutually exclusive at the same level (e.g. you cannot
combine `--skip foo` and `--only bar`). Combining flags at different levels is valid
and useful: `--skip-group credentials --only-pass routing-auth` expresses
"skip all credentials except routing protocol auth keys".

### Shared item IDs

`snmp-contact` and `snmp-location` appear in both `credentials/informational` and
`snmp`. They share a single item ID, so disabling either path disables both.

---

## How It Works

The script runs seven sequential passes over each config file:

1. **Credentials** — pattern-matches credential lines for all set-format and
   block-format Junos variants and replaces values with `<REMOVED>`
2. **SNMP** — tokenises community strings; location and contact are redacted in pass 1
3. **AS numbers** — replaces BGP AS numbers and community values with `AS-xxxx` tokens
4. **Named objects** — replaces all named configuration objects with deterministic
   `prefix-xxxx` tokens
5. **Descriptions** — replaces all description text with `desc-xxxx` tokens
6. **IPv4 addresses** — replaces host addresses with `IPv4-xxxx` tokens
7. **IPv6 addresses** — replaces host addresses with `IPv6-xxxx` tokens

Each token is derived from a SHA-256 hash of `seed:category:original_value`, so the
same value always maps to the same token within a run and across runs using the same
seed.

---

## Token Reference

| What | Token format | Example |
|------|-------------|---------|
| Hostname | `host-xxxx` | `host-c170` |
| Username | `user-xxxx` | `user-d120` |
| Domain name | `dom-xxxx` | `dom-005b` |
| Routing-instance (VRF) | `vrf-xxxx` | `vrf-caed` |
| Policy-statement | `rpol-xxxx` | `rpol-d768` |
| Firewall filter | `ff-xxxx` | `ff-643a` |
| Prefix-list | `pfx-xxxx` | `pfx-6e7e` |
| Community term | `cmty-xxxx` | `cmty-b8e9` |
| SNMP community string | `snmp-xxxx` | `snmp-f7d9` |
| BGP group | `bgrp-xxxx` | `bgrp-6dae` |
| IKE proposal | `ikep-xxxx` | `ikep-0d10` |
| IKE policy | `ikepol-xxxx` | `ikepol-2ea6` |
| IKE gateway | `ikegw-xxxx` | `ikegw-f2fc` |
| IPsec proposal | `isap-xxxx` | `isap-fa18` |
| IPsec policy | `isapol-xxxx` | `isapol-a9b7` |
| IPsec VPN | `vpn-xxxx` | `vpn-c771` |
| Security zone | `zone-xxxx` | `zone-274d` |
| Address-book | `abook-xxxx` | `abook-f9cf` |
| NAT rule-set | `nat-xxxx` | `nat-f398` |
| CoS scheduler | `sched-xxxx` | `sched-01d8` |
| CoS classifier | `cls-xxxx` | `cls-0b85` |
| CoS forwarding-class | `fwdc-xxxx` | `fwdc-2beb` |
| CoS scheduler-map | `cospol-xxxx` | `cospol-1fc4` |
| Access profile (AAA) | `aaa-xxxx` | `aaa-c6ee` |
| NTP key ID | `kc-xxxx` | `kc-b2e0` |
| Description text | `desc-xxxx` | `desc-2006` |
| AS number | `AS-xxxx` | `AS-2b08` |
| IPv4 host address | `IPv4-xxxx` | `IPv4-b766` |
| IPv6 host address | `IPv6-xxxx` | `IPv6-0d0b` |
| Credentials / sensitive strings | `<REMOVED>` | — |

---

## Cross-Script Token Compatibility with cisco_sanitise.py

When sanitising a mixed-vendor environment with the same seed, the following
categories produce **identical tokens** across both scripts:

| Category | Token prefix | Example |
|----------|-------------|---------|
| `ip_address` | `IPv4` | `10.0.0.1` → `IPv4-93fc` (seed: `myproject`) |
| `ipv6_address` | `IPv6` | same |
| `as_number` | `AS` | `65001` → `AS-d55c` |
| `hostname` | `host` | same |
| `username` | `user` | same |
| `domain` | `dom` | same |
| `snmp_community` | `snmp` | same |
| `prefix_list` | `pfx` | same |
| `description` | `desc` | same |

Categories that are conceptually equivalent across vendors but use different internal
keys (and therefore produce different tokens) include VRF/routing-instance,
route-map/policy-statement, peer-group/BGP-group, ACL/firewall-filter, and
community-list/community. This is intentional — the objects are not structurally
identical across platforms.

---

## What Is Never Modified

- CIDR prefix lengths — `/24`, `/32`, `/64`, `/128`, etc.
- Subnet masks — `255.255.255.0`, `255.255.0.0`, etc.
- Loopback range — the entire `127.0.0.0/8` range
- Special addresses — `0.0.0.0` and `255.255.255.255` exactly
- IPv6 link-local (`fe80::/10`), loopback (`::1`), multicast (`ff00::/8`), and
  unspecified (`::`) addresses
- Junos syntax keywords — `accept`, `reject`, `discard`, `next`, `inet`, `inet6`,
  `internal`, `external`, `local`, `default`, `permit`, `deny`, etc.
- Config structure — `{` `}` delimiters, `;` terminators, indentation,
  `#` comment lines, blank lines, and `version` / `last changed` header lines

---

## Mapping File

When `--dump-map` is used, a JSON file is written containing every substitution made,
grouped by category. Use this to reverse-look up any token in the sanitised output.

```json
{
  "hostname":          { "MX-CORE-LON-01": "host-c170" },
  "as_number":         { "65001": "AS-2b08", "65100": "AS-8a26" },
  "ip_address":        { "10.100.0.1": "IPv4-3011", "10.100.0.2": "IPv4-ac63" },
  "ipv6_address":      { "2001:db8:100:1::1": "IPv6-17b7" },
  "bgp_group":         { "UPSTREAM-PEERS": "bgrp-6dae" },
  "snmp_community":    { "public-ro": "snmp-f7d9" },
  "routing_instance":  { "CUSTOMER-ACME-VRF": "vrf-caed" }
}
```

---

## Platform and Feature Coverage

| Feature area | set-format | block-format |
|-------------|:----------:|:------------:|
| root-authentication password | ✓ | ✓ |
| Login user credentials | ✓ | ✓ |
| SSH public-key blobs | ✓ | ✓ |
| RADIUS server secret | ✓ | ✓ |
| TACACS+ server secret | ✓ | ✓ |
| BGP authentication-key | ✓ | ✓ |
| OSPF MD5 key | ✓ | ✓ |
| IS-IS authentication-key | ✓ | ✓ |
| IKE pre-shared-key | ✓ | ✓ |
| SNMPv3 auth/priv passwords | ✓ | ✓ |
| NTP authentication-key value | ✓ | ✓ |
| Login announcement / message | ✓ | ✓ |
| Certificate block data | ✓ | ✓ |
| SNMP community (def + trap-group) | ✓ | ✓ |
| SNMP location + contact | ✓ | ✓ |
| AS numbers (all contexts) | ✓ | ✓ |
| confederation identifier / peers | ✓ | — |
| BGP local-as | ✓ | ✓ |
| route-distinguisher | ✓ | ✓ |
| vrf-target / community target: | ✓ | ✓ |
| Hostname / domain / usernames | ✓ | ✓ |
| Routing-instances (VRF) | ✓ | ✓ |
| Policy-statements (import/export) | ✓ | ✓ |
| Firewall filters (def + interface ref) | ✓ | ✓ |
| Prefix-lists (def + match ref) | ✓ | ✓ |
| Community terms (def + match/set ref) | ✓ | ✓ |
| BGP groups | ✓ | ✓ |
| IKE proposals / policies / gateways | ✓ | ✓ |
| IPsec proposals / policies / VPNs | ✓ | ✓ |
| Security zones (def + from/to ref) | ✓ | ✓ |
| Address-books | ✓ | — |
| NAT rule-sets | ✓ | — |
| CoS schedulers / classifiers | ✓ | ✓ |
| CoS forwarding-classes | ✓ | ✓ |
| CoS scheduler-maps | ✓ | ✓ |
| Access profiles (AAA) | ✓ | ✓ |
| NTP key IDs (trusted-key refs) | ✓ | — |
| Descriptions (all positions) | ✓ | ✓ |
| IPv4 host addresses | ✓ | ✓ |
| IPv6 host addresses | ✓ | ✓ |

---

## Known Limitations

| Item | Detail |
|------|--------|
| **`apply-groups` references** | Group names in `apply-groups` and `groups` stanzas are not tokenised |
| **`event-options` policy names** | Event policy names under `event-options` are not tokenised |
| **Dynamic tunnel group names** | `dynamic-tunnels` group names are not tokenised; endpoint IPs are anonymised |
| **Block-format NAT / address-book names** | NAT rule-set and address-book names are matched in set-format only |
| **FQDN-based authentication servers** | RADIUS/TACACS+ servers configured with a hostname rather than an IP are not tokenised |
| **Hostnames in description lines** | If a real hostname appears inside a description string, the description token replaces the whole string, but the original text is visible in the mapping file |

---

## Testing

Two sample configs are included in `test_configs/` covering set-format and
curly-brace format and exercising all sanitisation rules. See `TEST_REFERENCE.md`
for the full rule coverage matrix and verification checklist.

```bash
python juniper_sanitise.py \
  -i ./test_configs/ \
  -o ./test_configs_sanitised/ \
  --seed test-run-2024 \
  --dump-map test_mapping.json
```

---

## License

MIT