# juniper_sanitise.py

A single-file Python script that sanitises Juniper Junos configuration files for
safe sharing — with engineers, vendors, or support teams — without exposing
credentials, internal addressing, or network topology.

Both Junos config formats are supported: **set-format** (one statement per line)
and **curly-brace / hierarchical** format. Real-world configs in either form, or
mixed, are handled correctly. Every credential and named-object rule has dual
patterns covering both formats.

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
  and `trap-group` references carry the same `snmp-xxxx` token; `snmp-server location`
  and `snmp-server contact` are redacted
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
  `ipaddress`, `json`, `pathlib`)

---

## Installation

No installation required. Copy `juniper_sanitise.py` to any convenient location and
run it directly with Python.

```bash
# Optional: make it executable
chmod +x juniper_sanitise.py
```

---

## Usage

```
python juniper_sanitise.py -i INPUT [-o OUTPUT] [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-i`, `--input` | Input file or directory (required) |
| `-o`, `--output` | Output file or directory. Defaults to `<input>_sanitised` alongside the source |
| `--seed TEXT` | Determinism seed. Same seed = same tokens every run. Default: `juniper-sanitise` |
| `--no-ips` | Skip IPv4 address anonymisation |
| `--no-descriptions` | Skip description line anonymisation |
| `--dump-map FILE` | Write the full `original → token` mapping to a JSON file |
| `--dry-run` | Print sanitised output to stdout; do not write any files |
| `--extensions` | Comma-separated file extensions to process. Default: `.conf,.txt,.cfg,.log` |

### Examples

```bash
# Sanitise a directory of configs with a project-specific seed
python juniper_sanitise.py -i ./configs/ -o ./sanitised/ --seed myproject

# Sanitise a single file and save the token mapping for reference
python juniper_sanitise.py -i router.conf -o router_clean.conf --dump-map map.json

# Preview sanitised output without writing any files
python juniper_sanitise.py -i router.conf --dry-run --seed myproject

# Sanitise named objects only — keep real IPs and descriptions
python juniper_sanitise.py -i ./configs/ -o ./sanitised/ --no-ips --no-descriptions
```

---

## How It Works

The script runs five sequential passes over each config file:

1. **Credentials** — pattern-matches credential lines for all set-format and
   block-format Junos variants and replaces values with `<REMOVED>`; also covers
   SSH public keys, SNMP auth/priv passwords, IKE pre-shared keys, NTP key values,
   certificate blocks, and login announcement/message text
2. **SNMP** — tokenises community strings; redacts location and contact strings
3. **AS numbers** — replaces BGP AS numbers and community values with `AS-xxxx`
   tokens, including confederation, local-as, route-distinguisher, and
   vrf-target/target: community values
4. **Named objects** — replaces all named configuration objects with deterministic
   `prefix-xxxx` tokens (see Token Reference below)
5. **Descriptions** — replaces all description text with `desc-xxxx` tokens
6. **IPv4 addresses** — replaces host addresses with `IPv4-xxxx` tokens
7. **IPv6 addresses** — replaces host addresses with `IPv6-xxxx` tokens;
   link-local, loopback, multicast, and unspecified addresses are preserved

Each token is derived from a SHA-256 hash of `seed:category:original_value`, so the
same value always maps to the same token within a run and across runs using the same
seed. A routing-instance name referenced in ten places will carry the same `vrf-xxxx`
token in all ten places in the output.

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
- Loopback range — the entire `127.0.0.0/8` range; note that a routable IP assigned
  to a `lo0` interface (e.g. `10.0.0.1`) is **not** preserved — the script operates
  on address values, not interface names
- Special addresses — `0.0.0.0` and `255.255.255.255` exactly
- IPv6 link-local (`fe80::/10`), loopback (`::1`), multicast (`ff00::/8`), and
  unspecified (`::`) addresses
- Junos syntax keywords — `accept`, `reject`, `discard`, `next`, `permit`, `deny`,
  `inet`, `inet6`, `internal`, `external`, `local`, `default`, etc.
- Config structure — indentation, `{` `}` delimiters, `;` terminators, comment lines
  (`#`), blank lines, and `version` / `last changed` header lines

---

## Output Example

**Before:**
```
set system host-name MX-CORE-LON-01
set system domain-name corp.internal
set system root-authentication encrypted-password "$6$abc123$hashedpassword"
set interfaces xe-0/0/0 unit 0 family inet address 10.100.0.1/30
set interfaces xe-0/0/0 unit 0 family inet6 address 2001:db8:100:1::1/64
set routing-options autonomous-system 65001
set protocols bgp group UPSTREAM-PEERS peer-as 65100
set protocols bgp group UPSTREAM-PEERS neighbor 10.100.0.2 authentication-key "bgpSecretKey1"
set snmp community public-ro authorization read-only
set snmp location "London Core DC - Row 4 Rack 12"
```

**After** (`--seed myproject`):
```
set system host-name host-c170
set system domain-name dom-005b
set system root-authentication encrypted-password <REMOVED>
set interfaces xe-0/0/0 unit 0 family inet address IPv4-3011/30
set interfaces xe-0/0/0 unit 0 family inet6 address IPv6-17b7/64
set routing-options autonomous-system AS-2b08
set protocols bgp group bgrp-6dae peer-as AS-8a26
set protocols bgp group bgrp-6dae neighbor IPv4-ac63 authentication-key <REMOVED>
set snmp community snmp-f7d9 authorization read-only
set snmp location <REMOVED>
```

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
| **`apply-groups` references** | Group names in `apply-groups` and `groups` stanzas are not tokenised. Group stanza contents are sanitised normally but the group name itself is preserved. |
| **`event-options` policy names** | Event policy names under `event-options` are not tokenised. |
| **Dynamic tunnel endpoints** | Tunnel endpoint IPs (`dynamic-tunnels` stanza) are anonymised by the IP pass but the tunnel group name is not tokenised. |
| **Hostnames in description lines** | If a real hostname appears inside a description string, the description token replaces the whole string (good), but the original text is visible in the mapping file. |
| **FQDN-based authentication servers** | RADIUS/TACACS+ servers configured with a hostname rather than an IP address will have the hostname anonymised by the description pass only if it appears in a description context; the server address field itself is not tokenised as a named object. Server IPs are anonymised by the IP pass. |
| **Block-format NAT / address-book names** | NAT rule-set and address-book names are matched in set-format only; block-format equivalents are not currently covered. |

---

## Testing

Two sample configs are included in `test_configs/` covering set-format and
curly-brace format and exercising all sanitisation rules including IPv6.
See `TEST_REFERENCE.md` for the full rule coverage matrix and verification
checklist.

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