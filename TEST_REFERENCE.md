# Juniper Configuration Sanitiser — Test Reference

`juniper_sanitise.py` is a single-file Python script supporting Junos set-format
and curly-brace (hierarchical) configuration syntax. Two sample configs exercise
its sanitisation rules across both formats, including full IPv6 coverage.

---

## Test Files

| File | Format | Device type | Role |
|------|--------|-------------|------|
| `sample_junos_set.conf` | set-format | MX Series | Core/edge router — full feature set |
| `sample_junos_block.conf` | curly-brace | EX/QFX Series | Distribution switch — block syntax |

---

## Token Scheme

Every anonymised value is replaced with a deterministic `prefix-xxxx` token derived
from a SHA-256 hash of `seed:category:original_value`. The same original value always
produces the same token for a given seed, making substitutions traceable via the
mapping file.

| Category | Token prefix | Example |
|----------|-------------|---------|
| Hostname | `host` | `host-c170` |
| Username | `user` | `user-d120` |
| Domain name | `dom` | `dom-005b` |
| Routing-instance (VRF) | `vrf` | `vrf-caed` |
| Policy-statement | `rpol` | `rpol-d768` |
| Firewall filter | `ff` | `ff-643a` |
| Prefix-list | `pfx` | `pfx-6e7e` |
| Community term | `cmty` | `cmty-b8e9` |
| SNMP community string | `snmp` | `snmp-f7d9` |
| BGP group | `bgrp` | `bgrp-6dae` |
| IKE proposal | `ikep` | `ikep-0d10` |
| IKE policy | `ikepol` | `ikepol-2ea6` |
| IKE gateway | `ikegw` | `ikegw-f2fc` |
| IPsec proposal | `isap` | `isap-fa18` |
| IPsec policy | `isapol` | `isapol-a9b7` |
| IPsec VPN | `vpn` | `vpn-c771` |
| Security zone | `zone` | `zone-274d` |
| Address-book | `abook` | `abook-f9cf` |
| NAT rule-set | `nat` | `nat-f398` |
| CoS scheduler | `sched` | `sched-01d8` |
| CoS classifier | `cls` | `cls-0b85` |
| CoS forwarding-class | `fwdc` | `fwdc-2beb` |
| CoS scheduler-map | `cospol` | `cospol-1fc4` |
| Access profile (AAA) | `aaa` | `aaa-c6ee` |
| NTP key ID | `kc` | `kc-b2e0` |
| Description text | `desc` | `desc-2006` |
| AS number | `AS` | `AS-2b08` |
| IPv4 host address | `IPv4` | `IPv4-b766` |
| IPv6 host address | `IPv6` | `IPv6-0d0b` |

Credentials and sensitive free-text values are replaced with the literal `<REMOVED>`
rather than a token, as they carry no structural meaning that needs to remain
traceable.

---

## What Is Preserved

The following values are never anonymised regardless of context:

- **CIDR prefix lengths** — `/24`, `/32`, `/64`, `/128`, etc.
- **Subnet masks** — any quad matching standard mask octets
- **Loopback range** — the entire `127.0.0.0/8` range (`addr.is_loopback`); note
  that routable IPs on `lo0` interfaces (e.g. `10.0.0.1/32`) are anonymised — the
  script operates on address values only, not interface names
- **Special addresses** — `0.0.0.0` and `255.255.255.255` exactly
- **IPv6 link-local** — `fe80::/10` range, e.g. `FE80::1`
- **IPv6 loopback** — `::1`
- **IPv6 unspecified** — `::`
- **IPv6 multicast** — `ff00::/8`, e.g. `ff02::5`
- **No wildcard-skip logic** — Junos uses CIDR notation exclusively; there are no
  wildcard address fields (unlike Cisco IOS ACLs), so all IPv4 addresses on a line
  are individually evaluated
- **Junos syntax keywords** — `accept`, `reject`, `discard`, `next`, `inet`, `inet6`,
  `internal`, `external`, `local`, `default`, `permit`, `deny`, etc.
- **Config structure** — `{` `}` delimiters, `;` terminators, indentation,
  `#` comment lines, blank lines, `version` and `last changed` header lines

---

## Sanitisation Passes (in execution order)

The script runs seven sequential passes. Each pass operates on the output of the
previous one. Set-format and block-format patterns are applied in the same pass.

---

### Pass 1 — Credentials

All credential values and sensitive literal strings are replaced with `<REMOVED>`.

#### Authentication credentials

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| root-authentication password | `set system root-authentication encrypted-password "..."` | `encrypted-password "$...";` | ✓ | ✓ |
| root plain-text password | `set system root-authentication plain-text-password-value "..."` | `plain-text-password-value "...";` | ✓ | ✓ |
| Login user encrypted password | `set system login user NAME authentication encrypted-password "..."` | `encrypted-password "$...";` (inside authentication block) | ✓ | ✓ |
| Login user SSH public key | `set system login user NAME authentication ssh-rsa "..."` | `ssh-rsa "...";` / `ssh-dsa "...";` / `ssh-ecdsa "...";` / `ssh-ed25519 "...";` | ✓ | ✓ |
| RADIUS server secret | `set access radius-server IP [port N] secret "..."` | `secret "...";` (inside radius-server block) | ✓ | ✓ |
| TACACS+ server secret | `set access tacplus-server IP [port N] secret "..."` | `secret "...";` (inside tacplus-server block) | ✓ | ✓ |
| BGP authentication-key | `set protocols bgp ... authentication-key "..."` | `authentication-key "...";` | ✓ | ✓ |
| OSPF MD5 key | `set protocols ospf area X interface IF authentication md5 N key "..."` | `key "...";` (inside md5 N block) | ✓ | ✓ |
| IS-IS authentication-key | `set protocols isis interface IF level N authentication-key "..."` | `authentication-key "...";` | ✓ | ✓ |
| IS-IS global authentication-key | `set protocols isis authentication-key "..."` | — | ✓ | — |
| IKE pre-shared-key (ASCII) | `set security ike policy NAME pre-shared-key ascii-text "..."` | `ascii-text "...";` | ✓ | ✓ |
| IKE pre-shared-key (hex) | `set security ike policy NAME pre-shared-key hexadecimal "..."` | `hexadecimal "...";` | ✓ | ✓ |
| SNMPv3 auth password | `set snmp v3 usm ... authentication-sha authentication-password "..."` | `authentication-password "...";` | ✓ | ✓ |
| SNMPv3 priv password | `set snmp v3 usm ... privacy-3des privacy-password "..."` | `privacy-password "...";` | ✓ | ✓ |
| NTP authentication-key value | `set system ntp authentication-key N type md5 value "..."` | `value "...";` (inside authentication-key block) | ✓ | ✓ |
| Certificate block | `set security pki local-certificate NAME certificate "..."` | `certificate { ... }` (multiline) | ✓ | ✓ |

#### Login announcement / banner

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| Login announcement | `set system login announcement "..."` | `announcement "...";` | ✓ | ✓ |
| Login message | `set system login message "..."` | `message "...";` | ✓ | ✓ |

#### SNMP sensitive fields (redacted, not tokenised)

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| SNMP contact | `set snmp contact "..."` | `contact "...";` | ✓ | ✓ |
| SNMP location | `set snmp location "..."` | `location "...";` | ✓ | ✓ |

---

### Pass 2 — SNMP

SNMP community strings are **tokenised** (not redacted) so that the same community
name appearing in a `community` definition and a `trap-group` reference maps to the
same `snmp-xxxx` token, preserving traceability.

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| SNMP community def | `set snmp community NAME authorization ...` | `community NAME { ... }` | ✓ | ✓ |
| SNMP trap-group name | `set snmp trap-group NAME ...` | — | ✓ | — |

Trap target IPs are handled by the IPv4 pass.

---

### Pass 3 — AS Numbers

BGP AS numbers and community values are tokenised to `AS-xxxx` tokens. The same AS
number maps to the same token across all contexts.

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| autonomous-system | `set routing-options autonomous-system N` | `autonomous-system N;` | ✓ | ✓ |
| confederation identifier | `set routing-options confederation N` | — | ✓ | — |
| confederation peers | `set routing-options confederation peers [N N ...]` (each AS tokenised) | — | ✓ | — |
| BGP local-as | `set protocols bgp group NAME local-as N` | `local-as N;` | ✓ | ✓ |
| BGP peer-as | `set protocols bgp group NAME peer-as N` | `peer-as N;` | ✓ | ✓ |
| route-distinguisher | `set routing-instances NAME route-distinguisher N:tag` | `route-distinguisher N:tag;` | ✓ | ✓ |
| vrf-target | `set routing-instances NAME vrf-target target:N:tag` | `vrf-target target:N:tag;` | ✓ | ✓ |
| community target: value | `target:N:tag` inline in policy or community members | same | ✓ | ✓ |
| community origin: value | `origin:N:tag` inline in community members | same | ✓ | ✓ |
| community members list | `members [ N:tag N:tag ]` | same | ✓ | ✓ |
| community value (inline) | bare `N:tag` (5-digit AS) inline in config lines | same | ✓ | ✓ |

---

### Pass 4 — Named Objects

All named configuration objects are replaced with deterministic tokens. Definitions
and all references share the same token category so names stay consistent throughout
the sanitised output.

#### System identity

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| hostname | `set system host-name NAME` | `host-name NAME;` | ✓ | ✓ |
| domain-name | `set system domain-name NAME` | `domain-name NAME;` | ✓ | ✓ |
| domain-search | `set system domain-search NAME` | — | ✓ | — |

#### Usernames

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| login user | `set system login user NAME ...` | `user NAME { ... }` | ✓ | ✓ |

The username field is anonymised to `user-xxxx`. The credential value is separately
removed by Pass 1.

#### AAA

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| access profile | `set access profile NAME ...` | — | ✓ | — |

RADIUS and TACACS+ server addresses are anonymised by the IP pass. Server secrets are
removed in Pass 1.

#### Routing instances (VRF equivalent)

Anonymised to `vrf-xxxx`. Both definition and reference syntaxes are covered:

| Rule | Syntax | set | block |
|------|--------|:---:|:-----:|
| `set routing-instances NAME ...` | set-format definition | ✓ | — |
| `instance NAME { ... }` | block-format definition | — | ✓ |
| `instance NAME` inline | block-format reference | — | ✓ |

#### Routing policies

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| policy-statement def | `set policy-options policy-statement NAME ...` | `policy-statement NAME { ... }` | ✓ | ✓ |
| export/import ref (protocol) | `set protocols bgp ... export NAME` | `export NAME;` / `import NAME;` | ✓ | ✓ |
| export/import ref (routing-options) | `set routing-options ... export NAME` | — | ✓ | — |

#### Firewall filters

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| filter def | `set firewall family inet filter NAME ...` | `filter NAME { ... }` | ✓ | ✓ |
| filter input ref (interface) | `set interfaces IF ... filter input NAME` | `filter { input NAME; }` | ✓ | ✓ |
| filter output ref (interface) | `set interfaces IF ... filter output NAME` | `filter { output NAME; }` | ✓ | ✓ |

#### Prefix lists

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| prefix-list def | `set policy-options prefix-list NAME ...` | `prefix-list NAME { ... }` | ✓ | ✓ |
| prefix-list ref | `prefix-list NAME;` (in from clause) | same | ✓ | ✓ |

#### Community terms

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| community def | `set policy-options community NAME members ...` | `community NAME { ... }` | ✓ | ✓ |
| community ref (match) | `from community NAME` | same | ✓ | ✓ |
| community ref (action) | `then community add/delete/set NAME` | same | ✓ | ✓ |

Note: The AS:tag *values* inside community members are tokenised by Pass 3
(`target:AS-xxxx:tag`). The community *name* is tokenised by Pass 4 (`cmty-xxxx`).

#### BGP groups

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| BGP group def | `set protocols bgp group NAME ...` | `group NAME { ... }` | ✓ | ✓ |

BGP neighbor IPs are handled by the IP pass. BGP authentication keys are removed in Pass 1.

#### IKE / IPsec (SRX)

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| IKE proposal def | `set security ike proposal NAME ...` | `proposal NAME { ... }` | ✓ | ✓ |
| IKE policy def | `set security ike policy NAME ...` | `policy NAME { ... }` | ✓ | ✓ |
| IKE gateway def | `set security ike gateway NAME ...` | `gateway NAME { ... }` | ✓ | ✓ |
| IPsec proposal def | `set security ipsec proposal NAME ...` | `proposal NAME { ... }` | ✓ | ✓ |
| IPsec policy def | `set security ipsec policy NAME ...` | — | ✓ | — |
| IPsec VPN def | `set security ipsec vpn NAME ...` | — | ✓ | — |

IKE gateway endpoint IPs are handled by the IP pass. Pre-shared keys are removed in Pass 1.

#### Security zones (SRX)

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| security-zone def | `set security zones security-zone NAME ...` | `security-zone NAME { ... }` | ✓ | ✓ |
| from-zone ref | `from-zone NAME` (in security policy) | same | ✓ | ✓ |
| to-zone ref | `to-zone NAME` | same | ✓ | ✓ |

#### Address books and NAT rule-sets (SRX)

| Rule | Set-format syntax | Block-format | set | block |
|------|-------------------|-------------|:---:|:-----:|
| address-book def | `set security address-book NAME ...` | — | ✓ | — |
| NAT rule-set def | `set security nat source rule-set NAME ...` | — | ✓ | — |

#### Class of Service

| Rule | Set-format syntax | Block-format syntax | set | block |
|------|-------------------|---------------------|:---:|:-----:|
| scheduler def | `set class-of-service schedulers NAME ...` | `NAME { ... }` (inside schedulers) | ✓ | ✓ |
| classifier def | `set class-of-service classifiers dscp NAME ...` | — | ✓ | — |
| forwarding-class def | `set class-of-service forwarding-classes class NAME ...` | `class NAME ...;` | ✓ | ✓ |
| scheduler-map def | `set class-of-service scheduler-maps NAME ...` | `NAME { ... }` (inside scheduler-maps) | ✓ | ✓ |
| scheduler-map ref | `set class-of-service interfaces IF scheduler-map NAME` | `scheduler-map NAME;` | ✓ | ✓ |

#### NTP key IDs

| Rule | Set-format syntax | Block-format | set | block |
|------|-------------------|-------------|:---:|:-----:|
| authentication-key ID | `set system ntp authentication-key N ...` | — | ✓ | — |
| trusted-key ref | `set system ntp trusted-key N` | — | ✓ | — |

NTP key values are removed in Pass 1.

---

### Pass 5 — Descriptions

Description text is anonymised to `desc-xxxx` tokens.

| Rule | Syntax matched | Notes |
|------|---------------|-------|
| Set-format description | `set ... description "text"` or `set ... description text` | Matches any set-format line with a trailing description |
| Block-format description | `description "text";` (any indentation) | Interface, routing-instance, BGP group, policy descriptions |

The same description text maps to the same `desc-xxxx` token wherever it appears.

---

### Pass 6 — IPv4 Addresses

IPv4 host addresses are anonymised after all named-object and credential passes.

- **Token format** — `IPv4-xxxx` (4 hex chars), e.g. `IPv4-b766`
- **Deterministic** — same source IP → same `IPv4-xxxx` token for the same seed
- **Loopbacks preserved** — `127.0.0.0/8` range only; routable IPs on `lo0`
  interfaces are anonymised
- **Special addresses preserved** — `0.0.0.0` and `255.255.255.255` exactly
- **Subnet masks preserved** — standard mask octets (255/254/252/248/240/224/192/128/0)
- **No wildcard-skip logic** — Junos uses CIDR notation exclusively; all IPv4
  addresses on any line are individually evaluated

---

### Pass 7 — IPv6 Addresses

IPv6 host addresses are anonymised last, after the IPv4 pass.

- **Token format** — `IPv6-xxxx` (4 hex chars), e.g. `IPv6-0d0b`
- **Deterministic** — same source address → same `IPv6-xxxx` token for the same seed
- **Detection** — a nine-alternation regex covering all RFC 5952 compressed forms,
  bounded by negative lookbehind/lookahead to exclude prefix lengths (`/64` etc.).
  Each candidate is validated with `ipaddress.ip_address()` to eliminate false positives
- **Preserved addresses:**
  - `::1` — loopback
  - `::` — unspecified
  - `fe80::/10` — link-local, e.g. `FE80::1`
  - `ff00::/8` — multicast, e.g. `ff02::5`
- **No skip-span logic needed** — CIDR notation is used throughout; the `/` in CIDR
  notation is excluded by the regex lookbehind

---

## Per-File Coverage Summary

| Rule group | `sample_junos_set` | `sample_junos_block` |
|-----------|:---:|:---:|
| root-authentication password | ✓ | ✓ |
| login user encrypted password | ✓ | ✓ |
| login user SSH public key | ✓ | ✓ |
| RADIUS server secret | ✓ | ✓ |
| TACACS+ server secret | ✓ | — |
| BGP authentication-key | ✓ | ✓ |
| OSPF MD5 key | ✓ | ✓ |
| IS-IS authentication-key | ✓ | ✓ |
| IKE pre-shared-key | ✓ | — |
| SNMPv3 auth / priv password | ✓ | ✓ |
| NTP authentication-key value | ✓ | ✓ |
| Login announcement / message | ✓ | ✓ |
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
| IKE proposals / policies / gateways | ✓ | — |
| IPsec proposals / policies / VPNs | ✓ | — |
| Security zones (def + from/to ref) | ✓ | — |
| Address-books | ✓ | — |
| NAT rule-sets | ✓ | — |
| CoS schedulers / forwarding-classes | ✓ | ✓ |
| CoS classifiers | ✓ | — |
| CoS scheduler-maps (def + ref) | ✓ | ✓ |
| Access profiles (AAA) | ✓ | ✓ |
| NTP key IDs (trusted-key refs) | ✓ | — |
| Descriptions (set + block format) | ✓ | ✓ |
| IPv4 host addresses | ✓ | ✓ |
| IPv6 host addresses | ✓ | ✓ |
| IPv6 link-local / loopback / multicast preserved | ✓ | ✓ |

---

## How to Run

```bash
# Sanitise both test configs with a reproducible seed
python juniper_sanitise.py \
  -i ./test_configs/ \
  -o ./test_configs_sanitised/ \
  --seed test-run-2024 \
  --dump-map test_mapping.json

# Dry-run preview of a single file (stdout only, no files written)
python juniper_sanitise.py \
  -i ./test_configs/sample_junos_set.conf \
  --dry-run \
  --seed test-run-2024

# Skip IP anonymisation (useful for isolating named-object changes)
python juniper_sanitise.py \
  -i ./test_configs/ \
  -o ./test_configs_sanitised/ \
  --seed test-run-2024 \
  --no-ips
```

---

## What to Verify After Running

**Sanitisation banner present**
The first line of every output file should be `!` followed by a row of `=` signs.
The banner block should contain:
- `! SANITISED CONFIGURATION`
- A bullet list of actions taken (credentials, named objects, and optionally IPs
  and descriptions depending on flags used)
- `! Sanitised   :` with a UTC timestamp
- `! Seed hash   :` with a 16-character hex fingerprint of the seed (not the seed
  itself — the fingerprint is a one-way SHA-256 commitment that allows two files
  to be verified as sharing the same seed without exposing it)
- `! Script      :` with the repository URL

To verify two sanitised files share the same seed, compare their `Seed hash` values.
To update the repository URL, set `REPO_URL` near the top of the script.

The banner uses `!` as the comment character.

**Credentials removed**
Search the output for `$6$`, `$1$`, `ssh-rsa`, `secret`, `authentication-key`,
`pre-shared-key`, `authentication-password`, `privacy-password`, `value`.
None should retain a real value — all should show `<REMOVED>`.

**RADIUS / TACACS+ secrets removed**
Lines of the form `set access radius-server IP port N secret "..."` should show
`<REMOVED>` for the secret value. The server IP will be anonymised by the IP pass.
Also check block-format `secret "...";` lines inside server stanzas.

**BGP authentication keys removed**
`authentication-key` lines should show `<REMOVED>` in both set-format and
block-format output.

**OSPF / IS-IS keys removed**
`key "...";` lines inside OSPF md5 stanzas and `authentication-key` lines in IS-IS
stanzas should show `<REMOVED>`.

**IKE pre-shared keys removed**
`ascii-text` and `hexadecimal` lines inside `pre-shared-key` stanzas should show
`<REMOVED>`.

**NTP key values removed, key IDs tokenised**
`value "...";` lines inside `authentication-key` stanzas should show `<REMOVED>`.
The key ID number on `authentication-key N` and `trusted-key N` lines should be
replaced with a `kc-xxxx` token, and the same token should appear on both lines for
the same original ID.

**Login announcement / message removed**
`announcement` and `message` fields should show `<REMOVED>`.

**SNMP contact and location removed**
`snmp-server contact` and `snmp-server location` equivalents should show `<REMOVED>`.

**SNMP community consistent**
The same community string should produce the same `snmp-xxxx` token on both the
`community NAME` definition line and any `trap-group` reference.

**AS numbers tokenised**
`65001` should map to the same `AS-xxxx` token in `autonomous-system`,
`peer-as`, `local-as`, `route-distinguisher`, `vrf-target`, and `target:` community
values. Verify confederation peer AS numbers are each individually tokenised on the
`confederation peers [...]` line.

**route-distinguisher and vrf-target consistent**
For a routing-instance with both `route-distinguisher 65001:100` and
`vrf-target target:65001:100`, the AS portion `65001` should produce the same
`AS-xxxx` token in both lines.

**IPv4 addresses tokenised**
All non-loopback host addresses replaced with `IPv4-xxxx` tokens. CIDR prefix
lengths (`/30`, `/32`, etc.) must be untouched. Verify RADIUS/TACACS+ server
addresses are tokenised (the credential pass runs first and removes the secret,
then the IP pass tokenises the address in the same line).

**IPv6 addresses tokenised**
All routable IPv6 addresses replaced with `IPv6-xxxx` tokens. Verify:
- `2001:db8:...` addresses become `IPv6-xxxx` tokens
- `FE80::x` link-local addresses are preserved unchanged
- `::1` loopback and `::` unspecified addresses are preserved unchanged
- `ff02::x` multicast addresses are preserved unchanged
- CIDR prefix lengths (`/64`, `/128`) are untouched
- The `[ipv6_address]` section appears in the mapping file

**Named objects consistent**
A named object (e.g. `UPSTREAM-PEERS`) should carry the same `bgrp-xxxx` token on
its `group UPSTREAM-PEERS` definition line and every reference in the same config
and across both test configs (same seed).

**Policy-statement references consistent**
A policy-statement name (e.g. `EXPORT-TO-ACME`) should carry the same `rpol-xxxx`
token on its `policy-statement` definition line, `export` reference lines, and
`import` reference lines.

**Firewall filter references consistent**
A filter name (e.g. `MGMT-ACCESS`) should carry the same `ff-xxxx` token on its
`filter MGMT-ACCESS` definition and the `filter input MGMT-ACCESS` interface
reference.

**Prefix-list references consistent**
A prefix-list name (e.g. `MGMT-PREFIXES`) should carry the same `pfx-xxxx` token
on its `prefix-list` definition and any `from prefix-list` match reference in a
policy-statement term.

**Community term names consistent**
A community term (e.g. `CUSTOMER-ACME-COMMUNITY`) should carry the same `cmty-xxxx`
token on its `community` definition and any `from community` or `then community add`
reference.

**Descriptions tokenised**
All `description "..."` text should be replaced with `desc-xxxx` tokens in both
set-format and block-format output.

**Config structure intact**
The sanitised file should remain syntactically valid — correct indentation, `{` `}`
delimiters, `;` terminators, and block structure all preserved. Verify that
set-format lines still read as single complete statements.

**Mapping file**
`test_mapping.json` lists every `original → token` substitution grouped by category.
Use this to trace any token back to its source value.

---

## Known Limitations

| Item | Detail | Test config |
|------|--------|-------------|
| **`apply-groups` references** | Group names in `apply-groups` and `groups` stanzas are not tokenised | — |
| **`event-options` policy names** | Event policy names are not tokenised | — |
| **Dynamic tunnel group names** | `dynamic-tunnels` group names are not tokenised; endpoint IPs are anonymised | — |
| **Block-format NAT / address-book names** | Only matched in set-format; block-format stanza names not currently covered | — |
| **FQDN-based server addresses** | A RADIUS/TACACS+ server configured with a hostname instead of an IP is not tokenised as a named object | — |
| **Hostnames in descriptions** | If a real hostname appears inside a description string, the description token replaces the whole string (good), but the original is visible in the mapping file | — |

---

## Rules Defined but Not Exercised by Current Test Configs

| Rule | Syntax | Notes |
|------|--------|-------|
| plain-text-password-value | `plain-text-password-value "...";` | All test configs use `encrypted-password` |
| IKE hexadecimal pre-shared-key | `hexadecimal "...";` | Test uses ASCII text only |
| Block-format IPsec policy / VPN | `ipsec policy NAME { ... }` | SRX rules only tested in set-format |
| Block-format NAT rule-set | `rule-set NAME { ... }` | Currently set-format only |
| community origin: value | `origin:AS:tag` | Test uses `target:` only |
| confederation (block) | `confederation N;` | Only exercised in set-format |