# Juniper Configuration Sanitiser — Test Reference

`juniper_sanitise.py` is a single-file Python script supporting Junos set-format
and curly-brace (hierarchical) configuration syntax. Two sample configs exercise
its sanitisation rules across both formats, including full IPv6 coverage and all
selectable-action combinations.

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

Credentials and sensitive free-text values are replaced with the literal `<REMOVED>`.

---

## What Is Preserved

- **CIDR prefix lengths** — `/24`, `/32`, `/64`, `/128`, etc.
- **Subnet masks** — any quad matching standard mask octets
- **Loopback range** — the entire `127.0.0.0/8` range
- **Special addresses** — `0.0.0.0` and `255.255.255.255` exactly
- **IPv6 link-local** — `fe80::/10`, e.g. `FE80::1`
- **IPv6 loopback** — `::1`
- **IPv6 unspecified** — `::`
- **IPv6 multicast** — `ff00::/8`, e.g. `ff02::5`
- **No wildcard-skip logic** — Junos uses CIDR notation exclusively
- **Junos syntax keywords** — `accept`, `reject`, `discard`, `next`, `inet`,
  `inet6`, `internal`, `external`, `local`, `default`, `permit`, `deny`, etc.
- **Config structure** — `{` `}` delimiters, `;` terminators, indentation,
  `#` comment lines, blank lines

---

## Sanitisation Passes (in execution order)

The script runs seven sequential passes. Within each pass, every logical block of
rules is guarded by a `cfg.enabled("item-id")` check — items, passes, and groups
not selected by the CLI flags are skipped entirely.

---

### Pass 1 — Credentials

| Item ID | Rule | Set-format syntax | Block-format syntax | set | block |
|---------|------|-------------------|---------------------|:---:|:-----:|
| `root-password` | root-authentication password | `set system root-authentication encrypted-password "..."` | `encrypted-password "$...";` | ✓ | ✓ |
| `root-password` | root plain-text password | `set system root-authentication plain-text-password-value "..."` | `plain-text-password-value "...";` | ✓ | ✓ |
| `user-passwords` | login user encrypted password | `set system login user NAME authentication encrypted-password "..."` | `encrypted-password "$...";` (inside authentication) | ✓ | ✓ |
| `ssh-keys` | login user SSH public key | `set system login user NAME authentication ssh-rsa "..."` | `ssh-rsa "...";` / `ssh-dsa "...";` etc. | ✓ | ✓ |
| `radius-secrets` | RADIUS server secret | `set access radius-server IP [port N] secret "..."` | `secret "...";` (inside radius-server block) | ✓ | ✓ |
| `tacacs-secrets` | TACACS+ server secret | `set access tacplus-server IP [port N] secret "..."` | *(no block pattern)* | ✓ | — |
| `bgp-keys` | BGP authentication-key | `set protocols bgp ... authentication-key "..."` | `authentication-key "...";` | ✓ | ✓ |
| `ospf-keys` | OSPF MD5 key | `set protocols ospf area X interface IF authentication md5 N key "..."` | `key "...";` (inside md5 N block) | ✓ | ✓ |
| `isis-keys` | IS-IS authentication-key | `set protocols isis interface IF level N authentication-key "..."` | *(matched by bgp-keys block pattern)* | ✓ | — |
| `ntp-keys` | NTP authentication-key value | `set system ntp authentication-key N type md5 value "..."` | `value "...";` | ✓ | ✓ |
| `ike-psk` | IKE pre-shared-key (ASCII) | `set security ike policy NAME pre-shared-key ascii-text "..."` | `ascii-text "...";` | ✓ | ✓ |
| `ike-psk` | IKE pre-shared-key (hex) | `set security ike policy NAME pre-shared-key hexadecimal "..."` | `hexadecimal "...";` | ✓ | ✓ |
| `snmpv3-passwords` | SNMPv3 auth password | `set snmp v3 usm ... authentication-sha authentication-password "..."` | `authentication-password "...";` | ✓ | ✓ |
| `snmpv3-passwords` | SNMPv3 priv password | `set snmp v3 usm ... privacy-3des privacy-password "..."` | `privacy-password "...";` | ✓ | ✓ |
| `certificate-data` | certificate block | `set security pki local-certificate NAME certificate "..."` | `certificate { ... }` (multiline) | ✓ | ✓ |
| `login-banner` | login announcement | `set system login announcement "..."` | `announcement "...";` | ✓ | ✓ |
| `login-banner` | login message | `set system login message "..."` | `message "...";` | ✓ | ✓ |
| `snmp-contact` | SNMP contact | `set snmp contact "..."` | `contact "...";` | ✓ | ✓ |
| `snmp-location` | SNMP location | `set snmp location "..."` | `location "...";` | ✓ | ✓ |

---

### Pass 2 — SNMP

| Item ID | Rule | Set-format syntax | Block-format syntax | set | block |
|---------|------|-------------------|---------------------|:---:|:-----:|
| `snmp-communities` | SNMP community def | `set snmp community NAME authorization ...` | `community NAME { ... }` | ✓ | ✓ |
| `snmp-communities` | SNMP trap-group name | `set snmp trap-group NAME ...` | — | ✓ | — |

`snmp-contact` and `snmp-location` share item IDs with `credentials/informational`
and are handled entirely in pass 1.

---

### Pass 3 — AS Numbers

| Item ID | Rule | Set-format syntax | Block-format syntax | set | block |
|---------|------|-------------------|---------------------|:---:|:-----:|
| `bgp-asn` | autonomous-system | `set routing-options autonomous-system N` | `autonomous-system N;` | ✓ | ✓ |
| `bgp-asn` | BGP local-as | `set protocols bgp group NAME local-as N` | `local-as N;` | ✓ | ✓ |
| `bgp-asn` | BGP peer-as | `set protocols bgp group NAME peer-as N` | `peer-as N;` | ✓ | ✓ |
| `bgp-confederation` | confederation identifier | `set routing-options confederation N` | — | ✓ | — |
| `bgp-confederation` | confederation peers | `set routing-options confederation peers [N N ...]` | — | ✓ | — |
| `vrf-rd-rt` | route-distinguisher | `set routing-instances NAME route-distinguisher N:tag` | `route-distinguisher N:tag;` | ✓ | ✓ |
| `vrf-rd-rt` | vrf-target | `set routing-instances NAME vrf-target target:N:tag` | `vrf-target target:N:tag;` | ✓ | ✓ |
| `community-values` | community target: value | `target:N:tag` inline | same | ✓ | ✓ |
| `community-values` | community origin: value | `origin:N:tag` inline | same | ✓ | ✓ |
| `community-values` | community members list | `members [ N:tag N:tag ]` | same | ✓ | ✓ |
| `community-values` | community value (inline) | bare `N:tag` (5-digit AS) | same | ✓ | ✓ |

---

### Pass 4 — Named Objects

#### identity pass

| Item ID | Rule | Set-format syntax | Block-format syntax | set | block |
|---------|------|-------------------|---------------------|:---:|:-----:|
| `hostname` | host-name | `set system host-name NAME` | `host-name NAME;` | ✓ | ✓ |
| `domain-name` | domain-name | `set system domain-name NAME` | `domain-name NAME;` | ✓ | ✓ |
| `domain-name` | domain-search | `set system domain-search NAME` | — | ✓ | — |
| `usernames` | login user | `set system login user NAME ...` | `user NAME { ... }` | ✓ | ✓ |

#### aaa-objects pass

| Item ID | Rule | Set-format syntax | Block-format | set | block |
|---------|------|-------------------|-------------|:---:|:-----:|
| `aaa-profiles` | access profile | `set access profile NAME ...` | — | ✓ | — |

#### network-objects pass

| Item ID | Rule | Set-format syntax | Block-format syntax | set | block |
|---------|------|-------------------|---------------------|:---:|:-----:|
| `routing-instances` | routing-instance def | `set routing-instances NAME ...` | `instance NAME { ... }` | ✓ | ✓ |
| `routing-instances` | routing-instance ref | — | `instance NAME` (inline ref) | — | ✓ |
| `security-zones` | security-zone def | `set security zones security-zone NAME ...` | `security-zone NAME { ... }` | ✓ | ✓ |
| `security-zones` | from-zone ref | `from-zone NAME` | same | ✓ | ✓ |
| `security-zones` | to-zone ref | `to-zone NAME` | same | ✓ | ✓ |
| `address-books` | address-book def | `set security address-book NAME ...` | — | ✓ | — |
| `nat-rulesets` | NAT rule-set def | `set security nat source rule-set NAME ...` | — | ✓ | — |

#### routing-policy pass

| Item ID | Rule | Set-format syntax | Block-format syntax | set | block |
|---------|------|-------------------|---------------------|:---:|:-----:|
| `policy-statements` | policy-statement def | `set policy-options policy-statement NAME ...` | `policy-statement NAME { ... }` | ✓ | ✓ |
| `policy-statements` | export/import ref (protocol) | `set protocols bgp ... export NAME` | `export NAME;` / `import NAME;` | ✓ | ✓ |
| `policy-statements` | export/import ref (routing-options) | `set routing-options ... export NAME` | — | ✓ | — |
| `firewall-filters` | filter def | `set firewall family inet filter NAME ...` | `filter NAME { ... }` | ✓ | ✓ |
| `firewall-filters` | filter input ref (interface) | `set interfaces IF ... filter input NAME` | `filter { input NAME; }` | ✓ | ✓ |
| `firewall-filters` | filter output ref (interface) | `set interfaces IF ... filter output NAME` | `filter { output NAME; }` | ✓ | ✓ |
| `prefix-lists` | prefix-list def | `set policy-options prefix-list NAME ...` | `prefix-list NAME { ... }` | ✓ | ✓ |
| `prefix-lists` | prefix-list ref | `from prefix-list NAME` | same | ✓ | ✓ |
| `communities` | community def | `set policy-options community NAME members ...` | `community NAME { ... }` | ✓ | ✓ |
| `communities` | community ref (match) | `from community NAME` | same | ✓ | ✓ |
| `communities` | community ref (action) | `then community add/delete/set NAME` | same | ✓ | ✓ |

#### bgp-objects pass

| Item ID | Rule | Set-format syntax | Block-format syntax | set | block |
|---------|------|-------------------|---------------------|:---:|:-----:|
| `bgp-groups` | BGP group def | `set protocols bgp group NAME ...` | `group NAME { ... }` | ✓ | ✓ |

#### vpn-objects pass

| Item ID | Rule | Set-format syntax | Block-format syntax | set | block |
|---------|------|-------------------|---------------------|:---:|:-----:|
| `ike-proposals` | IKE proposal def | `set security ike proposal NAME ...` | `proposal NAME { ... }` | ✓ | ✓ |
| `ike-policies` | IKE policy def | `set security ike policy NAME ...` | `policy NAME { ... }` | ✓ | ✓ |
| `ike-gateways` | IKE gateway def | `set security ike gateway NAME ...` | `gateway NAME { ... }` | ✓ | ✓ |
| `ipsec-proposals` | IPsec proposal def | `set security ipsec proposal NAME ...` | — | ✓ | — |
| `ipsec-policies` | IPsec policy def | `set security ipsec policy NAME ...` | — | ✓ | — |
| `ipsec-vpns` | IPsec VPN def | `set security ipsec vpn NAME ...` | — | ✓ | — |

#### cos-objects pass

| Item ID | Rule | Set-format syntax | Block-format | set | block |
|---------|------|-------------------|-------------|:---:|:-----:|
| `cos-schedulers` | CoS scheduler def | `set class-of-service schedulers NAME ...` | — | ✓ | — |
| `cos-classifiers` | CoS classifier def | `set class-of-service classifiers dscp NAME ...` | — | ✓ | — |
| `cos-forwarding-classes` | CoS forwarding-class def | `set class-of-service forwarding-classes class NAME ...` | — | ✓ | — |
| `cos-scheduler-maps` | CoS scheduler-map def | `set class-of-service scheduler-maps NAME ...` | — | ✓ | — |
| `cos-scheduler-maps` | CoS scheduler-map ref | `set class-of-service interfaces IF scheduler-map NAME` | — | ✓ | — |

#### ntp-objects pass

| Item ID | Rule | Set-format syntax | Block-format | set | block |
|---------|------|-------------------|-------------|:---:|:-----:|
| `ntp-key-ids` | NTP authentication-key ID | `set system ntp authentication-key N ...` | — | ✓ | — |
| `ntp-key-ids` | NTP trusted-key ref | `set system ntp trusted-key N` | — | ✓ | — |

---

### Pass 5 — Descriptions

| Item ID | Rule | Syntax matched | Notes |
|---------|------|---------------|-------|
| `set-descriptions` | Set-format description | `set ... description "text"` or `set ... description text` | Any set-format line with a trailing description |
| `block-descriptions` | Block-format description | `description "text";` (any indentation) | Interface, routing-instance, BGP group, policy descriptions |

---

### Pass 6 — IPv4 Addresses

| Item ID | Notes |
|---------|-------|
| `ipv4-addresses` | All non-loopback host addresses replaced with `IPv4-xxxx` tokens. CIDR prefixes untouched. No wildcard-skip logic — Junos uses CIDR only. |

---

### Pass 7 — IPv6 Addresses

| Item ID | Notes |
|---------|-------|
| `ipv6-addresses` | All routable IPv6 addresses replaced with `IPv6-xxxx` tokens. Link-local, loopback, multicast, and unspecified addresses preserved. CIDR prefix lengths untouched. |

---

## Selectable Actions — Complete Item ID Reference

```
GROUP             PASS               ITEM ID
──────────────    ──────────────     ──────────────────────
credentials       local-auth         root-password
credentials       local-auth         user-passwords
credentials       local-auth         ssh-keys
credentials       routing-auth       bgp-keys
credentials       routing-auth       ospf-keys
credentials       routing-auth       isis-keys
credentials       routing-auth       ntp-keys
credentials       aaa-keys           radius-secrets
credentials       aaa-keys           tacacs-secrets
credentials       vpn-keys           ike-psk
credentials       snmpv3-keys        snmpv3-passwords
credentials       pki                certificate-data
credentials       informational      login-banner
credentials       informational      snmp-contact  *
credentials       informational      snmp-location *
snmp              snmp               snmp-communities
snmp              snmp               snmp-location *
snmp              snmp               snmp-contact  *
bgp-topology      as-numbers         bgp-asn
bgp-topology      as-numbers         vrf-rd-rt
bgp-topology      as-numbers         community-values
bgp-topology      as-numbers         bgp-confederation
named-objects     identity           hostname
named-objects     identity           domain-name
named-objects     identity           usernames
named-objects     routing-policy     policy-statements
named-objects     routing-policy     firewall-filters
named-objects     routing-policy     prefix-lists
named-objects     routing-policy     communities
named-objects     bgp-objects        bgp-groups
named-objects     network-objects    routing-instances
named-objects     network-objects    security-zones
named-objects     network-objects    address-books
named-objects     network-objects    nat-rulesets
named-objects     aaa-objects        aaa-profiles
named-objects     vpn-objects        ike-proposals
named-objects     vpn-objects        ike-policies
named-objects     vpn-objects        ike-gateways
named-objects     vpn-objects        ipsec-proposals
named-objects     vpn-objects        ipsec-policies
named-objects     vpn-objects        ipsec-vpns
named-objects     cos-objects        cos-schedulers
named-objects     cos-objects        cos-classifiers
named-objects     cos-objects        cos-forwarding-classes
named-objects     cos-objects        cos-scheduler-maps
ntp-objects       ntp-objects        ntp-key-ids
addressing        ipv4               ipv4-addresses
addressing        ipv6               ipv6-addresses
descriptions      descriptions       set-descriptions
descriptions      descriptions       block-descriptions

* snmp-contact and snmp-location share a single item ID across both groups.
  Disabling either path disables both.
```

---

## Per-File Coverage Summary

| Rule group | `sample_junos_set` | `sample_junos_block` |
|-----------|:---:|:---:|
| `root-password` | ✓ | ✓ |
| `user-passwords` | ✓ | ✓ |
| `ssh-keys` | ✓ | ✓ |
| `radius-secrets` | ✓ | ✓ |
| `tacacs-secrets` | ✓ | — |
| `bgp-keys` | ✓ | ✓ |
| `ospf-keys` | ✓ | ✓ |
| `isis-keys` | ✓ | ✓ |
| `ntp-keys` | ✓ | ✓ |
| `ike-psk` | ✓ | — |
| `snmpv3-passwords` | ✓ | ✓ |
| `certificate-data` | ✓ | ✓ |
| `login-banner` | ✓ | ✓ |
| `snmp-contact` | ✓ | ✓ |
| `snmp-location` | ✓ | ✓ |
| `snmp-communities` | ✓ | ✓ |
| `bgp-asn` | ✓ | ✓ |
| `bgp-confederation` | ✓ | — |
| `vrf-rd-rt` | ✓ | ✓ |
| `community-values` | ✓ | ✓ |
| `hostname` | ✓ | ✓ |
| `domain-name` | ✓ | ✓ |
| `usernames` | ✓ | ✓ |
| `aaa-profiles` | ✓ | ✓ |
| `routing-instances` | ✓ | ✓ |
| `security-zones` | ✓ | — |
| `address-books` | ✓ | — |
| `nat-rulesets` | ✓ | — |
| `policy-statements` | ✓ | ✓ |
| `firewall-filters` | ✓ | ✓ |
| `prefix-lists` | ✓ | ✓ |
| `communities` | ✓ | ✓ |
| `bgp-groups` | ✓ | ✓ |
| `ike-proposals` | ✓ | — |
| `ike-policies` | ✓ | — |
| `ike-gateways` | ✓ | — |
| `ipsec-proposals` | ✓ | — |
| `ipsec-policies` | ✓ | — |
| `ipsec-vpns` | ✓ | — |
| `cos-schedulers` | ✓ | ✓ |
| `cos-classifiers` | ✓ | — |
| `cos-forwarding-classes` | ✓ | ✓ |
| `cos-scheduler-maps` | ✓ | ✓ |
| `ntp-key-ids` | ✓ | — |
| `set-descriptions` | ✓ | — |
| `block-descriptions` | — | ✓ |
| `ipv4-addresses` | ✓ | ✓ |
| `ipv6-addresses` | ✓ | ✓ |
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

# Dry-run preview of a single file
python juniper_sanitise.py \
  -i ./test_configs/sample_junos_set.conf \
  --dry-run \
  --seed test-run-2024

# Show all selectable IDs
python juniper_sanitise.py --list-items

# Test skip-group: verify credentials are NOT redacted, IPs ARE tokenised
python juniper_sanitise.py \
  -i ./test_configs/sample_junos_set.conf \
  --dry-run --seed test-run-2024 \
  --skip-group credentials

# Test only-pass: verify only named identity objects are processed
python juniper_sanitise.py \
  -i ./test_configs/sample_junos_set.conf \
  --dry-run --seed test-run-2024 \
  --only-pass identity

# Test skip at item level: verify ntp-keys and login-banner survive
python juniper_sanitise.py \
  -i ./test_configs/sample_junos_set.conf \
  --dry-run --seed test-run-2024 \
  --skip ntp-keys,login-banner
```

---

## What to Verify After Running

**Full run (default)**

Credentials removed — search the output for `$6$`, `ssh-rsa`, `secret`, `authentication-key`,
`pre-shared-key`, `authentication-password`, `privacy-password`, `value`.
None should retain a real value — all should show `<REMOVED>`.

SNMP community consistent — the same community string should produce the same
`snmp-xxxx` token on both the `community NAME` definition line and any `trap-group`
reference.

AS numbers tokenised — `65001` should map to the same `AS-xxxx` token in
`autonomous-system`, `peer-as`, `local-as`, `route-distinguisher`, `vrf-target`,
and `target:` community values.

IPv4 addresses tokenised — all non-loopback host addresses replaced with
`IPv4-xxxx` tokens. CIDR prefix lengths (`/30`, `/32`) must be untouched.

IPv6 addresses tokenised — routable addresses become `IPv6-xxxx` tokens. Verify
`FE80::x` link-local and `::1` loopback are preserved unchanged.

Config structure intact — correct indentation, `{` `}` delimiters, `;` terminators
and block structure all preserved in the sanitised file.

**Selectable actions**

`--skip-group credentials` — verify `$6$` hashes, `secret "..."`, `authentication-key "..."`
values all survive unchanged in the output. Named objects and IPs should still be tokenised.

`--only-group addressing` — verify only IP addresses are tokenised. All credentials,
hostnames, AS numbers, and descriptions should be unchanged.

`--skip-pass routing-auth` — verify `bgpSecretKey`, `ospfMd5Key`, `isisAuthKey`,
and `ntpSecretKey` values survive. Other credentials (`$6$`, RADIUS/TACACS+
secrets) should still show `<REMOVED>`.

`--skip ntp-keys,login-banner` — verify NTP `value "..."` lines and the login
announcement survive unchanged. All other credentials should still be redacted.

`--only-pass identity` — verify only `host-xxxx`, `user-xxxx`, and `dom-xxxx`
tokens appear. All IPs, AS numbers, descriptions, and other named objects should
be unchanged.

`--no-ips` (legacy) — identical behaviour to `--skip-group addressing`. IPs must
survive unchanged; all other sanitisation must still run.

**Mutual exclusion errors**

`--skip-group credentials --only-group snmp` must print an error and exit non-zero.
`--skip ntp-keys --only bgp-keys` must print an error and exit non-zero.

**Unknown ID error**

`--skip bogus-item` must print an error referencing `--list-items` and exit non-zero.

**`--list-items`**

Must print the complete hierarchy of all groups, passes, and item IDs with
descriptions, and exit without processing any files.

---

## Known Limitations

| Item | Detail | Test config |
|------|--------|-------------|
| **`apply-groups` references** | Group names in `apply-groups` and `groups` stanzas are not tokenised | — |
| **`event-options` policy names** | Event policy names are not tokenised | — |
| **Dynamic tunnel group names** | `dynamic-tunnels` group names not tokenised; endpoint IPs anonymised | — |
| **Block-format NAT / address-book names** | Only matched in set-format | — |
| **FQDN-based server addresses** | RADIUS/TACACS+ servers configured with a hostname rather than IP are not tokenised | — |
| **Hostnames in descriptions** | Description token replaces the whole string; original is visible in mapping file | — |
| **IPsec/IKE intra-stanza cross-references** | Lines that reference a named proposal, policy, or gateway *within* an enclosing stanza (e.g. `proposals IKE-PROPOSAL-BLOCK;`, `ike-policy IKE-POLICY-SITE-A;`, `gateway IKE-GW-SITE-A;`) are not tokenised — only the definition lines (`proposal NAME { }`, `policy NAME { }`, etc.) are matched. The same gap exists in set-format (e.g. `set security ike policy NAME proposals PROPOSAL-NAME` — the trailing `PROPOSAL-NAME` value is not tokenised). Definition names are consistently anonymised; the cross-reference values within a stanza are left as-is. | `sample_junos_block.conf` |

---

## Bugs Found and Fixed During Test Config Expansion

The following script bugs were discovered by adding the previously-uncovered test
cases and are fixed in the current version of `juniper_sanitise.py`.

| Bug | Symptom | Root cause | Fix |
|-----|---------|------------|-----|
| **NTP key value not redacted (set-format)** | `value "ntpSecretKey1"` survived in sanitised output | The set-format NTP credential pattern used `\S+\s+` (one token) between the key ID and `value` keyword, but Junos syntax places two tokens there: `type` and the algorithm name (e.g. `md5`). The pattern never matched. | Changed `\d+\s+\S+\s+value` to `\d+[^\S\n]+(?:\S+[^\S\n]+)+value` to consume any number of intermediate tokens while preventing cross-line matching. |
| **Block-format IPsec proposal/policy names not tokenised** | `IPSEC-PROPOSAL-BLOCK` and `IPSEC-POLICY-BLOCK` survived in sanitised output | The `proposal NAME {` and `policy NAME {` block patterns were guarded solely by `ike-proposals` and `ike-policies` respectively. When only `ipsec-proposals` or `ipsec-policies` was enabled, the shared block pattern never ran. | Restructured the guards to `if C("ike-proposals") or C("ipsec-proposals"):` so the shared block pattern fires whenever either item is enabled. |
| **Block-format IPsec VPN names not tokenised** | `VPN-BLOCK` survived in sanitised output | No block-format pattern existed for `vpn NAME {` — the `ipsec-vpns` item only had a set-format pattern. | Added `re.compile(r'^(\s*vpn\s+)(?P<n>\S+)\s*\{', re.M)` under the `ipsec-vpns` guard. |

---

## Rules Defined but Not Exercised by Current Test Configs

All previously uncovered rules are now exercised by the test configs. The table
below is retained as a nil return for completeness.

| Item ID | Syntax | Notes |
|---------|--------|-------|
| *(none)* | — | — |