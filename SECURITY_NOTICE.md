# Security Notice — Test Configuration Credentials

## Summary

The test configuration files in this repository contain credentials, password hashes,
and network addresses that appear sensitive. **Every single value is entirely fabricated.**
No credential, address, AS number, hostname, or organisation name in any test file has
ever been used on a real device or network. This document explains what is present,
why it is present, and why it does not represent a security risk.

---

## All Data Is Fictional

The two test configurations (`sample_junos_set.conf`, `sample_junos_block.conf`)
are synthetic. They were written from scratch to exercise the sanitiser's rule coverage
and contain no information derived from any real network, organisation, or device. In
particular:

- **Hostnames** such as `MX-CORE-LON-01` and `EX-DIST-LON-01` are invented. They do
  not correspond to any real device.
- **Organisation names** such as `acmecorp.com`, `corp.internal`, and `NOC` are
  placeholder names with no relation to any real entity.
- **Network addresses** are drawn exclusively from RFC-reserved ranges that can never
  appear on the public internet:
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — RFC 1918 private ranges
  - `198.51.100.0/24`, `203.0.113.0/24` — RFC 5737 documentation ranges (TEST-NET-2/3)
  - `2001:db8::/32` — RFC 3849 IPv6 documentation range
- **AS numbers** such as `65000`–`65300` are in the IANA-reserved private AS range
  (64512–65534) and are not assigned to any real organisation.
- **Contact details** and email addresses (e.g. `noc@acmecorp.com`,
  `noc-team@corp.internal`) are entirely made up.

---

## Why Plaintext Credentials Are Present

Junos supports several credential forms across its authentication features. A core
purpose of this tool is to detect and redact **all** of them. To test that coverage
comprehensively, the test configs must contain one or more examples of every credential
type that appears in real-world configurations.

| Junos credential type | Encoding | Example in test configs |
|----------------------|----------|------------------------|
| `encrypted-password` | Junos SHA-512 crypt hash (`$6$...`) | `"$6$abc123$hashedpassword"` |
| `plain-text-password-value` | Cleartext — stored verbatim | *(not exercised in current test configs)* |
| `secret` (RADIUS/TACACS+) | Cleartext string in quotes | `"radiusSecretKey1"` |
| `authentication-key` (BGP) | Cleartext string in quotes | `"bgpSecretKey1"` |
| `key` (OSPF MD5) | Cleartext string in quotes | `"ospfMd5Key1"` |
| `authentication-key` (IS-IS) | Cleartext string in quotes | `"isisAuthKey1"` |
| `ascii-text` (IKE PSK) | Cleartext string in quotes | `"ikePreSharedSecretKey"` |
| `authentication-password` (SNMPv3) | Cleartext string in quotes | `"snmpAuthPassword"` |
| `privacy-password` (SNMPv3) | Cleartext string in quotes | `"snmpPrivPassword"` |
| `value` (NTP auth-key) | Cleartext string in quotes | `"ntpSecretKey1"` |
| SSH public-key blob | Base64-encoded public key | `"AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."` |

**Encrypted hashes are fabricated.** The strings beginning `$6$` in the test configs
are SHA-512 crypt hashes with randomly chosen salts. They do not encode any real or
guessable passphrase and were constructed solely to exercise the encrypted-password
pattern in the sanitiser.

**The SSH public-key blob is truncated and invalid.** The value
`"AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."` is a partial, non-functional Base64 string.
It is present to confirm the sanitiser correctly matches and redacts SSH public-key
lines regardless of key length; it cannot be used to authenticate to any system.

### Plaintext credential values used

The following cleartext values appear across the test configs. They are listed here
in full to make clear that they are obviously contrived test strings, not operational
secrets:

| Value | Where used |
|-------|-----------|
| `radiusSecretKey1` | RADIUS server secret (set-format) |
| `radiusSecretKey2` | RADIUS server secret (set-format) |
| `tacacsSecretKey1` | TACACS+ server secret (set-format) |
| `blockRadiusSecret` | RADIUS server secret (block-format) |
| `blockRadiusSecret2` | RADIUS server secret (block-format) |
| `bgpSecretKey1` | BGP authentication-key (IPv4 peer, set-format) |
| `bgpSecretKey2` | BGP authentication-key (IPv6 peer, set-format) |
| `bgpAcmeKey` | BGP authentication-key (customer peer, set-format) |
| `ibgpAuthKeyBlock` | BGP authentication-key (IPv4 peer, block-format) |
| `ibgpAuthKeyBlockV6` | BGP authentication-key (IPv6 peer, block-format) |
| `custBAuthKey` | BGP authentication-key (VRF customer CE, block-format) |
| `ospfMd5Key1` | OSPF MD5 authentication key (set-format) |
| `ospfBlockMd5Key` | OSPF MD5 authentication key (block-format) |
| `isisAuthKey1` | IS-IS interface authentication key (set-format) |
| `isisGlobalKey` | IS-IS global authentication key (set-format) |
| `isisBlockKey` | IS-IS interface authentication key (block-format) |
| `ikePreSharedSecretKey` | IKE pre-shared key, ascii-text (set-format) |
| `snmpAuthPassword` | SNMPv3 authentication password (set-format) |
| `snmpPrivPassword` | SNMPv3 privacy password (set-format) |
| `snmpV3BlockAuthPw` | SNMPv3 authentication password (block-format) |
| `snmpV3BlockPrivPw` | SNMPv3 privacy password (block-format) |
| `ntpSecretKey1` | NTP authentication-key value, key ID 10 (set-format) |
| `ntpSecretKey2` | NTP authentication-key value, key ID 20 (set-format) |
| `ntpBlockSecret1` | NTP authentication-key value, key ID 1 (block-format) |
| `ntpBlockSecret2` | NTP authentication-key value, key ID 2 (block-format) |

None of these strings have ever been used as a credential on any real system. The
deliberate use of descriptive names such as `SecretKey`, `AuthPw`, and similar
patterns is intentional — they make the credential type immediately obvious to a
reviewer while remaining clearly non-operational test strings.

---

## Why Credentials Must Be Kept in the Test Configs

The sanitiser operates on raw configuration text. To verify that a rule works
correctly, the input file must contain a real example of the pattern the rule
targets. There is no way to test redaction of a cleartext BGP authentication key
without a cleartext BGP authentication key being present in the file.

Specifically, the test suite depends on these credential examples to verify:

1. **Pattern coverage** — every credential-bearing line type that exists in Junos
   set-format and block-format must appear in at least one test config so that the
   corresponding regex can be confirmed to match.

2. **Dual-format coverage** — most credential types appear in both
   `sample_junos_set.conf` and `sample_junos_block.conf` to confirm that both the
   set-format and block-format regex patterns fire correctly for the same underlying
   credential type.

3. **Pass ordering** — credentials are redacted in pass 1, before any other
   substitution. Test configs with multiple credential types on adjacent lines confirm
   that pass-ordering logic does not cause any form to be missed or double-processed.

4. **False-positive detection** — the IPv6 regex must not match Base64 SSH key blobs
   or quoted password strings. The only reliable way to confirm this is to run the
   sanitiser against a config that contains both IPv6 addresses and these credential
   forms on nearby lines.

5. **RADIUS/TACACS+ intermediate token handling** — Junos RADIUS and TACACS+ server
   lines include optional `port N` and `timeout N` tokens between the server address
   and the `secret` keyword. Test configs include lines with these optional tokens
   present to confirm the regex correctly skips them and still matches the secret value.

6. **Dry-run verification** — the `--dry-run` flag prints the sanitised output without
   writing files. Reviewers comparing before/after output need recognisable credential
   strings in the input to confirm that `<REMOVED>` appears in the correct positions
   in the output.

Removing or replacing credentials with inert placeholder text (e.g. `secret "REDACTED"`)
would make the test configs unable to serve their purpose: the sanitiser would have
nothing meaningful to redact, and the test would prove nothing.

---

## What the Sanitiser Does to These Values

When `juniper_sanitise.py` is run against the test configs, every credential listed
above is replaced with `<REMOVED>` in the output. After sanitisation, no credential
value appears in any output file.

The test configs exist as *inputs* to demonstrate the tool works. They are never
intended to be, and should never be treated as, outputs.

---

## The Seed and Token Reversibility

Tokens are derived from `SHA-256(seed:category:original_value)`. SHA-256 is a
one-way function — a token alone cannot be reversed to its source value, even
with full knowledge of the script.

However, the seed enables **forward lookup**: anyone who has the seed and the
script can compute the expected token for any candidate value and check whether
it matches the sanitised output. This is structurally the same as a salted
password hash — the salt is known, but an attacker still has to guess the input.

**Treat the seed as sensitive.** The practical severity depends on the data type:

| Data type | Enumeration feasibility | Risk with seed exposed |
|-----------|------------------------|----------------------|
| IPv4 addresses | RFC 1918 (~16 M addresses) — enumerable in seconds | High — full IP mapping reconstructible |
| IPv6 addresses | `2001:db8::/32` documentation range used in test configs; real ranges may be larger but still enumerable if the prefix is known | Medium–High |
| Hostnames / VRF names | Depends on naming conventions; systematic names (e.g. `SITE-ROUTER-LON-01`) are guessable | Low–Medium |
| Credentials | Already replaced with `<REMOVED>` — tokens are never issued for credential values | Not applicable |

### What the banner exposes

The sanitised-output banner records a **16-character SHA-256 fingerprint** of the
seed — the first 64 bits of `SHA-256(seed)`. This is a one-way commitment: it
allows two sanitised files to be verified as sharing the same seed (and therefore
having consistent, comparable tokens) without exposing the seed to anyone who reads
the output. The fingerprint alone provides no advantage to an attacker performing
forward lookup; they still need the actual seed.

### Recommended practice

- Use a seed that is not guessable or publicly documented (not `juniper-sanitise`,
  not a project name, not a date)
- Distribute the seed only to people who are authorised to reverse-look up tokens
- Store it alongside the mapping file (`--dump-map`), not alongside the sanitised
  configs themselves
- If a seed is compromised, re-sanitise all affected configs with a new seed

---

## Checklist for New Contributors

If you are adding new test configuration content to this project, please follow
these rules:

- [ ] All IP addresses must be drawn from RFC 1918 (`10/8`, `172.16/12`,
      `192.168/16`) or RFC 5737/3849 documentation ranges
      (`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`)
- [ ] All AS numbers must be in the IANA private range (64512–65534)
- [ ] All hostnames, domain names, and organisation names must be clearly fictional
- [ ] Cleartext credential values must be obviously contrived strings that bear no
      resemblance to a real password policy format — avoid dictionary words, common
      patterns, or anything that could plausibly be mistaken for an operational secret
- [ ] Encrypted hashes (`$6$...`) must be generated fresh with a random salt and
      must not encode any real or guessable passphrase
- [ ] SSH public-key blobs may be truncated or structurally invalid — they are
      present only to exercise the regex pattern, not to represent a usable key
- [ ] Any new credential pattern added for test coverage must be accompanied by a
      corresponding entry in `test_configs/TEST_REFERENCE.md`
- [ ] New test content must appear in both `sample_junos_set.conf` and
      `sample_junos_block.conf` wherever the credential type exists in both formats
- [ ] Run `juniper_sanitise.py --dry-run` against your new config and confirm that
      every credential you added appears as `<REMOVED>` in the output

---

## Questions

If you have concerns about any specific value in the test configs, open an issue.
Please quote the file name, line number, and the specific string you are querying.