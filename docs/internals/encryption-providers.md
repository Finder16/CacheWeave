# Syzygy vault encryption providers

This note records the provider implementations and identifiers recovered from
`mso30win32client.dll` 16.0.20527.20196. These providers transform the
`sessions_blob` inside the `_vault` format documented in
`protected-storage.md`; they are distinct from the per-shard crypt session and
SHA-512 HMAC used by `Syzygy::Cipher`.

## Provider identifiers

The GUID-returning virtual methods and their exact 16 bytes in `.rdata` give:

| Provider | GUID | GUID bytes RVA |
|---|---|---:|
| Standard Windows DPAPI | `54bd1499-7413-472f-8835-d19454db7952` | `0xc8afa0` |
| Enterprise Data Protection | `fb19597b-51db-40fb-ae2a-62acd2195bec` | `0xd05390` |
| Information Rights Management | `65e11c58-98f0-47f8-92a4-b3ecadd5b4d1` | `0xd1a7c0` |

The bytes use Windows GUID byte order, exactly as the vault serializer stores
them. `src/cacheweave/crypto/syzygy_encryption_providers.py` names all three IDs, and
`src/cacheweave/crypto/syzygy_vault.py` includes those names in decoded JSON while preserving
unknown future GUIDs.

`Storage::Encryption::Aggregator::Aggregate` at `+0x52f9b0` walks registered
encryption providers and registered decryption providers in insertion order,
retaining only providers whose `Enabled` virtual returns true. The Vault then
encrypts its session blob in forward provider order and decrypts in reverse
stored-GUID order. Registration order is therefore part of the effective
transform stack.

## Standard Windows DPAPI provider

`StandardEncryptionProvider::Encrypt` at `+0x38e130` calls
`CryptProtectData` with no description, optional entropy, reserved data, or
prompt structure. Its flags are `5`, the combination of UI-forbidden (`1`) and
local-machine (`4`). It immediately calls `CryptUnprotectData` with flags `1`
and rejects the result unless both length and bytes exactly match the input.

`StandardDecryptionProvider::Decrypt` at `+0x38e640` calls
`CryptUnprotectData` with flags `1` and no optional entropy or prompt. The
encryption and decryption halves return the same GUID at `+0x601310` and
`+0x61c820`.

CacheWeave's offline provider reproduces the machine-DPAPI path from the
originating installation's `SYSTEM` and `SECURITY` hives and `S-1-5-18`
master keys. Vault bytes alone are not sufficient.

## Enterprise Data Protection provider

The encryption half at `+0x789d00` first creates a Terse-v2 stream whose
payload is:

```text
ULEB16      schema_version = 1
byte_vector plaintext_sessions_blob
```

It then asks the configured enterprise-protection controller for an identity
and calls Office's `CBufferProtectionManager` through
`EnterpriseProtector::Protect` at `+0x92ee10`. The decrypt half at `+0x4803d0`
calls `EnterpriseProtector::Unprotect` (`+0x92ee60`), parses the same Terse-v2
wrapper, compares the stored schema version with current version `1`, and
returns the byte vector. A version mismatch is surfaced as an update condition
rather than silently changing the grammar.

The provider cannot be reproduced from vault bytes alone. It requires the
Office enterprise-data-protection service, an enterprise identity/policy
context, and its platform-protected state.

## IRM provider

`IrmEncryptionProvider::Encrypt` at `+0x47f860` creates this Terse-v2 stream:

```text
ULEB32      schema_version = 1
byte_vector plaintext_sessions_blob
```

`IrmIntegrity::AddMAC` at `+0x47fd78` then adds an independently reproducible
integrity layer before handing the result to `IIrmCrypto::Encrypt`:

```text
terse_plaintext
random_key_seed[32]
hmac_sha256[32]
```

The exact two HMAC-SHA256 operations are:

```text
context       = 01 || ASCII("PlaintextHmacKey") || 00 01 00
integrity_key = HMAC-SHA256(key=random_key_seed, data=context)
hmac_value    = HMAC-SHA256(
                    key=integrity_key,
                    data=terse_plaintext || random_key_seed)
```

`IrmDecryptionProvider::Decrypt` at `+0x47e610` tries every registered
`IIrmCrypto` object in order. `TryDecryptInternal` at `+0x47ea88` accepts a
candidate only after `IrmIntegrity::VerifyAndStripMAC` (`+0x47f6b0`) compares
the trailing MAC, then parses the Terse stream, requires schema version `1`,
and returns its byte vector. A failed MAC is not passed to the Terse parser.

`src/cacheweave/crypto/syzygy_encryption_providers.py` implements the provider-ID mapping,
key derivation, integrity add/verify/strip, and the inner IRM Terse wrapper.

The integrity layer is not IRM decryption. An applicable `IIrmCrypto` and its
rights-management credentials are still required to produce the bytes on
which this verifier operates.

## Validation boundary

The analysis identifies every provider implementation visible in this build
and the complete inner framing for IRM and enterprise data protection. Every
captured personal-OneDrive vault names only `standard-dpapi-machine`, and the
offline DPAPI provider unwraps it. No provider stacking was observed.
Enterprise data protection and IRM require their platform services, policy
state, and credentials; neither path was available for live validation.
