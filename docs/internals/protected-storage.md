# Syzygy protected streams and vault

This note records the byte grammar recovered from `mso20win32client.dll`
16.0.20527.20196. It covers the layer above Arx file extents and below the
logical DRG/document bytes. The equations and parsers are reproducible in
`src/cacheweave/crypto/syzygy_protected_stream.py` and `src/cacheweave/crypto/syzygy_vault.py`. The
current AES-256-CBC crypt session below this framing is documented in
`crypt-session.md` and reproduced by `src/cacheweave/crypto/syzygy_crypt_session.py`.

## Layer placement

Arx locates an opaque file byte stream. When that file is protected, Syzygy
frames it as encrypted shards with authenticated footers:

```text
Arx file extents
    -> protected-stream shards and fixed footers
    -> IMsoCryptSession decrypt
    -> remove final inner padding
    -> logical DRG/document bytes
```

The `_vault` resident property supplies serialized crypt-session records and
the ordered provider list needed to recover those sessions. It is not a child
filename.

## Physical size and shard grammar

`Syzygy::Cipher::Append` at `+0x27b8cc` limits each encrypted shard to
`0xff80` bytes. Every shard is immediately followed by a fixed `0x80`-byte
footer, so a full physical shard is exactly `0x10000` bytes.

For logical size `L` and the active crypt session's block size `B`:

```text
P = (-L) mod B                         # 0 when already aligned
A = L + P
N = ceil(A / 0xff80)
S = A + N * 0x80 + P
```

`P` random bytes are appended to the plaintext before encryption (inner
padding). After the final footer, another `P` random bytes are appended without
encryption (outer padding). This duplication is intentional; native code
requires `S mod B == P`.

`Syzygy::Cipher::SeekEnd` at `+0x381da8` recovers the logical size without
decrypting:

```text
P = S mod B
Q = S - 2*P
full, tail = divmod(Q, 0x10000)
L = full*0xff80 + (tail - 0x80 if tail else 0)
```

The decoder rejects noncanonical sizes, truncated footers, invalid Terse
streams, and footer slots with nonzero bytes after the embedded stream.

## Fixed 0x80-byte footer

The serializer is at `+0x2c2cc0` and the deserializer at `+0x2837e0`. Each
footer is one complete Terse-v2 envelope, then zero padding to exactly
`0x80` bytes. Its Terse payload is:

```text
u8            footer_format_version = 1
ULEB32        session_id
ULEB32        salt
array<u8,16>  encrypted_hmac_key     ULEB32 count (must be 0x10) + 16 bytes
array<u8,64>  encrypted_hmac_value   ULEB32 count (must be 0x40) + 64 bytes
```

A Terse fixed-size array includes a count prefix.
`Terse::Reader::Read<uint8_t,N>` (`+0x282258`) reads a ULEB32 count and rejects
any value other than `N` ("Array size mismatch"). All 71 streams in the initial
capture carry the expected `0x10` and `0x40` counts.

Neither stored value is plaintext:

- **HMAC key:** a fresh random key, encrypted with the stream AES key after
  `Reset(0x0b511c03, shard_index)`.
- **HMAC value:** the computed HMAC, encrypted after
  `Reset(0x033becab, shard_index)`. See the next section.

A standalone decoder can inventory the framing. Verifying the HMAC requires
the unwrapped stream key and the `keyData` salt.

## Integrity and read order

`Integrity::CalculateHMAC`, `VerifyHMAC`, and `GetHMAC` are at `+0x281d28`,
`+0x2819fc`, and `+0x3826d8`. The default for Syzygy setting ID `0x0d` is the
literal `SHA512`, returned by `Syzygy::SettingsDefaultValues::GetDefaultValue`
at `+0x0dc490`.

The rules below come from `Cipher::ReadBuffered`
(`+0x5cad58`), `VerifyHMAC`, `CalculateHMAC`, and
`CCryptoObj::HrReset(a, b)` (`+0x375790`). They verify on 71/71 live streams.

```text
Reset(a, b) block key = LE32(a)              if b == 0
                        LE32(a) || LE32(b)   otherwise
IV(blockKey)          = SHA512(keyData.saltValue || blockKey)[0:16]

content         : Reset(footer_salt, shard_index)
HMAC key        : Reset(0x0b511c03, shard_index), decrypt the footer key
HMAC input      : LE32(footer_salt) || LE32(shard_index) || ciphertext
HMAC value      : Reset(0x033becab, shard_index), encrypt the computed
                  HMAC-SHA512 and compare it with the footer's encrypted value
```

Because the content key carries the footer salt and every shard has its own
footer, each shard gets a distinct IV. The multi-shard eight-byte form follows
from `HrReset` and was verified on captured multi-shard streams.

The read path first removes outer padding, parses the footer, recovers the HMAC
key through the session, verifies the HMAC over ciphertext, decrypts only after
successful verification, and finally removes inner padding from the last
shard. Consumers must not decrypt unauthenticated bytes or treat protected
content as damaged plaintext.

## `_vault` outer grammar

`Vault::SerializeAndWrite` is at `+0x2c23e0` and
`Vault::ReadAndDeserialize` at `+0x2fbae0`. The current vault version is `1`,
initialized by the constructor at `+0x0bb4d8`. The complete outer value is a
Terse-v2 envelope with this payload:

```text
ULEB16        version = 1
ULEB32        Storage::Crc32(sessions_blob)
ULEB32        provider_count
repeat provider_count:
    GUID[16]  provider_id in Windows bytes_le form
byte_vector   sessions_blob
```

The checksum uses the same recovered `Storage::Crc32` algorithm as Terse:
MSB-first polynomial `0x000000af`, initial zero, no final XOR. Encryption
providers are applied in stored forward order by `Vault::EncryptSessions` at
`+0x2fae84`. They are resolved and applied in reverse order by
`Vault::DecryptSessions` at `+0x2f51e8`.

When `provider_count` is nonzero, `sessions_blob` remains provider-encrypted
and the generic decoder preserves it as opaque bytes. Provider code and any
required credentials are needed to go further. The three provider GUIDs in
this build, the exact DPAPI flags, enterprise wrapper, and reproducible IRM
HMAC-SHA256 layer are recovered in `encryption-providers.md`.

## Plaintext session-list grammar

The plaintext session list is a headerless Terse-v2 payload, with or without
providers. `ReadAndDeserialize` parses it with
`Terse::Reader::Create(span, 2, 1)`, not the enveloped `Create(span, 0xff)`
used for the outer value. The DPAPI-unwrapped list has no envelope. Its payload is:

```text
ULEB32 session_count
repeat session_count:
    ULEB32      session_id
    ULEB32      declared_secret_size
    byte_vector secret
    byte_vector serialized_value
    ULEB32      active              # exactly 0 or 1
    ZigZag64    created_timestamp
    u8          flags
```

`SerializeCryptSession` at `+0x3bbabc` serializes an `IMsoCryptSession` through
an `IStream` into `serialized_value`. The decoder validates duplicate IDs,
boolean values, checksums, lengths, and trailing bytes but deliberately assigns
no unsupported meaning to `flags` or the secret fields.

## Implementation and validation

`src/cacheweave/crypto/syzygy_protected_stream.py` reproduces both size directions, parses
and builds fixed footer slots, and inventories physical shard offsets, logical
sizes, footer metadata, outer padding, and ciphertext hashes. Given the
unwrapped random stream key and stream salt, it validates session IDs, decrypts
each footer HMAC key, authenticates all shards before returning data, derives
each content IV, decrypts AES-256-CBC, and removes only the final inner padding.
`src/cacheweave/crypto/syzygy_vault.py` parses both vault layers, validates the
outer checksum and GUID order, and passes provider-protected session blobs to
the configured key provider.

The active per-stream path is AES-256-CBC with a random 32-byte stream key and
16-byte stream salt. Crypto XML wraps that stream key under three
block-key-separated SHA-512/AES keys derived from the 64-byte random vault
secret and verifies the secret before unwrap; see `crypt-session.md`.

The complete path was validated against the initial 71-stream capture and the
lab corpus, including multi-shard streams. Provider credentials remain
an input requirement: personal-OneDrive captures used machine DPAPI, while
enterprise-protected and IRM-protected vaults were not available for live validation.
