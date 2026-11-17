# Syzygy current crypt session

This note records the current per-stream `IMsoCryptSession` selected by
Syzygy in `mso20win32client.dll` 16.0.20527.20196. It is the transform below
the protected-stream framing in `protected-storage.md` and is distinct from
the DPAPI, enterprise, and IRM providers that protect the `_vault` session
list. `src/cacheweave/crypto/syzygy_crypt_session.py` implements the standard Agile 4.4
`\EncryptionInfo` header and Crypto XML, password verifier, random stream-key
unwrap, optional standard `dataIntegrity`, and AES operation.

## Selection path

`Vault::Rotate` at `+0x2fb720` reads Syzygy setting `0x0a`. The default at
`+0x0dc490` is `0x20`, meaning 32 UTF-16 code units. The call site doubles
that value before `Vault::GenerateSecret` (`+0x396a78`), so each new session
contains exactly 64 cryptographically random bytes. The serialized vault
record retains `declared_secret_size = 32` and a 64-byte secret vector.

`Vault::CreateCryptSession` at `+0x300338` reads setting `0x0b`, whose default
is `0x3c0`, and passes it to `MsoPeadGetDefault` (`+0x3006a0`). The descriptor
created by `CMsoEad::PeadCreateNew` (`+0x30076c`) has effective flags
`0x400003c0` and selects the Session2/`CSX` CNG path. Bit 30 also causes
`CMsoEad::HrEnsureInit` (`+0x2ffc28`) to create a `CCryptoKeyMgr`: the Vault
secret protects a separate random stream key rather than becoming that key.

The current CNG algorithms are:

| Field | Current value | Evidence |
|---|---:|---|
| cipher provider | `AES` | `DefaultCngAlg` `+0x52df40`, algorithm ID 1 |
| hash provider | `SHA512` | same function, algorithm ID 2 |
| chaining mode | `ChainingModeCBC` | `FGetCngCipherChain` `+0x3005f0` |
| salt length | 16 bytes | next-generation descriptor and Crypto XML |
| digest length | 64 bytes | SHA-512 hash object queried by `HrInitObj` |
| key length | 256 bits | AES key-range selection in `GetDefaultKeyBits` `+0x3c6fd0` |
| block length | 16 bytes | CNG `BlockLength`, stored at `CMsoEad +0x14` |

`CCryptoObj::HrInitObj` at `+0x2ffa7c` records the SHA-512 output size and
uses that 64-byte size as the AES key-range preference. CNG therefore selects
the largest supported AES key, 256 bits, rather than the 128-bit minimum.

## Two distinct keys and salts

The current XML contains two AES descriptors with different jobs:

1. `keyData` describes the random 32-byte stream key and its 16-byte stream
   salt. This key encrypts protected-stream content; the salt is combined with
   an operation-specific reset key to derive each CBC IV.
2. `p:encryptedKey` describes password-derived wrapping keys. The 64-byte
   Vault secret acts as its raw UTF-16LE password bytes and unwraps the random
   stream key stored in `encryptedKeyValue`.

The password-key descriptor created by `CPasswordKeyEnc::HrSetPwd` at
`+0x2ffe18` is a separate `PeadCreateNew(0x40)` descriptor. `HrNewKeyMgr` at
`+0x38405c` copies parent descriptor flag bit 7 into the password encryptor;
the current `0x400003c0` flags have that bit set, so `HrSetPwd` explicitly
calls `FSetCSpin(0)`. Current XML therefore stores `spinCount = 0`. The XML
value remains authoritative when loading a non-default or older session.

## Password hash and field keys

Let `P` be the exact 64 secret bytes from `_vault`, `Rp` the 16-byte salt from
`p:encryptedKey`, and `N` its decimal `spinCount` attribute (zero in the
current Vault creation path):

```text
H = SHA512(Rp || P)
for i in 0 .. N-1:
    H = SHA512(LE32(i) || H)
```

`MsoHrComputePasswordHash` at `+0x273310` implements this prefix-counter mode.
It also supports a suffix-counter enum value, but the current
`HrComputeEncryptionKey` call at `+0x2fea2c` selects the prefix form.

`CCryptoObj::HrResetEx` at `+0x273a60` installs an eight-byte block key and
regenerates the CNG key. `HrGetKeyHashFromBlockKey` at `+0x2fdc20` computes:

```text
K(blockKey) = SHA512(H || blockKey)[0:32]
IVp         = Rp
```

The three exact block keys, expressed in their in-memory byte order, are:

| XML value | Block key |
|---|---|
| `encryptedVerifierHashInput` | `fe a7 d2 76 3b 4b 9e 79` |
| `encryptedVerifierHashValue` | `d7 aa 0f 6d 30 61 34 4e` |
| `encryptedKeyValue` | `14 6e 0b e7 ab ac d0 d6` |

`PadKey` at `+0x2fdd34` appends byte `0x36` only if the requested key is
longer than the digest. AES-256 needs 32 of SHA-512's 64 bytes, so it is a
straight truncation.

## Password verification and stream-key unwrap

The creation and unlock paths at `+0x2fd324`, `+0x2ffe18`, and `+0x2fef34`
are inverse operations:

```text
verifierInput = AES-256-CBC-Decrypt(
    K(fe a7 d2 76 3b 4b 9e 79), IVp,
    encryptedVerifierHashInput)

verifierHash = AES-256-CBC-Decrypt(
    K(d7 aa 0f 6d 30 61 34 4e), IVp,
    encryptedVerifierHashValue)

require verifierHash[0:64] == SHA512(verifierInput[0:16])

streamKey = AES-256-CBC-Decrypt(
    K(14 6e 0b e7 ab ac d0 d6), IVp,
    encryptedKeyValue)[0:32]
```

All CNG calls use flags `0`; the serialized values are already rounded to the
16-byte block size and no PKCS padding is added. `CCryptoKeyMgr::HrNewKeyMgr`
creates the 32-byte stream key from the secure random source. Consequently,
knowing the Vault secret and Crypto XML allows deterministic unwrap, but the
stream key is not simply a hash of the Vault secret.

## Per-operation IVs and AES operation

`keyData.saltValue` is the stream salt `Rs`, not a fixed content IV. With the
random-key-manager path active, `HrGenerateNextGenIV` at `+0x27367c` hashes
the salt and the block key installed by `CCryptoObj::HrReset`; it then takes
one AES block from the digest:

```text
IV(blockKey) = SHA512(Rs || blockKey)[0:16]
```

`CCryptoObj::HrReset(a, b)` at `+0x375790` passes `LE32(a)` alone to
`HrResetEx` when `b == 0`, and `LE32(a) || LE32(b)` otherwise. The block key is
therefore four bytes for shard 0. The resets around each protected shard were
verified on all 71 streams in the initial capture:

| Operation | Reset | Block key (shard 0) |
|---|---|---|
| content encrypt/decrypt | `(footer_salt, shard_index)` | `LE32(footer_salt)` |
| footer HMAC-key transform | `(0x0b511c03, shard_index)` | `LE32(0x0b511c03)` |
| HMAC value transform | `(0x033becab, shard_index)` | `LE32(0x033becab)` |

The two tag constants are initialized by `Syzygy::Integrity::Integrity` at
`+0x2fb2e4`. `Cipher::Append` and `Cipher::ReadBuffered` use the same content
reset.

The second argument of both tag resets is the shard index. The post-HMAC reset
encrypts the 64-byte HMAC before it is stored; the footer never contains a
plaintext HMAC.

The structure mirrors MS-OFFCRYPTO `dataIntegrity`, which uses separate block
keys for the HMAC key and the HMAC value, with 4-byte tags.

`CNGObj::HrCrypt` and `CNGObj::HrDecrypt` at `+0x273140` and `+0x273090`
call `BCryptEncrypt` and `BCryptDecrypt` in place with the unwrapped AES-256
stream key, the derived IV, and flags `0`. Syzygy supplies block-aligned data
by adding random inner padding at the protected-stream layer. The same random
stream key remains installed; reset changes the IV, not the key.

## Serialized v4 session and Crypto XML

`CSX::HrSave` at `+0x3058e0` and `HrSaveV4Stream` at `+0x305450` emit:

```text
uint16 session_version        = 4
uint16 compatibility_version  = 4
uint32 crypto_type            = 0x40
bytes  Crypto XML
```

The two uint16 values were verified directly at RVAs `0x7976b4` and
`0x79752c`. `MsoHrLoadCryptSession` (`+0x2fd0f0`) dispatches version 4 to
`HrLoadV4Stream` (`+0x2fe128`), which requires type `0x40` and parses the XML.
Version 2 is the legacy v3-stream fallback and version 1 selects Session1.

`HrSaveCryptoXml` at `+0x3049f8` writes the Office 2006 encryption namespace
and these current elements:

```text
encryption
├── keyData
│   ├── saltSize, blockSize, keyBits, hashSize
│   ├── cipherAlgorithm, cipherChaining, hashAlgorithm
│   └── saltValue                         # Base64
├── dataIntegrity                         # optional
│   ├── encryptedHmacKey                  # Base64
│   └── encryptedHmacValue                # Base64
└── keyEncryptors
    └── keyEncryptor uri=".../keyEncryptor/password"
        └── p:encryptedKey
            ├── spinCount
            ├── saltSize, blockSize, keyBits, hashSize
            ├── cipherAlgorithm, cipherChaining, hashAlgorithm
            ├── saltValue                 # Base64
            ├── encryptedVerifierHashInput
            ├── encryptedVerifierHashValue
            └── encryptedKeyValue
```

The writer and parser functions are at `+0x30594c`, `+0x304fe8`, `+0x41e008`,
`+0x2ff1a0`, `+0x2ff450`, `+0x41d408`, and `+0x41d868`. Certificate
key-encryptor elements are also supported by the generic XML loader, but the
current Vault path is password-based.

## Correspondence with MS-OFFCRYPTO Agile Encryption

Apart from the Syzygy-specific inputs listed below, this crypt session is the
public MS-OFFCRYPTO Agile Encryption scheme (§2.3.4.10–2.3.4.15). It is
implemented by Office's general-purpose document-encryption classes in
`mso20win32client.dll`.

Binary evidence from a direct Binary Ninja query: each block key is
passed to `CCryptoObj::HrReset` (vtable `+0x28`) as two imm32 arguments, low
half in `edx` and high half in `r8d`. Their little-endian concatenation is the
specification's byte string:

| MS-OFFCRYPTO block key | imm32 pair | Containing function (first imm32) |
|---|---|---|
| `encryptedVerifierHashInput` `fe a7 d2 76 3b 4b 9e 79` | `0x76d2a7fe, 0x799e4b3b` | `+0x2fd324` helper (`+0x2fd3b0`, `+0x2fd5eb`) |
| `encryptedVerifierHashValue` `d7 aa 0f 6d 30 61 34 4e` | `0x6d0faad7, 0x4e346130` | `+0x2fd324` helper (`+0x2fd4c9`) |
| `encryptedKeyValue` `14 6e 0b e7 ab ac d0 d6` | `0xe70b6e14, 0xd6d0acab` | `CPasswordKeyEnc::HrUnlock` (`+0x2ff0c2`), `HrSetPwd` (`+0x2fffb4`) |
| `dataIntegrity` HMAC key `5f b2 ad 01 0c b9 e1 f6` | `0x01adb25f, 0xf6e1b90c` | `CCryptoHmac::HrEncryptToParams` (`+0x306600`), `HrDecryptHmac` (`+0x532423`) |
| `dataIntegrity` HMAC value `a0 67 7f 02 b2 2c 84 33` | `0x027f67a0, 0x33842cb2` | same two functions (`+0x306642`, `+0x532467`) |

None of the five appears as a contiguous eight-byte string in the binary. A
search for the 8-byte form therefore misses all of them; search for the imm32
halves. `HrSetPwd` (`+0x2ffe18`) creates `PeadCreateNew(0x40)` and calls
`CMsoEad::FSetCSpin(.., 0)` when `this+0x18 == 1`, which is the spin-count-0
path described above.

Identical to the specification:

- the 8-byte header `uint16(4), uint16(4), uint32(0x40)`. This is the Agile
  `EncryptionVersionInfo` 4.4 header plus its reserved `0x40`, so
  `serialized_value` is an Agile `\EncryptionInfo` stream;
- the Crypto XML namespaces, `keyData`, `dataIntegrity`, and password
  `keyEncryptor` element grammar;
- `H0 = H(salt || password)`, `Hn = H(LE32(i) || Hn-1)`, and
  `K = H(Hn || blockKey)` truncated or `0x36`-padded (§2.3.4.11);
- IV = keyEncryptor salt for the key encryptor, and `H(keyDataSalt ||
  blockKey)` truncated or `0x36`-padded for data (§2.3.4.12);
- the verifier and `encryptedKeyValue` procedure and block keys (§2.3.4.13).

Syzygy-specific (the actual subject of this analysis):

- the "password" is the 64 random bytes of a `_vault` session record;
- spin count is `0` (specification examples use `100000`);
- the data block key is `Reset(footer_salt, shard_index)`: `LE32(footer_salt)`
  for shard 0 (live-verified) and `LE32(footer_salt) || LE32(shard_index)`
  for later shards (code). Shards are `0xff80` bytes, each with its own footer
  salt. The specification uses a 4-byte segment index over 4096-byte
  segments;
- integrity is the per-shard footer HMAC, not the XML `dataIntegrity` element:
  - key under `Reset(0x0b511c03, shard)`;
  - value encrypted under `Reset(0x033becab, shard)`;
  - input `LE32(salt) || LE32(shard) || ciphertext`.

  This was verified on 71/71 Gate-0 streams.

The parser now preserves optional `dataIntegrity` parameters and the helper
decrypts/verifies them with the two standard block keys. This remains separate
from the Syzygy footer HMAC used by protected streams.

The specification-identical portion can be checked independently with any
Agile implementation that accepts the same password bytes. The Syzygy-specific
reset keys, shard framing, and footer integrity still require the recovered
Office behavior and captured streams.

## Security and validation boundary

This derivation is not a provider bypass. The 64-byte wrapping secret resides
inside `_vault`, whose sessions blob may be protected by machine DPAPI,
enterprise data protection, IRM, or a stack of those providers. Without that
secret or the applicable platform state, brute force is not practical.

The captured personal-OneDrive vaults used `standard-dpapi-machine`. Offline
DPAPI unwrapped their sessions, every returned stream passed its footer HMAC,
and multi-shard AES-CBC decryption produced the document objects. In six
external comparisons, the rebuilt DOCX matched the OneDrive copy byte for byte.
