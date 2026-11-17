# CacheWeave

CacheWeave recovers Word documents from the Microsoft Office Document Cache (ODC).

Give it a copied `OfficeFileCache` directory or a raw disk image. It follows cached revisions, authenticates encrypted streams, rebuilds the document when enough data survives, and writes a JSON report that shows where every result came from.

## Current scope

CacheWeave has been tested with URL-opened documents from OneDrive Personal on Office build `16.0.20527.20196`.

| Item | Tested setup |
|---|---|
| Platform | Windows x64 |
| Python | `3.13.1` |
| Office cache | Loose `.C4`, `.P`, and `e_*.R` files; `0.ARX` volumes |
| Dependencies | `cryptography 49.0.0`, `lz4 4.4.5`, `numpy 2.2.2` |

The code is currently at the `0.x` stage. Office build `16.0.20430.20182` has limited test coverage; SharePoint Online, OneDrive for Business, and other Office channels still need end-to-end testing.

## Research findings

On the tested build, the ODC behaves as a versioned object store. A document namespace preserves metadata, revision pointers, storage indexes, content objects, and cryptographic state across several files:

- `.C4` is an append-style cluster set containing document metadata, revision records, older generations, and the DPAPI-protected vault.
- `.P` files are dictionary piles that map revision and storage identifiers to content objects.
- `e_*.R` files are AES-256-CBC protected streams with per-shard HMAC-SHA512 authentication. CacheWeave does not use plaintext from a stream that fails authentication.
- When the `ArxEnabled` feature gate is active, the same logical `.P` and `.R` files are stored inside `0.ARX`. The loose-file and ARX layouts feed the same recovery pipeline.

The cache can retain several complete saved states, including older revisions and locally committed offline edits. CacheWeave follows explicit current-state pointers first, then storage-index snapshots and revision lineage when the normal chain is damaged. If the evidence conflicts, it leaves the state unresolved instead of choosing one. When a whole document cannot be rebuilt, independently authenticated parts can still be recovered.

### Evaluation results

| Experiment | Result |
|---|---|
| Initial OneDrive Personal capture | All 71 protected streams authenticated; the pre-edit and post-edit DOCX states were rebuilt from the cache |
| 17 synthetic damage scenarios | CacheWeave alone rebuilt the intended state in 5 scenarios; no wrong state or unsupported complete result was reported across 51 engine/scenario combinations |
| 24-document structural corpus | With the current revision manifest removed, CacheWeave recovered 24/24 intended states while both comparison paths recovered 0/24 |
| Live AutoSave workflows | All 8 stages were recovered in each completed AutoSave-on and AutoSave-off run, with two complete runs per mode |
| Two-device workflow | All 5 stages were recovered in both complete runs |
| Raw-image copy-and-delete cases | Of 12 scored runs, 1 yielded the complete document, 7 yielded the intended revision's verified text parts, and 4 yielded no document content |
| Independent DOCX comparison | 6/6 reconstructed files matched the OneDrive copies byte for byte, including one rebuilt only from carved disk data |

The original DOCX files used for the last comparison were evaluation data, not recovery input. Byte equality is therefore an experimental result, not a claim made by the JSON report.

### Recovery limits observed in the experiments

- The vault is a single point of failure. If its `.C4` data is lost and no session material was preserved separately, surviving content objects cannot be decrypted. Machine-DPAPI files can unlock a surviving vault; they cannot recreate a missing session secret.
- Office may delete an entire damaged namespace when Word opens it again and records a cache fault. Acquisition should happen before reopening the document.
- On the tested physical SSD, TRIM cleared deleted non-resident data before it could be carved. MFT-resident records survived until reuse.
- These results describe the tested Office builds and OneDrive Personal workflow. Other Office channels and account types can use different gates or cache behavior.

See the [research summary](docs/research-summary.md) for the full evaluation and the [documentation index](docs/README.md) for the recovered cache formats and Office internals.

## Install

Run these commands from the repository root in PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
$CacheWeave = ".\.venv\Scripts\cacheweave.exe"
```

## Choose an input

An Office cache is usually stored here:

```text
C:\Users\<user>\AppData\Local\Microsoft\Office\16.0\OfficeFileCache
```

A cache copy on its own is enough to list objects, metadata, and revisions. Decrypting document content also requires the machine-DPAPI files from the Windows installation that created the cache. With a raw image and those keys, CacheWeave can carve deleted cache records before running the same recovery path.

Analyze a copy or a read-only image. Keep the output in a separate directory.

## Recover a copied cache

If you only have the cache, start with a structure-only report:

```powershell
& $CacheWeave recover "D:\case\OfficeFileCache" `
  --key-source none `
  --report "D:\case\reports\cacheweave.json"
```

For full recovery, point `offline:` at the root of the matching Windows volume. CacheWeave reads the `SYSTEM` and `SECURITY` hives and the machine master keys under `Windows\System32\Microsoft\Protect\S-1-5-18`.

```powershell
& $CacheWeave recover "D:\case\OfficeFileCache" `
  --key-source "offline:E:\mounted-windows" `
  --out "D:\case\recovered" `
  --report "D:\case\reports\cacheweave.json"
```

`--out` and `--report` must point outside the input cache.

## Carve a disk image

The carver accepts a raw image or an unallocated-space extract. It writes a synthetic cache tree that `odc_recover.py` can read.

```powershell
& $CacheWeave carve "D:\case\disk.raw" `
  --key-source "offline:E:\mounted-windows" `
  --out "D:\case\carved" `
  --report "D:\case\reports\carve.json"

& $CacheWeave recover "D:\case\carved\OfficeFileCache" `
  --key-source "offline:E:\mounted-windows" `
  --out "D:\case\recovered-from-image" `
  --report "D:\case\reports\recovered-from-image.json"
```

The carve output directory must be new. Convert a dynamic VHDX to raw or fixed VHD before running the carver.

## Read the report

The JSON report records the cache inventory, key lookup, stream authentication, revision candidates, recovered parts, output paths, and the evidence used to choose a document state.

The main states are:

- `ok`: parsing and authentication succeeded.
- `hmac_fail`: stream authentication failed; CacheWeave discards the plaintext.
- `no_key`: the object was found, but its key was unavailable.
- `selected`: the surviving evidence points to one document state.
- `ambiguous`: more than one state fits the evidence.
- `undetermined`: the cache no longer contains enough evidence to choose a state.
- `partial`: some document parts are missing.

Treat a reconstruction as complete only when its status is `complete_candidate` and `zip.crc_ok` is `true`. A whole-document reconstruction is reported as `complete_candidate`; verified parts recovered separately are listed under `salvaged_parts`.

## Options

Most runs use `--key-source none` or `--key-source offline:<Windows-root>`. You can also supply the registry hives and master-key directory separately:

```text
offline-files:system=<SYSTEM>,security=<SECURITY>,masterkeys=<S-1-5-18 directory>
```

The `live`, `live-export:`, and `sessions:` providers are development options. Exported session files contain document keys and should be handled like other sensitive evidence.

The default recovery mode is `cw`. Modes `b2` and `b3` are comparison baselines used by the project experiments.

## Limits

- Cache formats change between Office builds. Record the exact build with each case.
- Plaintext recovery normally depends on machine-DPAPI material from the original Windows installation.
- SSD TRIM and later writes can remove deleted or aged-out cache records.
- ARX recovery has fewer real-world samples than loose-cache recovery.
- Output collision handling and uncommon damaged ZIP cases still need more testing.

## Data handling

ODC caches, registry hives, DPAPI master keys, session exports, and recovered documents may contain private data. Hash the acquired input, keep an untouched original, and use CacheWeave only on data you are allowed to examine.

## Code map

```text
src/cacheweave/
  cli.py              `cacheweave recover` and `cacheweave carve`
  odc_recover.py      cache recovery pipeline
  odc_carve.py        raw-image carver
  formats/            ARX, Terse, KVTree, and FSSHTTP codecs
  crypto/             DPAPI and protected-stream handling
  odc/                ODC cache structures
```

Raw research notes, captures, binaries, keys, experiment records, and test artifacts stay outside the distribution.
