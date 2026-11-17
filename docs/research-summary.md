# Research summary

CacheWeave came out of a study of how Word stores OneDrive documents in the Office Document Cache (ODC), and of what can still be recovered after the cache is damaged. This page summarizes the findings and the evaluation. The format and behavior details are in [`internals/`](internals/).

## Scope

| Item | Setup |
|---|---|
| Application | Word, Office `16.0.20527.20196` x64, Current Channel (updates turned off in the lab VM) |
| Operating system | Windows 11 Pro 26200, NTFS (4 KiB clusters, 1 KiB MFT records) |
| Documents | Personal OneDrive documents opened by URL in desktop Word. The account had no Microsoft 365 plan, so documents were saved to the cloud only |
| Cache format | Loose `.C4`, `.P`, and `e_*.R` files; `0.ARX` volumes when a feature gate is on |
| Second build | `16.0.20430.20182` passed the P2 scenario once with AutoSave off and once with it on |

OneDrive for Business, SharePoint Online, and IRM-protected documents were not tested.

The engine works from three input levels:

- **C0:** a copy of the cache taken after the incident.
- **C1:** C0 plus the machine-DPAPI material from the same disk: the `SYSTEM` and `SECURITY` hives and the `S-1-5-18` master keys.
- **C2:** C1 plus an image of the same volume, for carving.

The engine never uses the original DOCX, pre-incident snapshots, server downloads, cloud lookups, or RAM. The ground truth (the text Word showed at each save) is stored separately and used only by the scorer.

## How Word stores a document

- **One folder per document.** Each document gets a namespace folder: `OfficeFileCache\0\<generation>\<namespace-id>\`. The folder name is the document's 16-byte ID in Office's own Base32 variant. Each byte becomes two characters, low bits first, and the whole string is reversed.
- **Three file types.**
  - `.C4` is a log of resident properties. It holds `DocumentMetadata`, the storage revisions, an audit log, and the key vault.
  - `.P` is a dictionary pile. It lists the data elements of one revision.
  - `e_<id>.R` is a protected stream. Its name is the Base32 form of `SpookyHash128(plaintext)`, so a renamed file can be identified again by its content.
- **No DOCX on disk.** Word stores the document as MS-FSSHTTPB data elements and MS-FSSHTTPD chunks, the same objects it exchanges with the server. A DOCX has to be reassembled from them.
- **Old saves remain.** Every save commits a new revision, and the objects of earlier revisions stay. Several saved states of a document can therefore be rebuilt. Storage Index snapshots and sequence numbers give their order.
- **`0.ARX` volumes.** When the feature gate `Microsoft.Office.FileIO.ArxEnabled` is on, the same files are stored inside a `0.ARX` volume in the namespace folder. The volume has 4 KiB blocks, a superblock, an allocator, a hash directory, and bucket file indexes. The gate is off by default. The lab account's cached feature gates (600 FileIO entries) did not include it. A local override turned it on, and Word then saved new documents into a volume.
- **Older tools do not apply.** Published ODC tools read `FSD`/`FSF` files and `CentralTable.accdb`. None of these files appeared in this build's caches.

## Keys

- **Machine DPAPI.** The vault in the `.C4` file is protected with machine-scope DPAPI (`dwFlags = 0x4`, master keys under `S-1-5-18`). It opens offline with the `SYSTEM` and `SECURITY` hives and those master keys. No user password is needed; all four master keys captured in the lab worked.
- **Encryption.** The vault holds Agile-4.4-style crypt sessions. Each protected stream is encrypted with AES-256-CBC in shards of `0xFF80` bytes. Each shard has a `0x80`-byte footer with an HMAC-SHA512 tag.
- **One in-cache copy of the keys.** In an ordinary cache, the vault exists only in the document's `.C4` file. If it is lost and no session material was preserved separately, the content cannot be decrypted even when every content stream survives. This is the format's single point of failure.

## What survives damage

The ransomware-like test (R3) wrote an encrypted `.locked` copy of every cache file, deleted the original, and then imaged the 64 GB system disk.

- **Large blobs.** Non-resident blobs stay in unallocated clusters until they are overwritten or trimmed.
- **Small blobs.** Blobs small enough to live inside an MFT record (up to 542 bytes on the test volume) survive only until that record is reused. The root object of every revision is 287 to 542 bytes, so roots were resident in all six measured namespaces.
- **MFT record reuse.** In a controlled test, NTFS gave a new file the lowest-numbered free MFT record. Whether encrypted copies took over the originals' records depended on how many lower free records existed just before the damage. During each Word session, Office unpacked a web resource package (`SolutionPackages\…\OfflineFiles`) into thousands of files, consuming the low free records first. Replaying the damage with that allocation rule reproduced the reuse counts of two images: 155 and 67 predicted, 166 and 67 observed.
- **TRIM on an SSD.** On a real NVMe SSD with TRIM on, deleted files read back as zeros before acquisition. Carving could not bring back non-resident cache files on that disk. MFT-resident files were not affected because no clusters were freed.
- **TRIM inside Hyper-V.** A dynamic VHDX released only whole 32 MiB blocks, so small cache files survived inside the VM.

## When Office deletes its own cache

- **Age-out.** `AgeOutPolicy` removes documents that have passed the configured retention threshold. The maintenance gate runs when the file cache starts, and a debugger showed the same removal branch as the static analysis.
- **`DisableLongTermCaching`.** When it is set to 1, a document's cache is deleted when the document is closed (2 of 2 runs).
- **Where the settings come from.** Office reads these values from the cloud policy key first, then the Group Policy key (`HKCU\Software\Policies\Microsoft\Office\16.0\Common\FileIO`), then the user key. This build has no code path that writes them, so they come only from the registry.
- **Pending uploads survive.** Documents with an upload still pending survived age-out. Word keeps them open to retry the upload, and the cleanup scan skips open files before judging their age (debugger, two runs).
- **Recovering after a cleanup.** Prompt acquisition preserved one deleted document well enough for an exact carved recovery. In two acquisitions made after further system activity, the vault had been overwritten and nothing was recovered.
- **Deletion after a fault.** When Word cannot read a blob, the revision graph raises a fault. Office records it in `OfficeFileCache\odc.faults` and ends the Word process. At the next file-cache start, Office deletes that document's cache. This was observed in three lab runs; in two of them the vault and most blobs were still intact before deletion.

## Unsynced edits

- **Offline saves.** A save made while offline stays in the cache as a local commit, and the engine selected it correctly (P2 scenario S5).
- **Conflicts.** In the conflict test, an unsynced local commit met a save from another device. Word merged the two edits without showing a conflict dialog. The cache kept the local commit, the other device's version, and the merged state as complete revisions.
- **The `UnresolvedUpload` flag.** This metadata flag is set when an upload starts and cleared when it finishes (debugger, four attempts). It never reached the disk in five deliberately interrupted uploads.
- **The lasting record.** What stays on disk is the branch columns. A pending document has its upload branch equal to its working branch and an older base branch. All 242 lab namespaces were in one of two states: settled (200) or not confirmed (42). The engine reports this as `upload_state` and does not use it to select a revision.

## Recovery method

The engine runs the same stages for every input:

1. **Carving (C2 only).** The carver reads the image once in fixed-size chunks and finds cluster-set records and protected-stream footers. It also finds `0.ARX` volumes. A protected stream has no header, so each candidate start is tried and accepted only when the shard HMAC verifies. Overwritten or foreign bytes cannot be stitched in.
2. **Keys.** Machine DPAPI is opened offline, then the vault, then the crypt sessions.
3. **Inventory.** Every file in the cache tree and every file inside a `0.ARX` volume is listed and classified by content, not by name. This includes files whose volume index records were deleted.
4. **Decryption and authentication.** Each shard is decrypted and authenticated, and each name is checked against the content hash. Every blob gets a trust tier.
5. **Revision reconstruction.** Each revision is rebuilt from its object groups and checked with chunk signatures and ZIP CRCs. When the normal links are broken, the engine (CW) also uses Storage Index snapshots and the hierarchy records Office writes at each commit. As a last step, it can regroup a revision whose manifest was lost, but only within one pile's object-group set.
6. **Target selection.** The saved state is chosen by evidence grade:
   - A: explicit current-state pointers.
   - B: the latest Storage Index snapshot.
   - C: the group-reuse lineage.

   Conflicting evidence leads to a refusal (`ambiguous`), not a guess. "The revision with the most content" is never used as a rule.
7. **Partial recovery and report.** When the named revision cannot be rebuilt whole, its verified parts are written separately. The JSON report records where every output came from.

Two baselines get the same input:

- **B2** follows only the normal path: native names and intact links.
- **B3** receives the same structure scan but none of CW's structural inference.

## Evaluation

What counts as "exact" depends on the test:

- **Synthetic tests:** byte-exact means the same SHA-256 as the undamaged cache rebuilt by CW.
- **Corpus tests:** exact means the body text matches the ground truth.
- **Lab tests:** exact means the SHA-256 of Word's displayed text (control characters below U+0020 removed) equals the SHA-256 of the rebuilt DOCX's text under the same rule. Word re-serializes documents on cloud save, so the lab compares text, not bytes. A state that was not selected never counts as exact, even when its text matches.

### Synthetic damage

17 scenarios, each run through B2, B3, and CW.

These synthetic cases used a separately exported session-key file. They test reconstruction after structural damage, not whether the vault survives that damage.

- B3 recovers pile loss and renamed files.
- CW alone restored the target byte-exactly in five scenarios: three kinds of current-manifest loss, metadata plus pile loss solved by a snapshot (grade B), and the same solved by lineage (grade C).
- CW refused in two scenarios, where the named revision could not be rebuilt or a newer revision was proven to exist.
- No method restored the whole document after full `.C4` encryption, 50 % `.R` loss, or intermittent encryption. With 50 % `.R` loss, CW still produced seven verified parts, including the current `document.xml`.
- No wrong selection and no false completion in 51 method-scenario pairs.

### Live corpus (P5, 24 documents)

- With intact input and keys (C1), every document was recovered exactly.
- Six damage types over 144 cases left content in 49 % of the cases. CW and B3 recovered 49 %, B2 recovered 15 %. Where content remained, CW was always exact. There were no wrong selections and no false completions.
- Twelve multi-shard streams (up to five shards) were rebuilt and authenticated. Their images matched the originals byte for byte.
- Current-manifest loss: B2 and B3 recovered nothing; CW recovered 24 of 24. CW also recovered 24 of 24 when the piles were removed, and again when the hierarchy records were removed with them. The `.C4` vault remained intact in all three cases.
- Metadata plus pile loss: the damage rule overwrote the first 20 KiB of `.C4`, which removed the vault as well as the metadata, and also damaged every pile. The external `SYSTEM`, `SECURITY`, and `S-1-5-18` files could open DPAPI but could not recreate the missing session secret. Key and content survival were both 0 of 24, so no method recovered a document. Removing the latest snapshot as well produced the same result.

### Hyper-V lab

A Hyper-V VM played the victim PC. Word was scripted inside it. At each step the cache and the C1 key material were acquired and then analyzed offline on the host. Each experiment started from a checkpoint with a newly created document, so step S0 had nothing of it in the cache.

| Experiment | Runs | Result |
|---|---|---|
| P2 usage steps S0–S7, AutoSave off | 2 | 8/8, 8/8 |
| P2 usage steps S0–S7, AutoSave on | 2 | 8/8, 8/8 (two more runs stopped early; every step they reached was exact) |
| Two devices, cache one save behind the cloud, T0–T4 | 2 | 5/5, 5/5 (one more run stopped by a lab problem; its T0 was exact) |
| Conflict: unsynced local commit plus a save on another device | 1 | 4/4 |
| R4 renames only, Word running | 4 | The state saved after the damage was restored exactly by CW and by B0 (reopening the document in Word) |
| R4 light damage (about 20 % of `.R` encrypted), Word running | 2 | Word recorded a fault and exited. CW refused to select (ambiguous). When Word next started, Office deleted the document's cache |
| R4 default damage (`.R` encrypted, first 4 KiB of `.C4`, `.P` renamed) | 5 | Undetermined in all five: the key material was lost. Word recorded a fault and exited each time, and B0 recovered nothing |
| R3 copy-then-delete, carved from a 64 GB image | 12 | 1 fully exact (B3 the same), 7 partial recoveries by CW only, 4 with no body text |
| Office's own cleanup (`close` and `age`), carved | 20 | Deleted documents were recovered only when the disk was acquired within minutes. Surviving documents were restored exactly |
| `0.ARX` volume, feature gate on | 2 | The undamaged sample was recovered exactly by B2, B3, and CW. In the seven-save sample, old bucket copies in freed blocks listed 81 deleted files by name and location; 71 of 75 protected streams authenticated, and the selected state remained exact. |

In the R3 runs, the 7 partial recoveries returned the exact body text of the named revision. One of them was an offline save that never reached the cloud. Of the 4 runs with no body text, one lost the document's vault, and one had the tail of its `0.ARX` volume overwritten.

### Byte comparison with OneDrive's file

The DOCX rebuilt by the engine was compared directly with the file OneDrive serves for the same document. All 6 comparisons were byte-identical: same SHA-256, same ZIP entry order. One of the six was rebuilt from disk carving alone after R3 damage. A separate cross-device check (one run) produced the same bytes from the saving device's cache and from a second device's cache.

### Selection safety

- **No wrong selections.** Across every scored step and run (synthetic, corpus, and lab), the engine never selected a wrong state and never marked an incomplete document as complete.
- **The lineage rule (grade C).** It was checked against 242 lab selections made with grade-A evidence. It agreed or stayed silent every time: 91 times it named the answer, 7 times a set that included the answer, and 144 times it was silent. In all 25 cases where grade C alone decided, the result was correct.

## Limits

- **One build.** The results cover one Office build (and one more for P2 only) and personal OneDrive.
- **Single point of failure.** Without the vault in `.C4` or session material preserved separately, surviving content streams cannot be decrypted.
- **SSD TRIM** can zero deleted non-resident files before acquisition.
- **MFT reuse.** Small blobs depend on whether their MFT records are reused.
- **Office's own deletions.** Office deletes a faulted document's cache at the next start, and it deletes aged-out documents on its own schedule.
- **Document identity.** Without `DocumentMetadata`, a recovered state cannot be tied to a document URL. Only the namespace ID remains.
- **Small samples.** Several results rest on few runs: `0.ARX` (2), conflict (1), byte comparison (6).

## Acquisition notes

- **Copy before reopening Word.** Copy the cache before Word starts again. After a fault, Office deletes the affected document at the next start, and `odc.faults` shows which documents are marked.
- **Collect the key material.** Take the `SYSTEM` and `SECURITY` hives and the `S-1-5-18` master keys from the same installation.
- **Defender and `reg save`.** In the lab, Defender blocked a PowerShell-started `reg save HKLM\SECURITY`. Its signatures flagged the command as `Trojan:Win32/Commando.B!ml`. The same save through `cmd.exe`, or a copy from a VSS snapshot, worked.
- **BitLocker.** Imaging a BitLocker volume needs its recovery key. Two lab runs carved normally from the decrypted volume.
- **Image quickly.** On an SSD with TRIM on, image as soon as possible. Deleted cache files may already read as zeros.

## Open questions

The ZipParts pile model exists in the binaries but is not used on the personal-OneDrive path of this build, so its details were not studied.
