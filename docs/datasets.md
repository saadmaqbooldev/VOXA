# Dataset provenance

Per roadmap Chunk 1.1. One entry per dataset file. Never commit the raw data itself —
`data/raw/` is gitignored.

## BODMAS

- **Source:** Blue Hexagon + UIUC, requested via institutional access request.
- **Project page:** https://whyisyoung.github.io/BODMAS/
- **Repository:** https://github.com/whyisyoung/BODMAS
- **Access status:** Granted 2026-09-21.
- **Licence:** _(fill in from the access agreement once files are downloaded)_
- **Citation:** _(BibTeX from the BODMAS paper, DLS'21)_
- **Retrieval date:** _(pending download)_
- **Files retrieved:** _(list filenames)_
- **Checksums (SHA-256):** _(one per file)_
- **Contents:** feature vectors (EMBER-format, 2381-dim) + family labels + SHA-256 hashes for
  57,293 malware and 77,142 benign Windows PE samples.

## EMBER

- **Source:** Elastic, public download, no access request required.
- **Repository:** https://github.com/elastic/ember
- **Access status:** Public; view access confirmed 2026-09-21, download not yet run.
- **Licence:** _(check elastic/ember LICENSE at download time)_
- **Citation:** _(BibTeX from the EMBER paper)_
- **Retrieval date:** _(pending download)_
- **Download URL used:** _(e.g. https://ember.elastic.co/ember_dataset_2018_2.tar.bz2)_
- **Checksum (SHA-256):** _(from the download)_
- **Contents:** pre-computed feature vectors (not raw binaries) from ~1M PE files scanned in
  or before 2018.

## Ransomware label derivation

See `docs/family_mapping.md` (to be written alongside this) for the exact BODMAS
family-name allow-list used to derive the ransomware subset, per A-4 in the roadmap:
BODMAS family labels are metadata for generalisation testing, not the deployed model's
training target — the deployed model is binary (ransomware vs benign).
