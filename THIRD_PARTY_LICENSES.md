# Third-Party Licenses

kl-scan is distributed under AGPL-3.0 (see `LICENSE`). The combined work
includes the following third-party components:

## Detection engines

### betterleaks
- **Repository:** https://github.com/betterleaks/betterleaks
- **License:** MIT
- **Usage:** Imported as a Go library to provide secret-scanning rules
  and the per-line `DetectString` API. See
  `internal/detect/betterleaks/`.

### Trufflehog
- **Repository:** https://github.com/trufflesecurity/trufflehog
- **License:** AGPL-3.0
- **Usage:** Imported as a Go library for its detector set
  (`pkg/detectors`, `pkg/engine/defaults`), Aho-Corasick keyword
  prefilter (`pkg/engine/ahocorasick`), and decoder set (`pkg/decoders`,
  excluding HTML). See `internal/detect/trufflehog/`.
- **Note:** kl-scan never invokes Trufflehog's verification (live API
  validation) functionality. Every call to `Detector.FromData` passes
  `verify=false` as a hardcoded literal.

The use of Trufflehog (AGPL-3.0) is the reason this project as a whole
is distributed under AGPL-3.0. If you redistribute or operate kl-scan
as a network service, you must comply with AGPL-3.0 §13.

## Other notable dependencies

The full transitive dependency list is captured in `go.sum`. 

License texts for transitive dependencies can be retrieved via
`go-licenses` or by inspecting the modules in `$GOPATH/pkg/mod/`.
