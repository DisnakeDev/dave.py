# Changelog

## [unreleased]

- Update to nanobind v2.13.0, speeding up method calls by ~20-50%
- Add `dave.__version__` attribute
- Support Python 3.15

## 0.1.2 (2026-03-09)

- [windows] Link msvc runtime statically instead of dynamically, which avoids having to install a newer vcredist manually under certain circumstances

## 0.1.1 (2026-02-19)

- Emit `LS_INFO` logs from libdave as `logging.DEBUG` logs instead, due to their verbosity
- Change logger name to `dave`

## 0.1.0 (2026-02-16)

- Initial release
