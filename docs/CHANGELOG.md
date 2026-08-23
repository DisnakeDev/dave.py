# Changelog

## [unreleased]

#### Bugfixes
- Handle potential errors in `Session.get_pairwise_fingerprint` caused by the event loop being closed
- Use `asyncio.get_event_loop().create_future()` instead of `asyncio.Future()` in `Session.get_pairwise_fingerprint()`


## 1.0.0 (2026-08-13)

#### Breaking changes
- Drop support for Python 3.9
- Methods that previously returned an empty bytes object (`b''`) on failure now return `None` in such cases. This applies to:
    - `Session.get_last_epoch_authenticator() -> bytes | None`
    - `Session.get_marshalled_key_package() -> bytes | None`
    - `Session.get_pairwise_fingerprint() -> asyncio.Future[bytes | None]`


## 0.2.0 (2026-08-08)

#### Features
- Support Python 3.15
- Add `dave.__version__` attribute

#### Miscellaneous
- Update to nanobind v2.14.0, speeding up method calls by ~20-50%


## 0.1.2 (2026-03-09)

#### Bugfixes
- [windows] Link msvc runtime statically instead of dynamically, which avoids having to install a newer vcredist manually under certain circumstances


## 0.1.1 (2026-02-19)

#### Bugfixes
- Emit `LS_INFO` logs from libdave as `logging.DEBUG` logs instead, due to their verbosity
- Change logger name to `dave`


## 0.1.0 (2026-02-16)

- Initial release
