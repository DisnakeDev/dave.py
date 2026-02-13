# dave.py

<img src="https://img.shields.io/github/actions/workflow/status/DisnakeDev/dave.py/wheels.yml?branch=main&style=flat-square"></img>
<a href="https://pypi.org/project/dave.py/"><img src="https://img.shields.io/pypi/v/dave.py.svg?style=flat-square" alt="PyPI version info" /></a>
<a href="https://pypi.org/project/dave.py/"><img src="https://img.shields.io/pypi/pyversions/dave.py.svg?style=flat-square" alt="PyPI supported Python versions" /></a>

Python bindings for [libdave](https://github.com/discord/libdave), Discord's C++ DAVE[^1] protocol implementation.

See the [API docs](https://docs.discord.com/developers/topics/voice-connections#end-to-end-encryption-dave-protocol) for a general overview of the protocol, as well as https://daveprotocol.com/ for an in-depth protocol description.


## Installation

```sh
pip install dave.py
```

Prebuilt wheels for all platforms and many 64-bit architectures are available directly from PyPI (32-bit architectures are not supported).  
If you're missing wheels for any specific platform/architecture, feel free to open an issue!

To build from source, any PEP 517-compatible build frontend can be used, e.g. `python -m build`.
Note that building from source (or sdist) also requires `$VCPKG_ROOT` to point to a [vcpkg](https://github.com/microsoft/vcpkg) clone, as well as a lot of patience.


## Usage

This is currently primarily intended for https://github.com/DisnakeDev/disnake, though it is not targeting it in any way.  
Due to this, there isn't really any documentation to speak of right now. Sorry about that.


[^1]: *"Discord's audio & video end-to-end encryption"*
