> [!NOTE]
> this is still very wip.

## First setup

1. Clone the repository:
    ```sh
    $ git clone --recurse-submodules https://github.com/DisnakeDev/libdave.py
    $ cd libdave.py
    ```
2. Bootstrap vcpkg:
    ```sh
    $ libdave/cpp/vcpkg/.bootstrap-vcpkg.bat  # Windows
    # or
    $ ./libdave/cpp/vcpkg/.bootstrap-vcpkg.sh  # mac OS/Linux
    ```
3. Install Python dependencies:
    ```sh
    # (optional: consider creating a venv beforehand)
    $ pip install nanobind scikit-build-core[pyproject]
    ```

## How to build

To perform a one-time build, simply run:
```sh
$ pip install .
```

For development, consider incremental builds instead;
this avoids pip recreating a new build environment from scratch every time:
```sh
$ pip install --no-build-isolation -ve .
```

To make development even more seamless, you can optionally have the extension be built automatically whenever the package is imported:
```sh
$ pip install --no-build-isolation -Ceditable.rebuild=true -ve .
```
