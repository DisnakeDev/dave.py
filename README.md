# libdave.py

> [!CAUTION]
> This is still very WIP and should not be used in production code.

## First setup

1. Clone the repository:

    ```sh
    git clone --recurse-submodules https://github.com/DisnakeDev/libdave.py
    cd libdave.py
    ```

    If you already cloned, use the following command to get the submodules:

    ```sh
    git submodule update --init --recursive
    ```

2. Bootstrap vcpkg:

   ```sh
   $ libdave/cpp/vcpkg/bootstrap-vcpkg.bat  # Windows
   # or
   $ ./libdave/cpp/vcpkg/bootstrap-vcpkg.sh  # mac OS/Linux
   ```

3. Install Python dependencies:

    ```sh
    $ uv sync --all-groups
    ```

## How to build

To perform a one-time build, simply run:

```sh
pip install .
```

You can also use any pep517-518 compatiable frontend.

For development, consider incremental builds instead;
this avoids pip recreating a new build environment from scratch every time:

```sh
pip install --no-build-isolation -ve .
```

To make development even more seamless, you can optionally have the extension be built automatically whenever the package is imported:

```sh
pip install --no-build-isolation -Ceditable.rebuild=true -ve .
```


### Creating a wheel
To create a built wheel relatively easily, e.g. for testing in another project:
```sh
pip wheel .
```
