# bicycl-rs-sys

Low-level Rust FFI bindings for the BICYCL C API.
- `vendored` (default): build bundled C API and vendored upstream headers with CMake
- `system`: link against prebuilt `bicycl_capi`

## Build

Vendored mode:

```bash
cargo build -p bicycl-rs-sys
```

System mode:

```bash
cargo build -p bicycl-rs-sys --no-default-features --features system
```

Optional env vars in `system` mode:

- `BICYCL_CAPI_LIB_DIR`
- `BICYCL_DEP_LIB_DIR`
- `BICYCL_CAPI_LIB_NAME` (default: `bicycl_capi`)
- `BICYCL_CAPI_LINK_KIND` (`static` or `dylib`, default: `static`)
- `BICYCL_CPP_RUNTIME_LIB_NAME` / `BICYCL_CPP_RUNTIME_LINK_KIND`
- `BICYCL_GMPXX_LIB_NAME` / `BICYCL_GMPXX_LINK_KIND`
- `BICYCL_GMP_LIB_NAME` / `BICYCL_GMP_LINK_KIND`
- `BICYCL_CRYPTO_LIB_NAME` / `BICYCL_CRYPTO_LINK_KIND`

## License

`GPL-3.0-or-later`.
