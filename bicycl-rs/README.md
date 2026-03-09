# bicycl-rs

Safe Rust wrapper for the BICYCL C API.
- `vendored` (default): build bundled C API via `bicycl-rs-sys`
- `system`: link against prebuilt `bicycl_capi`

## Build

Default mode:

```bash
cargo build -p bicycl-rs
```

System mode:

```bash
cargo build -p bicycl-rs --no-default-features --features system
```

## Example

```bash
cargo run -p bicycl-rs --example paillier_roundtrip
```

## License

`GPL-3.0-or-later`.
