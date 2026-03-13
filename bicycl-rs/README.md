# bicycl-rs

Safe Rust bindings for the [BICYCL](https://github.com/Jiangjiang-jiang/bicycl) cryptographic library. All wrapper types
are `!Send + !Sync` since the underlying C library is not thread-safe.

## Requirements

- **CMake** >= 3.16
- **GMP**: `libgmp-dev`, `gmp-devel`
- **OpenSSL**: `libssl-dev`, `openssl-devel`
- A C++11-capable compiler

## Usage

```toml
[dependencies]
bicycl-rs = "0.1"
```

```rust
use bicycl_rs::{Context, Error};

fn main() -> Result<(), Error> {
    let ctx = Context::new()?;
    let mut rng = ctx.randgen_from_seed_decimal("12345")?;
    let paillier = ctx.paillier(512)?;
    let (sk, pk) = paillier.keygen(&ctx, &mut rng)?;
    let ct = paillier.encrypt_decimal(&ctx, &pk, &mut rng, "42")?;
    let plain = paillier.decrypt_decimal(&ctx, &pk, &sk, &ct)?;
    assert_eq!(plain, "42");
    Ok(())
}
```

## License

`GPL-3.0-or-later`.
