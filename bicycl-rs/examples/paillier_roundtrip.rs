use bicycl_rs::Context;

fn main() -> Result<(), bicycl_rs::Error> {
    let mut ctx = Context::new()?;
    let mut rng = ctx.randgen_from_seed_decimal("1337")?;

    let paillier = ctx.paillier(64)?;
    let (sk, pk) = paillier.keygen(&mut ctx, &mut rng)?;
    let ct = paillier.encrypt_decimal(&mut ctx, &pk, &mut rng, "42")?;
    let clear = paillier.decrypt_decimal(&mut ctx, &pk, &sk, &ct)?;

    println!("decrypted={clear}");
    Ok(())
}
