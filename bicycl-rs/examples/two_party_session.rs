use bicycl_rs::Context;

fn main() -> Result<(), bicycl_rs::Error> {
    let mut ctx = Context::new()?;
    let mut rng = ctx.randgen_from_seed_decimal("1337")?;

    let mut session = ctx.two_party_ecdsa_session(&mut rng, 112)?;
    session.keygen_round1(&mut ctx, &mut rng)?;
    session.keygen_round2(&mut ctx, &mut rng)?;
    session.keygen_round3(&mut ctx, &mut rng)?;
    session.keygen_round4(&mut ctx)?;

    session.sign_round1(&mut ctx, &mut rng, b"abc")?;
    session.sign_round2(&mut ctx, &mut rng)?;
    session.sign_round3(&mut ctx)?;
    session.sign_round4(&mut ctx, &mut rng)?;

    let valid = session.sign_finalize(&mut ctx)?;
    println!("signature_valid={valid}");
    Ok(())
}
