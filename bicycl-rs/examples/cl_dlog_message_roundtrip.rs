use bicycl_rs::{ClDlogMessage, Context};

fn main() -> Result<(), bicycl_rs::Error> {
    let mut ctx = Context::new()?;
    let mut rng = ctx.randgen_from_seed_decimal("1337")?;

    let mut prover = ctx.cl_dlog_session(&mut rng, 112)?;
    prover.prepare_statement(&mut ctx, &mut rng)?;
    prover.prove_round(&mut ctx, &mut rng)?;

    let mut stmt = ClDlogMessage::new()?;
    let mut proof = ClDlogMessage::new()?;
    prover.export_statement(&mut ctx, &mut stmt)?;
    prover.export_proof(&mut ctx, &mut proof)?;

    let stmt_bytes = stmt.to_bytes(&mut ctx)?;
    let proof_bytes = proof.to_bytes(&mut ctx)?;

    let mut stmt_rx = ClDlogMessage::new()?;
    let mut proof_rx = ClDlogMessage::new()?;
    stmt_rx.from_bytes(&mut ctx, &stmt_bytes)?;
    proof_rx.from_bytes(&mut ctx, &proof_bytes)?;

    let mut verifier = ctx.cl_dlog_session(&mut rng, 112)?;
    verifier.import_statement(&mut ctx, &stmt_rx)?;
    verifier.import_proof(&mut ctx, &proof_rx)?;

    let valid = verifier.verify_round(&mut ctx)?;
    println!("proof_valid={valid}");
    Ok(())
}
