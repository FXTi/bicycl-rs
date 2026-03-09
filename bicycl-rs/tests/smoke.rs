use bicycl_rs::{
    abi_version, cl_dlog_proof_run_demo, cl_threshold_run_demo, threshold_ecdsa_run_demo,
    two_party_ecdsa_run_demo, version, ClDlogMessage, Context,
};

fn mod_decimal(value: i64, modulus: i64) -> String {
    value.rem_euclid(modulus).to_string()
}

#[test]
fn smoke_safe_api() {
    assert_eq!(abi_version(), bicycl_rs_sys::BICYCL_CAPI_VERSION);
    assert!(!version().is_empty());

    let mut ctx = Context::new().expect("context init should succeed");
    assert_eq!(ctx.last_error(), "");

    let mut rng = ctx.randgen_from_seed_decimal("1337").unwrap();
    let cg = ctx.classgroup_from_discriminant_decimal("-23").unwrap();
    let one = cg.one(&mut ctx).unwrap();
    assert!(one.is_one(&mut ctx).unwrap());
    assert_eq!(one.discriminant_decimal(&mut ctx).unwrap(), "-23");

    let paillier = ctx.paillier(64).unwrap();
    let (sk, pk) = paillier.keygen(&mut ctx, &mut rng).unwrap();
    let ct = paillier
        .encrypt_decimal(&mut ctx, &pk, &mut rng, "42")
        .unwrap();
    let clear = paillier.decrypt_decimal(&mut ctx, &pk, &sk, &ct).unwrap();
    assert_eq!(clear, "42");

    let jl = ctx.joye_libert(64, 8).unwrap();
    let (jl_sk, jl_pk) = jl.keygen(&mut ctx, &mut rng).unwrap();
    let jl_ct = jl.encrypt_decimal(&mut ctx, &jl_pk, &mut rng, "7").unwrap();
    let jl_clear = jl.decrypt_decimal(&mut ctx, &jl_sk, &jl_ct).unwrap();
    assert_eq!(jl_clear, "7");

    let cl = ctx.cl_hsmqk("3", 1, "5").unwrap();
    let (cl_sk, cl_pk) = cl.keygen(&mut ctx, &mut rng).unwrap();
    let cl_ct = cl.encrypt_decimal(&mut ctx, &cl_pk, &mut rng, "2").unwrap();
    let cl_clear = cl.decrypt_decimal(&mut ctx, &cl_sk, &cl_ct).unwrap();
    assert_eq!(cl_clear, "2");

    let cl_ct_add = cl
        .add_ciphertexts(&mut ctx, &cl_pk, &mut rng, &cl_ct, &cl_ct)
        .unwrap();
    assert_eq!(
        cl.decrypt_decimal(&mut ctx, &cl_sk, &cl_ct_add).unwrap(),
        "1"
    );

    let cl_ct_scal = cl
        .scal_ciphertext_decimal(&mut ctx, &cl_pk, &mut rng, &cl_ct, "3")
        .unwrap();
    assert_eq!(
        cl.decrypt_decimal(&mut ctx, &cl_sk, &cl_ct_scal).unwrap(),
        "0"
    );

    let cl_ct_addscal = cl
        .addscal_ciphertexts_decimal(&mut ctx, &cl_pk, &mut rng, &cl_ct, &cl_ct, "2")
        .unwrap();
    assert_eq!(
        cl.decrypt_decimal(&mut ctx, &cl_sk, &cl_ct_addscal)
            .unwrap(),
        "0"
    );

    let cl2 = ctx.cl_hsm2k("15", 3).unwrap();
    let (cl2_sk, cl2_pk) = cl2.keygen(&mut ctx, &mut rng).unwrap();
    let cl2_ct = cl2
        .encrypt_decimal(&mut ctx, &cl2_pk, &mut rng, "5")
        .unwrap();
    assert_eq!(
        cl2.decrypt_decimal(&mut ctx, &cl2_sk, &cl2_ct).unwrap(),
        "5"
    );

    let cl2_add = cl2
        .add_ciphertexts(&mut ctx, &cl2_pk, &mut rng, &cl2_ct, &cl2_ct)
        .unwrap();
    assert_eq!(
        cl2.decrypt_decimal(&mut ctx, &cl2_sk, &cl2_add).unwrap(),
        "2"
    );

    let cl2_scal = cl2
        .scal_ciphertext_decimal(&mut ctx, &cl2_pk, &mut rng, &cl2_ct, "3")
        .unwrap();
    assert_eq!(
        cl2.decrypt_decimal(&mut ctx, &cl2_sk, &cl2_scal).unwrap(),
        "7"
    );

    let cl2_addscal = cl2
        .addscal_ciphertexts_decimal(&mut ctx, &cl2_pk, &mut rng, &cl2_ct, &cl2_ct, "2")
        .unwrap();
    assert_eq!(
        cl2.decrypt_decimal(&mut ctx, &cl2_sk, &cl2_addscal)
            .unwrap(),
        "7"
    );

    let ecdsa = ctx.ecdsa(112).unwrap();
    let (ecdsa_sk, ecdsa_pk) = ecdsa.keygen(&mut ctx, &mut rng).unwrap();
    let sig = ecdsa
        .sign_message(&mut ctx, &mut rng, &ecdsa_sk, b"abc")
        .unwrap();
    assert!(ecdsa
        .verify_message(&mut ctx, &ecdsa_pk, b"abc", &sig)
        .unwrap());
    assert!(!ecdsa
        .verify_message(&mut ctx, &ecdsa_pk, b"abd", &sig)
        .unwrap());
    assert!(!sig.r_decimal(&mut ctx).unwrap().is_empty());
    assert!(!sig.s_decimal(&mut ctx).unwrap().is_empty());

    assert!(two_party_ecdsa_run_demo(&mut ctx, &mut rng, 112, b"abc").unwrap());
    let mut tp_session = ctx.two_party_ecdsa_session(&mut rng, 112).unwrap();
    tp_session.keygen_round1(&mut ctx, &mut rng).unwrap();
    tp_session.keygen_round2(&mut ctx, &mut rng).unwrap();
    tp_session.keygen_round3(&mut ctx, &mut rng).unwrap();
    tp_session.keygen_round4(&mut ctx).unwrap();
    tp_session.sign_round1(&mut ctx, &mut rng, b"abc").unwrap();
    tp_session.sign_round2(&mut ctx, &mut rng).unwrap();
    tp_session.sign_round3(&mut ctx).unwrap();
    tp_session.sign_round4(&mut ctx, &mut rng).unwrap();
    assert!(tp_session.sign_finalize(&mut ctx).unwrap());
    assert!(cl_dlog_proof_run_demo(&mut ctx, &mut rng, 112).unwrap());
    assert!(threshold_ecdsa_run_demo(&mut ctx, &mut rng, 112, b"abc").unwrap());
    assert_eq!(cl_threshold_run_demo(&mut ctx, &mut rng).unwrap(), "2");

    let mut dlog_session = ctx.cl_dlog_session(&mut rng, 112).unwrap();
    dlog_session.prepare_statement(&mut ctx, &mut rng).unwrap();
    dlog_session.prove_round(&mut ctx, &mut rng).unwrap();
    assert!(dlog_session.verify_round(&mut ctx).unwrap());

    let mut stmt = ClDlogMessage::new().unwrap();
    let mut proof = ClDlogMessage::new().unwrap();
    dlog_session.export_statement(&mut ctx, &mut stmt).unwrap();
    dlog_session.export_proof(&mut ctx, &mut proof).unwrap();
    let stmt_bytes = stmt.to_bytes(&mut ctx).unwrap();
    let proof_bytes = proof.to_bytes(&mut ctx).unwrap();
    let mut stmt_rx = ClDlogMessage::new().unwrap();
    let mut proof_rx = ClDlogMessage::new().unwrap();
    stmt_rx.from_bytes(&mut ctx, &stmt_bytes).unwrap();
    proof_rx.from_bytes(&mut ctx, &proof_bytes).unwrap();
    let mut dlog_verifier = ctx.cl_dlog_session(&mut rng, 112).unwrap();
    dlog_verifier.import_statement(&mut ctx, &stmt_rx).unwrap();
    dlog_verifier.import_proof(&mut ctx, &proof_rx).unwrap();
    assert!(dlog_verifier.verify_round(&mut ctx).unwrap());

    let mut th_session = ctx.threshold_ecdsa_session(&mut rng, 112, 2, 1).unwrap();
    th_session.keygen_round1(&mut ctx, &mut rng).unwrap();
    th_session.keygen_round2(&mut ctx, &mut rng).unwrap();
    th_session.keygen_finalize(&mut ctx).unwrap();
    th_session.sign_round1(&mut ctx, &mut rng, b"abc").unwrap();
    th_session.sign_round2(&mut ctx, &mut rng).unwrap();
    th_session.sign_round3(&mut ctx).unwrap();
    th_session.sign_round4(&mut ctx).unwrap();
    th_session.sign_round5(&mut ctx, &mut rng).unwrap();
    th_session.sign_round6(&mut ctx, &mut rng).unwrap();
    th_session.sign_round7(&mut ctx, &mut rng).unwrap();
    th_session.sign_round8(&mut ctx).unwrap();
    th_session.sign_finalize(&mut ctx).unwrap();
    assert!(th_session.signature_valid(&mut ctx).unwrap());
}

#[test]
fn zeroize_works() {
    let mut buf = [10_u8, 20, 30, 40];
    bicycl_rs::zeroize(&mut buf);
    assert_eq!(buf, [0_u8; 4]);
}

#[test]
fn repeated_encrypt_decrypt_matches_upstream_test_patterns() {
    let mut ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("20250309").unwrap();

    let paillier = ctx.paillier(64).unwrap();
    let (paillier_sk, paillier_pk) = paillier.keygen(&mut ctx, &mut rng).unwrap();
    for message in ["0", "1", "2", "17", "42"] {
        let ct = paillier
            .encrypt_decimal(&mut ctx, &paillier_pk, &mut rng, message)
            .unwrap();
        let clear = paillier
            .decrypt_decimal(&mut ctx, &paillier_pk, &paillier_sk, &ct)
            .unwrap();
        assert_eq!(clear, message);
    }

    let jl = ctx.joye_libert(64, 8).unwrap();
    let (jl_sk, jl_pk) = jl.keygen(&mut ctx, &mut rng).unwrap();
    for message in ["0", "1", "7", "13"] {
        let ct = jl
            .encrypt_decimal(&mut ctx, &jl_pk, &mut rng, message)
            .unwrap();
        let clear = jl.decrypt_decimal(&mut ctx, &jl_sk, &ct).unwrap();
        assert_eq!(clear, message);
    }
}

#[test]
fn ecdsa_rejects_wrong_key_and_wrong_message_across_multiple_cases() {
    let mut ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("424242").unwrap();
    let ecdsa = ctx.ecdsa(112).unwrap();

    for message in [
        b"abc".as_slice(),
        b"message-2".as_slice(),
        b"\x00\x01payload".as_slice(),
    ] {
        let (sk, pk) = ecdsa.keygen(&mut ctx, &mut rng).unwrap();
        let (wrong_sk, wrong_pk) = ecdsa.keygen(&mut ctx, &mut rng).unwrap();
        let sig = ecdsa
            .sign_message(&mut ctx, &mut rng, &sk, message)
            .unwrap();

        assert!(ecdsa.verify_message(&mut ctx, &pk, message, &sig).unwrap());
        assert!(!ecdsa
            .verify_message(&mut ctx, &wrong_pk, message, &sig)
            .unwrap());

        let wrong_sig = ecdsa
            .sign_message(&mut ctx, &mut rng, &wrong_sk, message)
            .unwrap();
        assert!(!ecdsa
            .verify_message(&mut ctx, &pk, message, &wrong_sig)
            .unwrap());

        let wrong_message = if message == b"abc" {
            b"abd".as_slice()
        } else {
            b"abc".as_slice()
        };
        assert!(!ecdsa
            .verify_message(&mut ctx, &pk, wrong_message, &sig)
            .unwrap());
    }
}

#[test]
fn cl_ciphertext_ops_match_expected_modular_results() {
    let mut ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("777").unwrap();

    let cl_qk = ctx.cl_hsmqk("3", 1, "5").unwrap();
    let (cl_qk_sk, cl_qk_pk) = cl_qk.keygen(&mut ctx, &mut rng).unwrap();
    for (a, b, scalar) in [(0_i64, 0_i64, 0_i64), (1, 2, 2), (2, 2, 3), (2, 1, 4)] {
        let ct_a = cl_qk
            .encrypt_decimal(&mut ctx, &cl_qk_pk, &mut rng, &a.to_string())
            .unwrap();
        let ct_b = cl_qk
            .encrypt_decimal(&mut ctx, &cl_qk_pk, &mut rng, &b.to_string())
            .unwrap();

        let ct_sum = cl_qk
            .add_ciphertexts(&mut ctx, &cl_qk_pk, &mut rng, &ct_a, &ct_b)
            .unwrap();
        let sum = cl_qk.decrypt_decimal(&mut ctx, &cl_qk_sk, &ct_sum).unwrap();
        assert_eq!(sum, mod_decimal(a + b, 3));

        let ct_scal = cl_qk
            .scal_ciphertext_decimal(&mut ctx, &cl_qk_pk, &mut rng, &ct_a, &scalar.to_string())
            .unwrap();
        let scal = cl_qk
            .decrypt_decimal(&mut ctx, &cl_qk_sk, &ct_scal)
            .unwrap();
        assert_eq!(scal, mod_decimal(a * scalar, 3));
    }

    let cl_2k = ctx.cl_hsm2k("15", 3).unwrap();
    let (cl_2k_sk, cl_2k_pk) = cl_2k.keygen(&mut ctx, &mut rng).unwrap();
    for (a, b, scalar) in [(0_i64, 0_i64, 0_i64), (1, 6, 3), (5, 5, 2), (7, 4, 5)] {
        let ct_a = cl_2k
            .encrypt_decimal(&mut ctx, &cl_2k_pk, &mut rng, &a.to_string())
            .unwrap();
        let ct_b = cl_2k
            .encrypt_decimal(&mut ctx, &cl_2k_pk, &mut rng, &b.to_string())
            .unwrap();

        let ct_sum = cl_2k
            .add_ciphertexts(&mut ctx, &cl_2k_pk, &mut rng, &ct_a, &ct_b)
            .unwrap();
        let sum = cl_2k.decrypt_decimal(&mut ctx, &cl_2k_sk, &ct_sum).unwrap();
        assert_eq!(sum, mod_decimal(a + b, 8));

        let ct_scal = cl_2k
            .scal_ciphertext_decimal(&mut ctx, &cl_2k_pk, &mut rng, &ct_a, &scalar.to_string())
            .unwrap();
        let scal = cl_2k
            .decrypt_decimal(&mut ctx, &cl_2k_sk, &ct_scal)
            .unwrap();
        assert_eq!(scal, mod_decimal(a * scalar, 8));
    }
}
