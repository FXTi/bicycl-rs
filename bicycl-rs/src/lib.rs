#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(all(feature = "vendored", feature = "system"))]
compile_error!("features 'vendored' and 'system' are mutually exclusive");
#[cfg(all(
    not(feature = "vendored"),
    not(feature = "system"),
    not(feature = "docsrs")
))]
compile_error!("enable one of: feature 'vendored' (default) or feature 'system'");

mod error;

use core::ffi::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::ptr::NonNull;

pub use error::{Error, Result};

fn status_to_result(status: bicycl_rs_sys::bicycl_status_t) -> Result<()> {
    if status == bicycl_rs_sys::bicycl_status_t::BICYCL_OK {
        Ok(())
    } else {
        Err(Error::from_status(status))
    }
}

fn ffi_string_from_len<F>(mut f: F) -> Result<String>
where
    F: FnMut(*mut c_char, *mut usize) -> bicycl_rs_sys::bicycl_status_t,
{
    let buf = ffi_bytes_from_len(|buf, len| f(buf.cast::<c_char>(), len))?;
    let cstr = CStr::from_bytes_with_nul(&buf).map_err(|_| Error::InvalidArgument)?;
    Ok(cstr.to_str()?.to_owned())
}

fn ffi_bytes_from_len<F>(mut f: F) -> Result<Vec<u8>>
where
    F: FnMut(*mut u8, *mut usize) -> bicycl_rs_sys::bicycl_status_t,
{
    let mut len: usize = 0;
    let first = f(std::ptr::null_mut(), &mut len as *mut usize);
    if first != bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        && first != bicycl_rs_sys::bicycl_status_t::BICYCL_OK
    {
        return Err(Error::from_status(first));
    }

    let mut buf = vec![0_u8; len];
    if len == 0 {
        return Ok(buf);
    }

    let second = f(buf.as_mut_ptr(), &mut len as *mut usize);
    status_to_result(second)?;
    buf.truncate(len);
    Ok(buf)
}

pub fn abi_version() -> u32 {
    unsafe { bicycl_rs_sys::bicycl_get_abi_version() }
}

pub fn version() -> &'static str {
    unsafe {
        let p = bicycl_rs_sys::bicycl_get_version();
        if p.is_null() {
            return "";
        }
        CStr::from_ptr(p).to_str().unwrap_or("")
    }
}

pub fn zeroize(buf: &mut [u8]) {
    unsafe {
        bicycl_rs_sys::bicycl_zeroize(buf.as_mut_ptr().cast::<c_void>(), buf.len());
    }
}

pub fn two_party_ecdsa_run_demo(
    ctx: &mut Context,
    rng: &mut RandGen,
    seclevel_bits: u32,
    msg: &[u8],
) -> Result<bool> {
    let mut out_valid: c_int = 0;
    let status = unsafe {
        bicycl_rs_sys::bicycl_two_party_ecdsa_run_demo(
            ctx.raw.as_ptr(),
            rng.raw.as_ptr(),
            seclevel_bits,
            msg.as_ptr(),
            msg.len(),
            &mut out_valid as *mut _,
        )
    };
    status_to_result(status)?;
    Ok(out_valid != 0)
}

#[derive(Debug)]
pub struct TwoPartyEcdsaSession {
    raw: NonNull<bicycl_rs_sys::bicycl_two_party_ecdsa_session_t>,
}

pub fn cl_threshold_run_demo(ctx: &mut Context, rng: &mut RandGen) -> Result<String> {
    ffi_string_from_len(|buf, len| unsafe {
        bicycl_rs_sys::bicycl_cl_threshold_run_demo(ctx.raw.as_ptr(), rng.raw.as_ptr(), buf, len)
    })
}

pub fn cl_dlog_proof_run_demo(
    ctx: &mut Context,
    rng: &mut RandGen,
    seclevel_bits: u32,
) -> Result<bool> {
    let mut out_valid: c_int = 0;
    let status = unsafe {
        bicycl_rs_sys::bicycl_cl_dlog_proof_run_demo(
            ctx.raw.as_ptr(),
            rng.raw.as_ptr(),
            seclevel_bits,
            &mut out_valid as *mut _,
        )
    };
    status_to_result(status)?;
    Ok(out_valid != 0)
}

pub fn threshold_ecdsa_run_demo(
    ctx: &mut Context,
    rng: &mut RandGen,
    seclevel_bits: u32,
    msg: &[u8],
) -> Result<bool> {
    let mut out_valid: c_int = 0;
    let status = unsafe {
        bicycl_rs_sys::bicycl_threshold_ecdsa_run_demo(
            ctx.raw.as_ptr(),
            rng.raw.as_ptr(),
            seclevel_bits,
            msg.as_ptr(),
            msg.len(),
            &mut out_valid as *mut _,
        )
    };
    status_to_result(status)?;
    Ok(out_valid != 0)
}

#[derive(Debug)]
pub struct Context {
    raw: NonNull<bicycl_rs_sys::bicycl_context_t>,
}

impl Context {
    pub fn new() -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe { bicycl_rs_sys::bicycl_context_new(&mut raw as *mut _) };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_context_new"))?;
        Ok(Self { raw })
    }

    pub fn last_error(&self) -> &str {
        unsafe {
            let p = bicycl_rs_sys::bicycl_context_last_error(self.raw.as_ptr());
            if p.is_null() {
                return "";
            }
            CStr::from_ptr(p).to_str().unwrap_or("")
        }
    }

    pub fn clear_error(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_context_clear_error(self.raw.as_ptr()) }
    }

    pub fn randgen_from_seed_decimal(&mut self, seed_decimal: &str) -> Result<RandGen> {
        let seed_c = CString::new(seed_decimal)?;
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_randgen_new_from_seed_decimal(
                self.raw.as_ptr(),
                seed_c.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_randgen_new_from_seed_decimal"))?;
        Ok(RandGen { raw })
    }

    pub fn classgroup_from_discriminant_decimal(
        &mut self,
        discriminant_decimal: &str,
    ) -> Result<ClassGroup> {
        let disc_c = CString::new(discriminant_decimal)?;
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_classgroup_new_from_discriminant_decimal(
                self.raw.as_ptr(),
                disc_c.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi(
            "bicycl_classgroup_new_from_discriminant_decimal",
        ))?;
        Ok(ClassGroup { raw })
    }

    pub fn paillier(&mut self, modulus_bits: u32) -> Result<Paillier> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_paillier_new(self.raw.as_ptr(), modulus_bits, &mut raw as *mut _)
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_paillier_new"))?;
        Ok(Paillier { raw })
    }

    pub fn joye_libert(&mut self, modulus_bits: u32, k: u32) -> Result<JoyeLibert> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_joye_libert_new(
                self.raw.as_ptr(),
                modulus_bits,
                k,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_joye_libert_new"))?;
        Ok(JoyeLibert { raw })
    }

    pub fn cl_hsmqk(&mut self, q_decimal: &str, k: u32, p_decimal: &str) -> Result<ClHsmqk> {
        let q_c = CString::new(q_decimal)?;
        let p_c = CString::new(p_decimal)?;
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_new(
                self.raw.as_ptr(),
                q_c.as_ptr(),
                k,
                p_c.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_cl_hsmqk_new"))?;
        Ok(ClHsmqk { raw })
    }

    pub fn cl_hsm2k(&mut self, n_decimal: &str, k: u32) -> Result<ClHsm2k> {
        let n_c = CString::new(n_decimal)?;
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_new(
                self.raw.as_ptr(),
                n_c.as_ptr(),
                k,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_cl_hsm2k_new"))?;
        Ok(ClHsm2k { raw })
    }

    pub fn ecdsa(&mut self, seclevel_bits: u32) -> Result<Ecdsa> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_ecdsa_new(self.raw.as_ptr(), seclevel_bits, &mut raw as *mut _)
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_ecdsa_new"))?;
        Ok(Ecdsa { raw })
    }

    pub fn two_party_ecdsa_session(
        &mut self,
        rng: &mut RandGen,
        seclevel_bits: u32,
    ) -> Result<TwoPartyEcdsaSession> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_session_new(
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                seclevel_bits,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_two_party_ecdsa_session_new"))?;
        Ok(TwoPartyEcdsaSession { raw })
    }

    pub fn cl_dlog_session(
        &mut self,
        rng: &mut RandGen,
        seclevel_bits: u32,
    ) -> Result<ClDlogSession> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_new(
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                seclevel_bits,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_cl_dlog_session_new"))?;
        Ok(ClDlogSession { raw })
    }

    pub fn threshold_ecdsa_session(
        &mut self,
        rng: &mut RandGen,
        seclevel_bits: u32,
        n_players: u32,
        threshold_t: u32,
    ) -> Result<ThresholdEcdsaSession> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_session_new(
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                seclevel_bits,
                n_players,
                threshold_t,
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_threshold_ecdsa_session_new"))?;
        Ok(ThresholdEcdsaSession { raw })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_context_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct RandGen {
    raw: NonNull<bicycl_rs_sys::bicycl_randgen_t>,
}

impl Drop for RandGen {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_randgen_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct ClassGroup {
    raw: NonNull<bicycl_rs_sys::bicycl_classgroup_t>,
}

impl ClassGroup {
    pub fn one(&self, ctx: &mut Context) -> Result<Qfi> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_classgroup_one(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_classgroup_one"))?;
        Ok(Qfi { raw })
    }

    pub fn nudupl(&self, ctx: &mut Context, input: &Qfi) -> Result<Qfi> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_classgroup_nudupl(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                input.raw.as_ptr(),
                &mut raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_classgroup_nudupl"))?;
        Ok(Qfi { raw })
    }
}

impl Drop for ClassGroup {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_classgroup_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct Qfi {
    raw: NonNull<bicycl_rs_sys::bicycl_qfi_t>,
}

impl Qfi {
    pub fn is_one(&self, ctx: &mut Context) -> Result<bool> {
        let mut out: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_qfi_is_one(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut out as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out != 0)
    }

    pub fn discriminant_decimal(&self, ctx: &mut Context) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_qfi_discriminant_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                buf,
                len,
            )
        })
    }
}

impl Drop for Qfi {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_qfi_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct Paillier {
    raw: NonNull<bicycl_rs_sys::bicycl_paillier_t>,
}

#[derive(Debug)]
pub struct PaillierSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_paillier_sk_t>,
}

#[derive(Debug)]
pub struct PaillierPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_paillier_pk_t>,
}

#[derive(Debug)]
pub struct PaillierCipherText {
    raw: NonNull<bicycl_rs_sys::bicycl_paillier_ct_t>,
}

impl Paillier {
    pub fn keygen(
        &self,
        ctx: &mut Context,
        rng: &mut RandGen,
    ) -> Result<(PaillierSecretKey, PaillierPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_paillier_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;

        let sk = PaillierSecretKey {
            raw: NonNull::new(sk_raw).ok_or(Error::NullFromFfi("bicycl_paillier_keygen/sk"))?,
        };
        let pk = PaillierPublicKey {
            raw: NonNull::new(pk_raw).ok_or(Error::NullFromFfi("bicycl_paillier_keygen/pk"))?,
        };
        Ok((sk, pk))
    }

    pub fn encrypt_decimal(
        &self,
        ctx: &mut Context,
        pk: &PaillierPublicKey,
        rng: &mut RandGen,
        message_decimal: &str,
    ) -> Result<PaillierCipherText> {
        let message_c = CString::new(message_decimal)?;
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_paillier_encrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                message_c.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(ct_raw).ok_or(Error::NullFromFfi("bicycl_paillier_encrypt_decimal"))?;
        Ok(PaillierCipherText { raw })
    }

    pub fn decrypt_decimal(
        &self,
        ctx: &mut Context,
        pk: &PaillierPublicKey,
        sk: &PaillierSecretKey,
        ct: &PaillierCipherText,
    ) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_paillier_decrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                sk.raw.as_ptr(),
                ct.raw.as_ptr(),
                buf,
                len,
            )
        })
    }
}

impl Drop for Paillier {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_paillier_free(self.raw.as_ptr()) }
    }
}

impl Drop for PaillierSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_paillier_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for PaillierPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_paillier_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for PaillierCipherText {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_paillier_ct_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct JoyeLibert {
    raw: NonNull<bicycl_rs_sys::bicycl_joye_libert_t>,
}

#[derive(Debug)]
pub struct JoyeLibertSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_joye_libert_sk_t>,
}

#[derive(Debug)]
pub struct JoyeLibertPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_joye_libert_pk_t>,
}

#[derive(Debug)]
pub struct JoyeLibertCipherText {
    raw: NonNull<bicycl_rs_sys::bicycl_joye_libert_ct_t>,
}

impl JoyeLibert {
    pub fn keygen(
        &self,
        ctx: &mut Context,
        rng: &mut RandGen,
    ) -> Result<(JoyeLibertSecretKey, JoyeLibertPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_joye_libert_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;

        let sk = JoyeLibertSecretKey {
            raw: NonNull::new(sk_raw).ok_or(Error::NullFromFfi("bicycl_joye_libert_keygen/sk"))?,
        };
        let pk = JoyeLibertPublicKey {
            raw: NonNull::new(pk_raw).ok_or(Error::NullFromFfi("bicycl_joye_libert_keygen/pk"))?,
        };
        Ok((sk, pk))
    }

    pub fn encrypt_decimal(
        &self,
        ctx: &mut Context,
        pk: &JoyeLibertPublicKey,
        rng: &mut RandGen,
        message_decimal: &str,
    ) -> Result<JoyeLibertCipherText> {
        let message_c = CString::new(message_decimal)?;
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_joye_libert_encrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                message_c.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(ct_raw).ok_or(Error::NullFromFfi("bicycl_joye_libert_encrypt_decimal"))?;
        Ok(JoyeLibertCipherText { raw })
    }

    pub fn decrypt_decimal(
        &self,
        ctx: &mut Context,
        sk: &JoyeLibertSecretKey,
        ct: &JoyeLibertCipherText,
    ) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_joye_libert_decrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                sk.raw.as_ptr(),
                ct.raw.as_ptr(),
                buf,
                len,
            )
        })
    }
}

impl Drop for JoyeLibert {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_joye_libert_free(self.raw.as_ptr()) }
    }
}

impl Drop for JoyeLibertSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_joye_libert_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for JoyeLibertPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_joye_libert_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for JoyeLibertCipherText {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_joye_libert_ct_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct ClHsmqk {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsmqk_t>,
}

#[derive(Debug)]
pub struct ClHsmqkSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsmqk_sk_t>,
}

#[derive(Debug)]
pub struct ClHsmqkPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsmqk_pk_t>,
}

#[derive(Debug)]
pub struct ClHsmqkCipherText {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsmqk_ct_t>,
}

impl ClHsmqk {
    pub fn keygen(
        &self,
        ctx: &mut Context,
        rng: &mut RandGen,
    ) -> Result<(ClHsmqkSecretKey, ClHsmqkPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;

        let sk = ClHsmqkSecretKey {
            raw: NonNull::new(sk_raw).ok_or(Error::NullFromFfi("bicycl_cl_hsmqk_keygen/sk"))?,
        };
        let pk = ClHsmqkPublicKey {
            raw: NonNull::new(pk_raw).ok_or(Error::NullFromFfi("bicycl_cl_hsmqk_keygen/pk"))?,
        };
        Ok((sk, pk))
    }

    pub fn encrypt_decimal(
        &self,
        ctx: &mut Context,
        pk: &ClHsmqkPublicKey,
        rng: &mut RandGen,
        message_decimal: &str,
    ) -> Result<ClHsmqkCipherText> {
        let message_c = CString::new(message_decimal)?;
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_encrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                message_c.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(ct_raw).ok_or(Error::NullFromFfi("bicycl_cl_hsmqk_encrypt_decimal"))?;
        Ok(ClHsmqkCipherText { raw })
    }

    pub fn decrypt_decimal(
        &self,
        ctx: &mut Context,
        sk: &ClHsmqkSecretKey,
        ct: &ClHsmqkCipherText,
    ) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_decrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                sk.raw.as_ptr(),
                ct.raw.as_ptr(),
                buf,
                len,
            )
        })
    }

    pub fn add_ciphertexts(
        &self,
        ctx: &mut Context,
        pk: &ClHsmqkPublicKey,
        rng: &mut RandGen,
        ca: &ClHsmqkCipherText,
        cb: &ClHsmqkCipherText,
    ) -> Result<ClHsmqkCipherText> {
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_add_ciphertexts(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ca.raw.as_ptr(),
                cb.raw.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(ct_raw).ok_or(Error::NullFromFfi("bicycl_cl_hsmqk_add_ciphertexts"))?;
        Ok(ClHsmqkCipherText { raw })
    }

    pub fn scal_ciphertext_decimal(
        &self,
        ctx: &mut Context,
        pk: &ClHsmqkPublicKey,
        rng: &mut RandGen,
        ct: &ClHsmqkCipherText,
        scalar_decimal: &str,
    ) -> Result<ClHsmqkCipherText> {
        let scalar_c = CString::new(scalar_decimal)?;
        let mut out_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_scal_ciphertext_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ct.raw.as_ptr(),
                scalar_c.as_ptr(),
                &mut out_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(out_raw).ok_or(Error::NullFromFfi(
            "bicycl_cl_hsmqk_scal_ciphertext_decimal",
        ))?;
        Ok(ClHsmqkCipherText { raw })
    }

    pub fn addscal_ciphertexts_decimal(
        &self,
        ctx: &mut Context,
        pk: &ClHsmqkPublicKey,
        rng: &mut RandGen,
        ca: &ClHsmqkCipherText,
        cb: &ClHsmqkCipherText,
        scalar_decimal: &str,
    ) -> Result<ClHsmqkCipherText> {
        let scalar_c = CString::new(scalar_decimal)?;
        let mut out_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsmqk_addscal_ciphertexts_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ca.raw.as_ptr(),
                cb.raw.as_ptr(),
                scalar_c.as_ptr(),
                &mut out_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(out_raw).ok_or(Error::NullFromFfi(
            "bicycl_cl_hsmqk_addscal_ciphertexts_decimal",
        ))?;
        Ok(ClHsmqkCipherText { raw })
    }
}

impl Drop for ClHsmqk {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsmqk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsmqkSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsmqk_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsmqkPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsmqk_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsmqkCipherText {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsmqk_ct_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct ClHsm2k {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsm2k_t>,
}

#[derive(Debug)]
pub struct ClHsm2kSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsm2k_sk_t>,
}

#[derive(Debug)]
pub struct ClHsm2kPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsm2k_pk_t>,
}

#[derive(Debug)]
pub struct ClHsm2kCipherText {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_hsm2k_ct_t>,
}

impl ClHsm2k {
    pub fn keygen(
        &self,
        ctx: &mut Context,
        rng: &mut RandGen,
    ) -> Result<(ClHsm2kSecretKey, ClHsm2kPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;

        let sk = ClHsm2kSecretKey {
            raw: NonNull::new(sk_raw).ok_or(Error::NullFromFfi("bicycl_cl_hsm2k_keygen/sk"))?,
        };
        let pk = ClHsm2kPublicKey {
            raw: NonNull::new(pk_raw).ok_or(Error::NullFromFfi("bicycl_cl_hsm2k_keygen/pk"))?,
        };
        Ok((sk, pk))
    }

    pub fn encrypt_decimal(
        &self,
        ctx: &mut Context,
        pk: &ClHsm2kPublicKey,
        rng: &mut RandGen,
        message_decimal: &str,
    ) -> Result<ClHsm2kCipherText> {
        let message_c = CString::new(message_decimal)?;
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_encrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                message_c.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(ct_raw).ok_or(Error::NullFromFfi("bicycl_cl_hsm2k_encrypt_decimal"))?;
        Ok(ClHsm2kCipherText { raw })
    }

    pub fn decrypt_decimal(
        &self,
        ctx: &mut Context,
        sk: &ClHsm2kSecretKey,
        ct: &ClHsm2kCipherText,
    ) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_decrypt_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                sk.raw.as_ptr(),
                ct.raw.as_ptr(),
                buf,
                len,
            )
        })
    }

    pub fn add_ciphertexts(
        &self,
        ctx: &mut Context,
        pk: &ClHsm2kPublicKey,
        rng: &mut RandGen,
        ca: &ClHsm2kCipherText,
        cb: &ClHsm2kCipherText,
    ) -> Result<ClHsm2kCipherText> {
        let mut ct_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_add_ciphertexts(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ca.raw.as_ptr(),
                cb.raw.as_ptr(),
                &mut ct_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw =
            NonNull::new(ct_raw).ok_or(Error::NullFromFfi("bicycl_cl_hsm2k_add_ciphertexts"))?;
        Ok(ClHsm2kCipherText { raw })
    }

    pub fn scal_ciphertext_decimal(
        &self,
        ctx: &mut Context,
        pk: &ClHsm2kPublicKey,
        rng: &mut RandGen,
        ct: &ClHsm2kCipherText,
        scalar_decimal: &str,
    ) -> Result<ClHsm2kCipherText> {
        let scalar_c = CString::new(scalar_decimal)?;
        let mut out_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_scal_ciphertext_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ct.raw.as_ptr(),
                scalar_c.as_ptr(),
                &mut out_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(out_raw).ok_or(Error::NullFromFfi(
            "bicycl_cl_hsm2k_scal_ciphertext_decimal",
        ))?;
        Ok(ClHsm2kCipherText { raw })
    }

    pub fn addscal_ciphertexts_decimal(
        &self,
        ctx: &mut Context,
        pk: &ClHsm2kPublicKey,
        rng: &mut RandGen,
        ca: &ClHsm2kCipherText,
        cb: &ClHsm2kCipherText,
        scalar_decimal: &str,
    ) -> Result<ClHsm2kCipherText> {
        let scalar_c = CString::new(scalar_decimal)?;
        let mut out_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_hsm2k_addscal_ciphertexts_decimal(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                rng.raw.as_ptr(),
                ca.raw.as_ptr(),
                cb.raw.as_ptr(),
                scalar_c.as_ptr(),
                &mut out_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(out_raw).ok_or(Error::NullFromFfi(
            "bicycl_cl_hsm2k_addscal_ciphertexts_decimal",
        ))?;
        Ok(ClHsm2kCipherText { raw })
    }
}

impl Drop for ClHsm2k {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsm2k_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsm2kSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsm2k_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsm2kPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsm2k_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for ClHsm2kCipherText {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_hsm2k_ct_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct Ecdsa {
    raw: NonNull<bicycl_rs_sys::bicycl_ecdsa_t>,
}

#[derive(Debug)]
pub struct EcdsaSecretKey {
    raw: NonNull<bicycl_rs_sys::bicycl_ecdsa_sk_t>,
}

#[derive(Debug)]
pub struct EcdsaPublicKey {
    raw: NonNull<bicycl_rs_sys::bicycl_ecdsa_pk_t>,
}

#[derive(Debug)]
pub struct EcdsaSignature {
    raw: NonNull<bicycl_rs_sys::bicycl_ecdsa_sig_t>,
}

impl Ecdsa {
    pub fn keygen(
        &self,
        ctx: &mut Context,
        rng: &mut RandGen,
    ) -> Result<(EcdsaSecretKey, EcdsaPublicKey)> {
        let mut sk_raw = std::ptr::null_mut();
        let mut pk_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_ecdsa_keygen(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                &mut sk_raw as *mut _,
                &mut pk_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let sk = EcdsaSecretKey {
            raw: NonNull::new(sk_raw).ok_or(Error::NullFromFfi("bicycl_ecdsa_keygen/sk"))?,
        };
        let pk = EcdsaPublicKey {
            raw: NonNull::new(pk_raw).ok_or(Error::NullFromFfi("bicycl_ecdsa_keygen/pk"))?,
        };
        Ok((sk, pk))
    }

    pub fn sign_message(
        &self,
        ctx: &mut Context,
        rng: &mut RandGen,
        sk: &EcdsaSecretKey,
        msg: &[u8],
    ) -> Result<EcdsaSignature> {
        let mut sig_raw = std::ptr::null_mut();
        let status = unsafe {
            bicycl_rs_sys::bicycl_ecdsa_sign_message(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                sk.raw.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                &mut sig_raw as *mut _,
            )
        };
        status_to_result(status)?;
        let raw = NonNull::new(sig_raw).ok_or(Error::NullFromFfi("bicycl_ecdsa_sign_message"))?;
        Ok(EcdsaSignature { raw })
    }

    pub fn verify_message(
        &self,
        ctx: &mut Context,
        pk: &EcdsaPublicKey,
        msg: &[u8],
        sig: &EcdsaSignature,
    ) -> Result<bool> {
        let mut out_valid: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_ecdsa_verify_message(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                pk.raw.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.raw.as_ptr(),
                &mut out_valid as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out_valid != 0)
    }
}

impl EcdsaSignature {
    pub fn r_decimal(&self, ctx: &mut Context) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_ecdsa_sig_r_decimal(ctx.raw.as_ptr(), self.raw.as_ptr(), buf, len)
        })
    }

    pub fn s_decimal(&self, ctx: &mut Context) -> Result<String> {
        ffi_string_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_ecdsa_sig_s_decimal(ctx.raw.as_ptr(), self.raw.as_ptr(), buf, len)
        })
    }
}

impl TwoPartyEcdsaSession {
    pub fn keygen_round1(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_keygen_round1(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn keygen_round2(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_keygen_round2(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn keygen_round3(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_keygen_round3(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn keygen_round4(&mut self, ctx: &mut Context) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_keygen_round4(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)
    }

    pub fn sign_round1(&mut self, ctx: &mut Context, rng: &mut RandGen, msg: &[u8]) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_round1(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                msg.as_ptr(),
                msg.len(),
            )
        };
        status_to_result(status)
    }

    pub fn sign_round2(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_round2(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn sign_round3(&mut self, ctx: &mut Context) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_round3(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)
    }

    pub fn sign_round4(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_round4(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn sign_finalize(&mut self, ctx: &mut Context) -> Result<bool> {
        let mut out_valid: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_two_party_ecdsa_sign_finalize(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut out_valid as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out_valid != 0)
    }
}

impl Drop for TwoPartyEcdsaSession {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_two_party_ecdsa_session_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct ClDlogSession {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_dlog_session_t>,
}

#[derive(Debug)]
pub struct ClDlogMessage {
    raw: NonNull<bicycl_rs_sys::bicycl_cl_dlog_message_t>,
}

impl ClDlogSession {
    pub fn prepare_statement(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_prepare_statement(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn prove_round(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_prove_round(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn verify_round(&self, ctx: &mut Context) -> Result<bool> {
        let mut out_valid: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_verify_round(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut out_valid as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out_valid != 0)
    }

    pub fn export_statement(&self, ctx: &mut Context, out_msg: &mut ClDlogMessage) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_export_statement(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                out_msg.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn import_statement(&mut self, ctx: &mut Context, msg: &ClDlogMessage) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_import_statement(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                msg.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn export_proof(&self, ctx: &mut Context, out_msg: &mut ClDlogMessage) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_export_proof(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                out_msg.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn import_proof(&mut self, ctx: &mut Context, msg: &ClDlogMessage) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_session_import_proof(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                msg.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }
}

impl Drop for ClDlogSession {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_dlog_session_free(self.raw.as_ptr()) }
    }
}

impl ClDlogMessage {
    pub fn new() -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe { bicycl_rs_sys::bicycl_cl_dlog_message_new(&mut raw as *mut _) };
        status_to_result(status)?;
        let raw = NonNull::new(raw).ok_or(Error::NullFromFfi("bicycl_cl_dlog_message_new"))?;
        Ok(Self { raw })
    }

    pub fn to_bytes(&self, ctx: &mut Context) -> Result<Vec<u8>> {
        ffi_bytes_from_len(|buf, len| unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_message_export_bytes(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                buf,
                len,
            )
        })
    }

    pub fn from_bytes(&mut self, ctx: &mut Context, bytes: &[u8]) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_cl_dlog_message_import_bytes(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        status_to_result(status)
    }
}

impl Drop for ClDlogMessage {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_cl_dlog_message_free(self.raw.as_ptr()) }
    }
}

#[derive(Debug)]
pub struct ThresholdEcdsaSession {
    raw: NonNull<bicycl_rs_sys::bicycl_threshold_ecdsa_session_t>,
}

impl ThresholdEcdsaSession {
    pub fn keygen_round1(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_keygen_round1(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn keygen_round2(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_keygen_round2(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn keygen_finalize(&mut self, ctx: &mut Context) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_keygen_finalize(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn sign_round1(&mut self, ctx: &mut Context, rng: &mut RandGen, msg: &[u8]) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round1(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
                msg.as_ptr(),
                msg.len(),
            )
        };
        status_to_result(status)
    }

    pub fn sign_round2(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round2(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn sign_round3(&mut self, ctx: &mut Context) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round3(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)
    }

    pub fn sign_round4(&mut self, ctx: &mut Context) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round4(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)
    }

    pub fn sign_round5(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round5(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn sign_round6(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round6(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn sign_round7(&mut self, ctx: &mut Context, rng: &mut RandGen) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round7(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                rng.raw.as_ptr(),
            )
        };
        status_to_result(status)
    }

    pub fn sign_round8(&mut self, ctx: &mut Context) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_round8(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)
    }

    pub fn sign_finalize(&mut self, ctx: &mut Context) -> Result<()> {
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_sign_finalize(ctx.raw.as_ptr(), self.raw.as_ptr())
        };
        status_to_result(status)
    }

    pub fn signature_valid(&self, ctx: &mut Context) -> Result<bool> {
        let mut out_valid: c_int = 0;
        let status = unsafe {
            bicycl_rs_sys::bicycl_threshold_ecdsa_signature_valid(
                ctx.raw.as_ptr(),
                self.raw.as_ptr(),
                &mut out_valid as *mut _,
            )
        };
        status_to_result(status)?;
        Ok(out_valid != 0)
    }
}

impl Drop for ThresholdEcdsaSession {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_threshold_ecdsa_session_free(self.raw.as_ptr()) }
    }
}

impl Drop for Ecdsa {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_ecdsa_free(self.raw.as_ptr()) }
    }
}

impl Drop for EcdsaSecretKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_ecdsa_sk_free(self.raw.as_ptr()) }
    }
}

impl Drop for EcdsaPublicKey {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_ecdsa_pk_free(self.raw.as_ptr()) }
    }
}

impl Drop for EcdsaSignature {
    fn drop(&mut self) {
        unsafe { bicycl_rs_sys::bicycl_ecdsa_sig_free(self.raw.as_ptr()) }
    }
}
