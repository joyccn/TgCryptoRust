//! Python bindings for TgCryptoRust.
//!
//! Provides the native `tgcryptors` module. The packaged `tgcrypto` shim
//! re-exports this module so existing TgCrypto imports keep working.
//! - `ige256_encrypt(data, key, iv) -> bytes`
//! - `ige256_decrypt(data, key, iv) -> bytes`
//! - `ctr256_encrypt(data, key, iv, state) -> bytes`
//! - `ctr256_decrypt(data, key, iv, state) -> bytes`
//! - `cbc256_encrypt(data, key, iv) -> bytes`
//! - `cbc256_decrypt(data, key, iv) -> bytes`

use core::slice;
use pyo3::exceptions::{PyOverflowError, PyRuntimeError, PyValueError};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::panic::{catch_unwind, AssertUnwindSafe};

const AES_BLOCK_SIZE: usize = 16;
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Copy a Python bytes-like value into a fixed-size Rust array.
fn copy_array<const N: usize>(value: &[u8], label: &str) -> PyResult<[u8; N]> {
    value
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{label} must be exactly {N} bytes")))
}

/// Ensure block cipher input is aligned to the AES block size.
fn ensure_block_aligned(data: &[u8]) -> PyResult<()> {
    if data.len() % AES_BLOCK_SIZE != 0 {
        return Err(PyValueError::new_err(format!(
            "Data length must be a multiple of {AES_BLOCK_SIZE} bytes"
        )));
    }
    Ok(())
}

/// Validate the single-byte CTR carry state.
fn validate_ctr_state(state: &[u8]) -> PyResult<u8> {
    let state = copy_array::<1>(state, "State")?[0];
    if state > 15 {
        return Err(PyValueError::new_err(
            "State value must be in the range [0, 15]",
        ));
    }
    Ok(state)
}

/// Zero-copy PyBytes allocation with GIL release and panic isolation.
///
/// Allocates uninitialized Python bytes, releases the GIL,
/// runs the cipher operation in-place, and returns the result plus
/// any auxiliary state produced by the operation.
fn execute_zerocopy<'py, T, F>(
    py: Python<'py>,
    len: usize,
    f: F,
) -> PyResult<(Bound<'py, PyBytes>, T)>
where
    T: Send,
    F: FnOnce(&mut [u8]) -> T + Send,
{
    let py_len: ffi::Py_ssize_t = len.try_into().map_err(|_| {
        PyOverflowError::new_err("Data is too large to fit in a Python bytes object")
    })?;

    let obj_ptr = unsafe { ffi::PyBytes_FromStringAndSize(std::ptr::null(), py_len) };
    let any = unsafe { Bound::from_owned_ptr_or_err(py, obj_ptr)? };
    let dest_ptr = unsafe { ffi::PyBytes_AsString(any.as_ptr()) };
    if dest_ptr.is_null() {
        return Err(PyRuntimeError::new_err(
            "Python bytes allocation succeeded but returned a null data pointer",
        ));
    }
    let dest_addr = dest_ptr as usize;

    let result = py.detach(move || {
        // SAFETY: dest_ptr is valid for `len` bytes and exclusively owned.
        let dest = unsafe { slice::from_raw_parts_mut(dest_addr as *mut u8, len) };
        catch_unwind(AssertUnwindSafe(|| f(dest)))
    });

    let result = result.map_err(|_| {
        PyRuntimeError::new_err("Unexpected internal failure while executing cipher operation")
    })?;

    let bytes: Bound<'py, PyBytes> = unsafe { any.cast_into_unchecked() };
    Ok((bytes, result))
}

/// Encrypt bytes with AES-256-IGE.
///
/// Args:
///     data: Plaintext bytes. Length must be a multiple of 16 bytes.
///     key: AES-256 key, exactly 32 bytes.
///     iv: Initial vector, exactly 32 bytes.
///
/// Returns:
///     The encrypted ciphertext as `bytes`.
///
/// Raises:
///     ValueError: If `data`, `key`, or `iv` have invalid lengths.
///     OverflowError: If the requested output would exceed Python's `bytes` size limit.
///     RuntimeError: If an unexpected internal error occurs.
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    ensure_block_aligned(data)?;
    let key_arr = copy_array::<32>(key, "Key")?;
    let mut iv_arr = copy_array::<32>(iv, "IV")?;

    let (bytes, _) = execute_zerocopy(py, data.len(), move |dest| {
        tgcryptors_core::ige256_encrypt_into(data, &key_arr, &mut iv_arr, dest);
    })?;
    Ok(bytes)
}

/// Decrypt bytes with AES-256-IGE.
///
/// Args:
///     data: Ciphertext bytes. Length must be a multiple of 16 bytes.
///     key: AES-256 key, exactly 32 bytes.
///     iv: Initial vector, exactly 32 bytes.
///
/// Returns:
///     The decrypted plaintext as `bytes`.
///
/// Raises:
///     ValueError: If `data`, `key`, or `iv` have invalid lengths.
///     OverflowError: If the requested output would exceed Python's `bytes` size limit.
///     RuntimeError: If an unexpected internal error occurs.
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    ensure_block_aligned(data)?;
    let key_arr = copy_array::<32>(key, "Key")?;
    let mut iv_arr = copy_array::<32>(iv, "IV")?;

    let (bytes, _) = execute_zerocopy(py, data.len(), move |dest| {
        tgcryptors_core::ige256_decrypt_into(data, &key_arr, &mut iv_arr, dest);
    })?;
    Ok(bytes)
}

/// Encrypt bytes with AES-256-CTR.
///
/// Args:
///     data: Plaintext bytes of any length.
///     key: AES-256 key, exactly 32 bytes.
///     iv: Counter block, exactly 16 bytes.
///     state: Residual CTR byte offset encoded as a one-byte `bytes` object.
///
/// Returns:
///     The encrypted ciphertext as `bytes`.
///
/// Raises:
///     ValueError: If `key`, `iv`, or `state` are invalid.
///     OverflowError: If the requested output would exceed Python's `bytes` size limit.
///     RuntimeError: If an unexpected internal error occurs.
#[pyfunction]
#[pyo3(signature = (data, key, iv, state))]
fn ctr256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
    state: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key_arr = copy_array::<32>(key, "Key")?;
    let mut iv_arr = copy_array::<16>(iv, "IV")?;
    let mut state_val = validate_ctr_state(state)?;

    let (bytes, _) = execute_zerocopy(py, data.len(), move |dest| {
        tgcryptors_core::ctr256_encrypt_into(data, &key_arr, &mut iv_arr, &mut state_val, dest);
    })?;
    Ok(bytes)
}

/// Decrypt bytes with AES-256-CTR.
///
/// CTR is symmetric, so decryption delegates to `ctr256_encrypt`.
#[pyfunction]
#[pyo3(signature = (data, key, iv, state))]
fn ctr256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
    state: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    ctr256_encrypt(py, data, key, iv, state)
}

/// Encrypt bytes with AES-256-CBC.
///
/// Args:
///     data: Plaintext bytes. Length must be a multiple of 16 bytes.
///     key: AES-256 key, exactly 32 bytes.
///     iv: Initial vector, exactly 16 bytes.
///
/// Returns:
///     The encrypted ciphertext as `bytes`.
///
/// Raises:
///     ValueError: If `data`, `key`, or `iv` have invalid lengths.
///     OverflowError: If the requested output would exceed Python's `bytes` size limit.
///     RuntimeError: If an unexpected internal error occurs.
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn cbc256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    ensure_block_aligned(data)?;
    let key_arr = copy_array::<32>(key, "Key")?;
    let mut iv_arr = copy_array::<16>(iv, "IV")?;

    let (bytes, _) = execute_zerocopy(py, data.len(), move |dest| {
        tgcryptors_core::cbc256_encrypt_into(data, &key_arr, &mut iv_arr, dest);
    })?;
    Ok(bytes)
}

/// Decrypt bytes with AES-256-CBC.
///
/// Args:
///     data: Ciphertext bytes. Length must be a multiple of 16 bytes.
///     key: AES-256 key, exactly 32 bytes.
///     iv: Initial vector, exactly 16 bytes.
///
/// Returns:
///     The decrypted plaintext as `bytes`.
///
/// Raises:
///     ValueError: If `data`, `key`, or `iv` have invalid lengths.
///     OverflowError: If the requested output would exceed Python's `bytes` size limit.
///     RuntimeError: If an unexpected internal error occurs.
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn cbc256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    ensure_block_aligned(data)?;
    let key_arr = copy_array::<32>(key, "Key")?;
    let mut iv_arr = copy_array::<16>(iv, "IV")?;

    let (bytes, _) = execute_zerocopy(py, data.len(), move |dest| {
        tgcryptors_core::cbc256_decrypt_into(data, &key_arr, &mut iv_arr, dest);
    })?;
    Ok(bytes)
}

/// Return compact runtime metadata useful for support and diagnostics.
#[pyfunction]
fn runtime_info(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let info = PyDict::new(py);
    info.set_item("version", VERSION)?;
    info.set_item("crate_version", VERSION)?;
    info.set_item("implementation", "rust")?;
    info.set_item("aesni", tgcryptors_core::AESNI_FEATURE_ENABLED)?;
    Ok(info)
}

/// Stateful AES-256-CTR stream cipher.
///
/// The object preserves the CTR counter and residual byte offset between
/// `update()` calls, allowing chunked encryption and decryption of a single
/// logical byte stream. The AES key schedule is expanded once at construction
/// and reused for all subsequent operations.
#[pyclass(module = "tgcryptors")]
struct Ctr256 {
    ek: tgcryptors_core::ExpandedKey,
    iv: [u8; 16],
    state: u8,
}

#[pymethods]
impl Ctr256 {
    /// Create a new AES-256-CTR stream cipher.
    ///
    /// Args:
    ///     key: AES-256 key, exactly 32 bytes.
    ///     iv: Initial counter block, exactly 16 bytes.
    ///
    /// Raises:
    ///     ValueError: If `key` or `iv` have invalid lengths.
    #[new]
    fn new(key: &[u8], iv: &[u8]) -> PyResult<Self> {
        let key_arr = copy_array::<32>(key, "Key")?;
        let iv_arr = copy_array::<16>(iv, "IV")?;
        Ok(Ctr256 {
            ek: tgcryptors_core::ExpandedKey::new_encrypt(&key_arr),
            iv: iv_arr,
            state: 0,
        })
    }

    /// Encrypt or decrypt the next chunk of a CTR stream.
    ///
    /// Args:
    ///     data: The next plaintext or ciphertext chunk.
    ///
    /// Returns:
    ///     The processed chunk as `bytes`.
    ///
    /// Notes:
    ///     AES-CTR is symmetric, so the same method is used for encryption
    ///     and decryption.
    fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let ek = &self.ek;
        let mut iv_arr = self.iv;
        let mut state_val = self.state;

        let (res, (next_iv, next_state)) = execute_zerocopy(py, data.len(), move |dest| {
            tgcryptors_core::ctr256_encrypt_into_ek(data, ek, &mut iv_arr, &mut state_val, dest);
            (iv_arr, state_val)
        })?;

        self.iv = next_iv;
        self.state = next_state;
        Ok(res)
    }
}

/// Stateful AES-256-IGE stream cipher.
///
/// The object preserves the evolving IGE chaining state between `encrypt()`
/// or `decrypt()` calls, allowing incremental processing of a single logical
/// block-aligned stream. The AES key schedules are expanded once at construction
/// and reused for all subsequent operations.
#[pyclass(module = "tgcryptors")]
struct Ige256 {
    enc_key: tgcryptors_core::ExpandedKey,
    dec_key: tgcryptors_core::ExpandedKey,
    iv: [u8; 32],
}

#[pymethods]
impl Ige256 {
    /// Create a new AES-256-IGE stream cipher.
    ///
    /// Args:
    ///     key: AES-256 key, exactly 32 bytes.
    ///     iv: Initial vector, exactly 32 bytes.
    ///
    /// Raises:
    ///     ValueError: If `key` or `iv` have invalid lengths.
    #[new]
    fn new(key: &[u8], iv: &[u8]) -> PyResult<Self> {
        let key_arr = copy_array::<32>(key, "Key")?;
        let iv_arr = copy_array::<32>(iv, "IV")?;
        Ok(Ige256 {
            enc_key: tgcryptors_core::ExpandedKey::new_encrypt(&key_arr),
            dec_key: tgcryptors_core::ExpandedKey::new_decrypt(&key_arr),
            iv: iv_arr,
        })
    }

    /// Encrypt the next block-aligned chunk with AES-256-IGE.
    ///
    /// Args:
    ///     data: Plaintext bytes. Length must be a multiple of 16 bytes.
    ///
    /// Returns:
    ///     The encrypted ciphertext chunk as `bytes`.
    ///
    /// Raises:
    ///     ValueError: If `data` is not block-aligned.
    fn encrypt<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        ensure_block_aligned(data)?;
        let ek = &self.enc_key;
        let mut iv_arr = self.iv;

        let (res, next_iv) = execute_zerocopy(py, data.len(), move |dest| {
            tgcryptors_core::ige256_encrypt_into_ek(data, ek, &mut iv_arr, dest);
            iv_arr
        })?;

        self.iv = next_iv;
        Ok(res)
    }

    /// Decrypt the next block-aligned chunk with AES-256-IGE.
    ///
    /// Args:
    ///     data: Ciphertext bytes. Length must be a multiple of 16 bytes.
    ///
    /// Returns:
    ///     The decrypted plaintext chunk as `bytes`.
    ///
    /// Raises:
    ///     ValueError: If `data` is not block-aligned.
    fn decrypt<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        ensure_block_aligned(data)?;
        let dk = &self.dec_key;
        let mut iv_arr = self.iv;

        let (res, next_iv) = execute_zerocopy(py, data.len(), move |dest| {
            tgcryptors_core::ige256_decrypt_into_ek(data, dk, &mut iv_arr, dest);
            iv_arr
        })?;

        self.iv = next_iv;
        Ok(res)
    }
}

/// Native TgCryptoRust Python extension module.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", VERSION)?;
    m.add_function(wrap_pyfunction!(ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cbc256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cbc256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(runtime_info, m)?)?;

    m.add_class::<Ctr256>()?;
    m.add_class::<Ige256>()?;

    Ok(())
}
