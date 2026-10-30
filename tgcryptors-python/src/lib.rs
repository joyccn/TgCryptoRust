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

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyOverflowError, PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::critical_section::with_critical_section;
use pyo3::types::{PyAny, PyByteArray, PyBytes, PyDict};
use std::panic::{catch_unwind, AssertUnwindSafe};
use tgcryptors_core::AES_BLOCK_SIZE;
use zeroize::Zeroizing;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Copy a Python bytes-like value into a fixed-size Rust array.
fn copy_array<const N: usize>(value: &[u8], label: &str) -> PyResult<[u8; N]> {
    value
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{label} must be exactly {N} bytes")))
}

/// Ensure block cipher input is aligned to the AES block size.
fn ensure_block_aligned(data: &[u8]) -> PyResult<()> {
    if !data.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(PyValueError::new_err(format!(
            "Data length must be a multiple of {AES_BLOCK_SIZE} bytes"
        )));
    }
    Ok(())
}

/// Validate the single-byte CTR carry state.
fn validate_ctr_state(state: u8) -> PyResult<u8> {
    if state > 15 {
        return Err(PyValueError::new_err(
            "State value must be in the range [0, 15]",
        ));
    }
    Ok(state)
}

/// A `bytes` or `bytearray` argument.
///
/// `bytes` is read zero-copy and treated as stateless input. `bytearray`
/// contents are copied out up front, because the buffer may be mutated by
/// Python code while the GIL is released during the operation; the original
/// object remains exported until processing completes. Fixed-size key and
/// state arguments use stack snapshots instead (see [`copy_buffer_array`]).
enum BufferInput<'py> {
    Bytes(Bound<'py, PyBytes>),
    ByteArray {
        data: Zeroizing<Vec<u8>>,
        _source: ByteArraySource<'py>,
    },
}

impl<'py> BufferInput<'py> {
    fn from_any(ob: &Bound<'py, PyAny>, label: &str) -> PyResult<Self> {
        if let Ok(bytes) = ob.cast::<PyBytes>() {
            return Ok(BufferInput::Bytes(bytes.clone()));
        }
        if let Ok(array) = ob.cast::<PyByteArray>() {
            return Ok(BufferInput::ByteArray {
                _source: ByteArraySource::new(array)?,
                data: Zeroizing::new(array.to_vec()),
            });
        }
        Err(PyTypeError::new_err(format!(
            "{label} must be bytes or bytearray"
        )))
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            BufferInput::Bytes(bytes) => bytes.as_bytes(),
            BufferInput::ByteArray { data, .. } => data,
        }
    }
}

/// Keep the bytearray's buffer exported while native code runs without the GIL.
/// Python raises BufferError if another thread tries to resize it in that time.
struct ByteArraySource<'py> {
    array: Bound<'py, PyByteArray>,
    _lease: PyBuffer<u8>,
}

impl<'py> ByteArraySource<'py> {
    fn new(array: &Bound<'py, PyByteArray>) -> PyResult<Self> {
        Ok(Self {
            array: array.clone(),
            _lease: PyBuffer::get(array.as_any())?,
        })
    }

    fn from_any(value: &Bound<'py, PyAny>) -> PyResult<Option<Self>> {
        value.cast::<PyByteArray>().ok().map(Self::new).transpose()
    }

    fn write_back(&self, value: &[u8]) -> PyResult<()> {
        with_critical_section(self.array.as_any(), || {
            // A real check also protects against unusual bytearray subclasses
            // whose buffer exporter does not pin the underlying bytearray.
            if self.array.len() != value.len() {
                return Err(PyRuntimeError::new_err(
                    "CTR state buffer was resized during cipher operation",
                ));
            }
            // SAFETY: the critical section excludes concurrent mutation, and
            // no Python code is called while the short-lived slice is used.
            unsafe { self.array.as_bytes_mut() }.copy_from_slice(value);
            Ok(())
        })
    }
}

/// Copy a small bytes/bytearray argument directly to a fixed-size stack array.
///
/// Mutable input is only borrowed inside its critical section, never across a
/// Python call or GIL release. IV/state callers retain a separate buffer export
/// until write-back. Key input needs no export after its owned snapshot exists.
fn copy_buffer_array<const N: usize>(
    value: &Bound<'_, PyAny>,
    label: &str,
) -> PyResult<Zeroizing<[u8; N]>> {
    if let Ok(bytes) = value.cast::<PyBytes>() {
        return copy_array(bytes.as_bytes(), label).map(Zeroizing::new);
    }
    if let Ok(array) = value.cast::<PyByteArray>() {
        return with_critical_section(array.as_any(), || {
            if array.len() != N {
                return Err(PyValueError::new_err(format!(
                    "{label} must be exactly {N} bytes"
                )));
            }
            let mut snapshot = Zeroizing::new([0; N]);
            // SAFETY: the bytearray is locked, its length was checked, and
            // the borrowed slice is consumed without any Python interaction.
            snapshot.copy_from_slice(unsafe { array.as_bytes() });
            Ok(snapshot)
        });
    }
    Err(PyTypeError::new_err(format!(
        "{label} must be bytes or bytearray"
    )))
}

/// Fill a fresh Python bytes allocation, keeping all raw allocation handling
/// inside PyO3. Panic isolation prevents partial output from reaching Python.
fn execute_zerocopy<'py, T, F>(
    py: Python<'py>,
    len: usize,
    f: F,
) -> PyResult<(Bound<'py, PyBytes>, T)>
where
    T: Send,
    F: FnOnce(&mut [u8]) -> T + Send,
{
    if len > isize::MAX as usize {
        return Err(PyOverflowError::new_err(
            "Data is too large to fit in a Python bytes object",
        ));
    }

    let mut result = None;
    let bytes = PyBytes::new_with(py, len, |dest| {
        let operation = || catch_unwind(AssertUnwindSafe(|| f(dest)));
        // Avoid the detach/reattach cost for small Telegram transport chunks.
        // Large buffers still release the GIL for concurrency.
        let output = if len >= 16 * 1024 {
            py.detach(operation)
        } else {
            operation()
        };
        result = Some(output.map_err(|_| {
            PyRuntimeError::new_err("Unexpected internal failure while executing cipher operation")
        })?);
        Ok(())
    })?;

    let result = result
        .ok_or_else(|| PyRuntimeError::new_err("Python bytes initializer did not execute"))?;
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
    let key_arr = Zeroizing::new(copy_array::<32>(key, "Key")?);
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
    let key_arr = Zeroizing::new(copy_array::<32>(key, "Key")?);
    let mut iv_arr = copy_array::<32>(iv, "IV")?;

    let (bytes, _) = execute_zerocopy(py, data.len(), move |dest| {
        tgcryptors_core::ige256_decrypt_into(data, &key_arr, &mut iv_arr, dest);
    })?;
    Ok(bytes)
}

/// Encrypt bytes with AES-256-CTR.
///
/// Args:
///     data: Plaintext bytes of any length. May be `bytes` or `bytearray`.
///     key: AES-256 key, exactly 32 bytes. May be `bytes` or `bytearray`.
///     iv: Counter block, exactly 16 bytes. May be `bytes` or `bytearray`.
///     state: Residual CTR byte offset encoded as a one-byte `bytes` or
///         `bytearray`.
///
/// Returns:
///     The encrypted ciphertext as `bytes`.
///
/// Notes:
///     When `iv` or `state` are passed as `bytearray`, they are updated in
///     place: after the call they hold the advanced counter and residual
///     offset, so passing the same objects to the next call continues the
///     keystream (TgCrypto-compatible, required by pyrogram and its forks).
///     `bytes` inputs are treated as stateless one-shot calls.
///     Data and mutable IV/state cannot be resized until processing completes.
///     Key input is copied immediately and may be resized after that snapshot.
///     Synchronize callers sharing mutable state; use separate `Ctr256`
///     objects for independent streams and never reuse a key/counter pair.
///
/// Raises:
///     TypeError: If `data`, `key`, `iv`, or `state` are not `bytes` or
///         `bytearray`.
///     ValueError: If `data`, `key`, `iv`, or `state` have invalid lengths.
///     OverflowError: If the requested output would exceed Python's `bytes` size limit.
///     RuntimeError: If an unexpected internal error occurs.
#[pyfunction]
#[pyo3(signature = (data, key, iv, state))]
fn ctr256_encrypt<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyAny>,
    key: &Bound<'py, PyAny>,
    iv: &Bound<'py, PyAny>,
    state: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let data = BufferInput::from_any(data, "Data")?;
    let key_arr = copy_buffer_array::<32>(key, "Key")?;
    // Exports pin only state that will be written back. Small snapshots avoid
    // allocating separate Vecs for the key, counter, and residual byte offset.
    let iv_source = ByteArraySource::from_any(iv)?;
    let mut iv_arr = copy_buffer_array::<16>(iv, "IV")?;
    let state_source = ByteArraySource::from_any(state)?;
    let state_arr = copy_buffer_array::<1>(state, "State")?;
    let mut state_val = validate_ctr_state(state_arr[0])?;
    let data_slice = data.as_bytes();

    let (bytes, (next_iv, next_state)) = execute_zerocopy(py, data_slice.len(), move |dest| {
        tgcryptors_core::ctr256_encrypt_into(
            data_slice,
            &key_arr,
            &mut iv_arr,
            &mut state_val,
            dest,
        );
        (iv_arr, state_val)
    })?;

    if let Some(source) = iv_source {
        source.write_back(&next_iv[..])?;
    }
    if let Some(source) = state_source {
        source.write_back(&[next_state])?;
    }

    Ok(bytes)
}

/// Decrypt bytes with AES-256-CTR.
///
/// CTR is symmetric, so decryption delegates to `ctr256_encrypt`. See
/// [`ctr256_encrypt`] for the accepted argument types and the in-place
/// `bytearray` carry semantics.
#[pyfunction]
#[pyo3(signature = (data, key, iv, state))]
fn ctr256_decrypt<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyAny>,
    key: &Bound<'py, PyAny>,
    iv: &Bound<'py, PyAny>,
    state: &Bound<'py, PyAny>,
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
    let key_arr = Zeroizing::new(copy_array::<32>(key, "Key")?);
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
    let key_arr = Zeroizing::new(copy_array::<32>(key, "Key")?);
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
    let hardware = tgcryptors_core::aes256::hardware_accelerated();
    info.set_item(
        "aesni",
        hardware && cfg!(any(target_arch = "x86", target_arch = "x86_64")),
    )?;
    info.set_item("hardware_accelerated", hardware)?;
    info.set_item("backend", tgcryptors_core::aes256::backend_name())?;
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
        let key_arr = Zeroizing::new(copy_array::<32>(key, "Key")?);
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
    key: tgcryptors_core::ExpandedKey,
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
        let key_arr = Zeroizing::new(copy_array::<32>(key, "Key")?);
        let iv_arr = copy_array::<32>(iv, "IV")?;
        Ok(Ige256 {
            // RustCrypto's opaque AES key already holds both round schedules.
            key: tgcryptors_core::ExpandedKey::new_encrypt(&key_arr),
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
        let ek = &self.key;
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
        let dk = &self.key;
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
