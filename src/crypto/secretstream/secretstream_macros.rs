macro_rules! stream_module (($state_name: ident,
                             $init_push_name:ident,
                             $push_name:ident,
                             $init_pull_name:ident,
                             $pull_name:ident,
                             $rekey_name: ident,
                             $messagebytes_max:ident,
                             $keybytes:expr,
                             $headerbytes:expr,
                             $abytes:expr,
                             $tag_message: expr,
                             $tag_push: expr,
                             $tag_rekey: expr,
                             $tag_final: expr) => (

use libc::c_ulonglong;
#[cfg(not(feature = "std"))]
use prelude::Vec;
use randombytes::randombytes_into;
use std::mem;
use std::ops::Drop;
use std::ptr;

/// Returns the maximum length of an individual message.
// TODO: use `const fn` when stable
// (https://github.com/rust-lang/rust/issues/24111).
pub fn messagebytes_max() -> usize {
    unsafe { $messagebytes_max() }
}

/// Number of bytes in a `Key`.
pub const KEYBYTES: usize = $keybytes as usize;

/// Number of bytes in a `Header`.
/// An encrypted stream starts with a short header, whose size is HEADERBYTES
/// bytes. That header must be sent/stored before the sequence of encrypted
/// messages, as it is required to decrypt the stream.
pub const HEADERBYTES: usize = $headerbytes as usize;

/// Number of added bytes. The ciphertext length is guaranteed to always be
/// message length + ABYTES.
pub const ABYTES: usize = $abytes as usize;

/// Tag message: the most common tag, that doesn't add any information about the
/// nature of the message.
const TAG_MESSAGE: u8 = $tag_message as u8;

/// Tag push: indicates that the message marks the end of a set of messages, but
/// not the end of the stream.
/// For example, a huge JSON string sent as multiple chunks can use this tag to
/// indicate to the application that the string is complete and that it can be
/// decoded. But the stream itself is not closed, and more data may follow.
const TAG_PUSH: u8 = $tag_push as u8;

/// Tag rekey: "forget" the key used to encrypt this message and the previous
/// ones, and derive a new secret key.
const TAG_REKEY: u8 = $tag_rekey as u8;

/// Tag final: indicates that the message marks the end of the stream and erases
/// the secret key used to encrypt the previous sequence.
const TAG_FINAL: u8 = $tag_final as u8;

/// A tag is encrypted and attached to each message before the authentication
/// code is generated over all data. A typical encrypted stream simply attaches
/// `0` as a tag to all messages, except the last one which is tagged as
/// `Tag::Final`. When decrypting the tag is retrieved and may be used.
#[derive(Debug, PartialEq)]
pub enum Tag {
    /// Message, the most common tag, that doesn't add any information about the
    /// nature of the message.
    Message,
    /// Push: indicates that the message marks the end of a set of messages, but
    /// not the end of the stream.
    /// For example, a huge JSON string sent as multiple chunks can use this tag
    /// to indicate to the application that the string is complete and that it
    /// can be decoded. But the stream itself is not closed, and more data may
    /// follow.
    Push,
    /// Rekey: "forget" the key used to encrypt this message and the previous
    /// ones, and derive a new secret key.
    Rekey,
    /// Final: indicates that the message marks the end of the stream and erases
    /// the secret key used to encrypt the previous sequence.
    Final,
}

impl Tag {
    /// Returns the corresponding `Tag` given a `u8`, else `Err(())`.
    fn from_u8(tag: u8) -> Result<Tag, ()> {
        match tag {
            TAG_MESSAGE => Ok(Tag::Message),
            TAG_PUSH => Ok(Tag::Push),
            TAG_REKEY => Ok(Tag::Rekey),
            TAG_FINAL => Ok(Tag::Final),
            _ => Err(())
        }
    }
}

new_type! {
    /// `Key` for symmetric authenticated encryption.
    ///
    /// When a `Key` goes out of scope its contents will be overwritten in
    /// memory.
    secret Key(KEYBYTES);
}

new_type! {
    /// An encrypted stream starts with a short header, whose size is HEADERBYTES bytes.
    /// That header must be sent/stored before the sequence of encrypted messages,
    /// as it is required to decrypt the stream.
    public Header(HEADERBYTES);
}

/// `gen_key()` randomly generates a secret key
///
/// THREAD SAFETY: `gen_key()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_key() -> Key {
    let mut key = [0; KEYBYTES];
    randombytes_into(&mut key);
    Key(key)
}

/// `Stream` contains the state for multi-part (streaming) computations. This
/// allows the caller to process encryption of a sequence of multiple messages.
pub struct Stream<M: StreamMode> {
    state: $state_name,
    finalized: bool,
    phantom: core::marker::PhantomData<M>,
}

impl<M: StreamMode> Stream<M> {
    /// Explicit rekeying. This updates the internal state of the `Stream<Pull>`,
    /// and should only be called in a synchronized manner with how the
    /// corresponding `Stream` called it when encrypting the stream. Returns
    /// `Err(())` if the stream was already finalized, else `Ok(())`.
    pub fn rekey(&mut self) -> Result<(), ()> {
        if self.finalized {
            return Err(());
        }
        unsafe {
            $rekey_name(&mut self.state);
        }
        Ok(())
    }

    /// Returns true if the stream is finalized.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Returns true if the stream is not finalized.
    pub fn is_not_finalized(&self) -> bool {
        !self.finalized
    }
}

impl Stream<Push> {
    /// Initializes an `Stream` using a provided `key`. Returns the
    /// `Stream` object and a `Header`, which is needed by the recipient to
    /// initialize a corresponding `Stream<Pull>`. The `key` will not be needed be
    /// required for any subsequent authenticated encryption operations.
    /// If you would like to securely generate a key and initialize an
    /// `Stream` at the same time see the `new` method.
    /// Network protocols can leverage the key exchange API in order to get a
    /// shared key that can be used to encrypt streams. Similarly, file
    /// encryption applications can use the password hashing API to get a key
    /// that can be used with the functions below.
    pub fn init_push(key: &Key) -> Result<(Stream<Push>, Header), ()> {
        let mut header: [u8; HEADERBYTES] = unsafe { mem::uninitialized() };
        let mut state: $state_name =
            unsafe { mem::uninitialized() };
        let rc = unsafe {
            $init_push_name(
                &mut state,
                header.as_mut_ptr(),
                key.0.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(());
        }
        Ok((
            Stream::<Push> {
                state,
                finalized: false,
                phantom: core::marker::PhantomData,
            },
            Header(header),
        ))
    }

    /// All data (including optional fields) is authenticated. Encrypts a
    /// message `m` and its `tag`. Optionally includes additional data `ad`,
    /// which is not encrypted.
    pub fn push(&mut self, m: &[u8], ad: Option<&[u8]>, tag: Tag) -> Result<Vec<u8>, ()> {
        if self.finalized {
            return Err(());
        }
        let m_len = m.len();
        if m_len > messagebytes_max() {
            return Err(());
        }
        if tag == Tag::Final {
            self.finalized = true;
        }

        let (ad_p, ad_len) = ad
            .map(|ad| (ad.as_ptr(), ad.len()))
            .unwrap_or((ptr::null(), 0));

        let buf_len = m_len + ABYTES;
        let mut buf = Vec::with_capacity(buf_len);
        let rc = unsafe {
            buf.set_len(buf_len);
            $push_name(
                &mut self.state,
                buf.as_mut_ptr(),
                &mut (buf_len as c_ulonglong),
                m.as_ptr(),
                m_len as c_ulonglong,
                ad_p,
                ad_len as c_ulonglong,
                tag as u8,
            )
        };
        if rc != 0 {
            return Err(());
        }
        Ok(buf)
    }

    /// Create a ciphertext for an empty message with the `TAG_FINAL` added
    /// to signal the end of the stream. Since the `Stream` is not usable
    /// after this point, this method consumes the `Stream.
    pub fn finalize(mut self, ad: Option<&[u8]>) -> Result<Vec<u8>, ()> {
        self.push(&[], ad, Tag::Final)
    }
}

impl Stream<Pull> {
    /// Initializes a `Stream<Pull>` given a secret `Key` and a `Header`. The key
    /// will not be required any more for subsequent operations. `Err(())` is
    /// returned if the header is invalid.
    pub fn init_pull(header: &Header, key: &Key) -> Result<Stream<Pull>, ()> {
        let mut state: $state_name =
            unsafe { mem::uninitialized() };
        let rc = unsafe {
            $init_pull_name(
                &mut state,
                header.0.as_ptr(),
                key.0.as_ptr(),
            )
        };
        if rc == -1 {
            // NOTE: this return code explicitly means the header is invalid,
            // but when implementing error types we should still consider the
            // possibility of some other non-zero code below with a generic call
            // to external function failed error.
            return Err(());
        } else if rc != 0 {
            return Err(());
        }
        Ok(Stream::<Pull> {
            state: state,
            finalized: false,
            phantom: core::marker::PhantomData,
        })
    }

    /// Verifies that `c` is a valid ciphertext with a correct authentication tag
    /// given the internal state of the `Stream` (ciphertext streams cannot be
    /// decrypted out of order for this reason). Also may validate the optional
    /// unencrypted additional data `ad` using the authentication tag attached to
    /// `c`. Finally decrypts the ciphertext and tag, and checks the tag
    /// validity.
    /// If any authentication fails, the stream has already been finalized, or if
    /// the tag byte for some reason does not correspond to a valid `Tag`,
    /// returns `Err(())`. Otherwise returns the plaintext and the tag.
    /// Applications will typically use a `while stream.is_not_finalized()`
    /// loop to authenticate and decrypt a stream of messages.
    pub fn pull(&mut self, c: &[u8], ad: Option<&[u8]>) -> Result<(Vec<u8>, Tag), ()> {
        if self.finalized {
            return Err(());
        }
        let c_len = c.len();
        if c_len < ABYTES {
            // An empty message will still be at least ABYTES.
            return Err(());
        }
        let m_len = c_len - ABYTES;
        if m_len > messagebytes_max() {
            return Err(());
        }
        let (ad_p, ad_len) = ad
            .map(|ad| (ad.as_ptr(), ad.len()))
            .unwrap_or((ptr::null(), 0));
        let mut tag: u8 = unsafe { mem::uninitialized() };
        let mut buf = Vec::with_capacity(m_len);
        let rc = unsafe {
            buf.set_len(m_len);
            $pull_name(
                &mut self.state,
                buf.as_mut_ptr(),
                &mut (m_len as c_ulonglong),
                &mut tag,
                c.as_ptr(),
                c_len as c_ulonglong,
                ad_p,
                ad_len as c_ulonglong,
            )
        };
        if rc != 0 {
            return Err(());
        }
        let tag = Tag::from_u8(tag)?;
        if tag == Tag::Final {
            self.finalized = true;
        }
        Ok((buf, tag))
    }
}

// As additional precaution, rotate the keys when dropping the `Stream`
// to ensure keys do no stay in memory.
impl<T: StreamMode> Drop for Stream<T> {
    fn drop(&mut self) {
        let _ = self.rekey();
    }
}

/// The trait that distinguishes between the pull and push modes of a Stream.
pub trait StreamMode: private::Sealed {}

/// Represents the push mode of a Stream.
pub struct Push;

/// Represents the pull mode of a Stream.
pub struct Pull;

mod private {
    pub trait Sealed {}

    impl Sealed for super::Push {}
    impl Sealed for super::Pull {}
}

impl StreamMode for Push {}
impl StreamMode for Pull {}

));
