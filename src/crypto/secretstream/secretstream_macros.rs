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

#[cfg(not(feature = "std"))] use prelude::*;
use libc::c_ulonglong;
use randombytes::randombytes_into;
use std::mem;
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

impl Key {
    /// Randomly generates a key for authenticated encryption.
    ///
    /// THREAD SAFETY: this method is safe provided that you have called
    /// `sodiumoxide::init()` once before using any other function from
    /// sodiumoxide.
    // TODO: create a new `new_type!` macro for keys. It will probably look like
    // `public`, and then just have this method.
    pub fn new() -> Key {
        let mut key: [u8; KEYBYTES] = unsafe { mem::uninitialized() };
        randombytes_into(&mut key);
        Key(key)
    }
}

/// `Encryptor` contains the state for multi-part (streaming) computations. This
/// allows the caller to process encryption of a sequence of multiple messages.
pub struct Encryptor($state_name);

impl Encryptor {
    /// Initializes an `Encryptor` using a provided `key`. Returns the
    /// `Encryptor` object and a `Header`, which is needed by the recipient to
    /// initialize a corresponding `Decryptor`. The `key` will not be needed be
    /// required for any subsequent authenticated encryption operations.
    /// If you would like to securely generate a key and initialize an
    /// `Encryptor` at the same time see the `new` method.
    /// Network protocols can leverage the key exchange API in order to get a
    /// shared key that can be used to encrypt streams. Similarly, file
    /// encryption applications can use the password hashing API to get a key
    /// that can be used with the functions below.
    pub fn init(key: &Key) -> Result<(Self, Header), ()> {
        let mut header: [u8; HEADERBYTES] = unsafe { mem::uninitialized() };
        let mut state: $state_name = unsafe { mem::uninitialized() };

        let rc = unsafe {
            $init_push_name(&mut state, header.as_mut_ptr(), key.0.as_ptr())
        };
        if rc != 0 {
            return Err(());
        }

        Ok((Encryptor(state), Header(header)))
    }


    /// Securely generates a key and uses it to initialize an `Encryptor`.
    /// Returns the `Encryptor` object, a `Header` (which is needed by the
    /// recipient to initialize a corresponding `Decryptor`), and the `Key`
    /// object.
    pub fn new() -> Result<(Self, Header, Key), ()> {
        let key = Key::new();

        let result = Self::init(&key);
        if result.is_err() {
            return Err(());
        }

        let (encryptor, header) = result.unwrap();
        Ok((encryptor, header, key))
    }

    /// All data (including optional fields) is authenticated. Encrypts a
    /// message `m` and its `tag`. Optionally includes additional data `ad`,
    /// which is not encrypted.
    fn aencrypt(&mut self, m: &[u8], ad: Option<&[u8]>, tag: u8) -> Result<Vec<u8>, ()> {
        let mlen = m.len();
        if m.len() > messagebytes_max() {
            return Err(());
        }
        let clen = mlen + ABYTES;
        let mut c = Vec::with_capacity(clen);
        let (ad_p, ad_len) = ad.map(|ad| (ad.as_ptr(), ad.len()))
                               .unwrap_or((ptr::null(), 0));

        let rc = unsafe {
            $push_name(&mut self.0,
                       c.as_mut_ptr(),
                       &mut (clen as c_ulonglong),
                       m.as_ptr(),
                       mlen as c_ulonglong,
                       ad_p,
                       ad_len as c_ulonglong,
                       tag)
        };
        if rc != 0 {
            return Err(());
        }

        unsafe { c.set_len(clen) };
        Ok(c)
    }

    /// All data (including optional fields) is authenticated. Encrypts a
    /// message `m` and the tag `Tag::Message`. Optionally includes additional data `ad`,
    /// which is not encrypted.
    pub fn aencrypt_message(&mut self, m: &[u8], ad: Option<&[u8]>) -> Result<Vec<u8>, ()> {
        self.aencrypt(m, ad, TAG_MESSAGE)
    }

    /// All data (including optional fields) is authenticated. Encrypts a message
    /// `m` and the tag `Tag::Push`. Optionally includes additional data `ad`,
    /// which is not encrypted.
    pub fn aencrypt_push(&mut self, m: &[u8], ad: Option<&[u8]>) -> Result<Vec<u8>, ()> {
        self.aencrypt(m, ad, TAG_PUSH)
    }

    /// All data (including optional fields) is authenticated. Encrypts a message
    /// `m` and the tag `Tag::Rekey`. Optionally includes additional data `ad`,
    /// which is not encrypted.
    pub fn aencrypt_rekey(&mut self, m: &[u8], ad: Option<&[u8]>) -> Result<Vec<u8>, ()> {
        self.aencrypt(m, ad, TAG_REKEY)
    }

    /// All data (including optional fields) is authenticated. Encrypts a message
    /// `m` and the tag `Tag::Finalize`. Optionally includes additional data `ad`,
    /// which is not encrypted. Consumes `self` so that the `Encryptor` may no
    /// longer be used after sending the finalize tag.
    pub fn aencrypt_finalize(mut self, m: &[u8], ad: Option<&[u8]>) -> Result<Vec<u8>, ()> {
        self.aencrypt(m, ad, TAG_FINAL)
    }

    /// This method explicitly re-keys the `Encryptor` and updates its state, but
    /// doesn't add any information about the key change to the stream. If this
    /// function is used to create an encrypted stream, the decryption process
    /// must call that function at the exact same stream location.
    /// See also the method `aencrypt_rekey`.
    pub fn rekey(&mut self) {
        unsafe {
            $rekey_name(&mut self.0);
        }
    }
}

/// `Decryptor` contains the state for multi-part (streaming) computations. This
/// allows the caller to process encryption of a sequence of multiple messages.
/// After the last message of a valid stream containing the tag `Tag::Finalized`
/// is decrypted, the `Decryptor` may no longer verify and decrypt messages or
/// re-key itself.
pub struct Decryptor {
    state: $state_name,
    finalized: bool,
}

impl Decryptor {
    /// Initializes a `Decryptor` given a secret `Key` and a `Header`. The key
    /// will not be required any more for subsequent operations. `Err(())` is
    /// returned if the header is invalid.
    pub fn init(header: &Header, key: &Key) -> Result<Self, ()> {
        let mut state: $state_name = unsafe { mem::uninitialized() };

        let rc = unsafe {
            $init_pull_name(&mut state, header.0.as_ptr(), key.0.as_ptr())
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

        Ok(Self{state, finalized: false})
    }

    /// Verifies that `c` is a valid ciphertext with a correct authentication tag
    /// given the internal state of the `Decryptor` (ciphertext streams cannot be
    /// decrypted out of order for this reason). Also may validate the optional
    /// unencrypted additional data `ad` using the authentication tag attached to
    /// `c`. Finally decrypts the ciphertext and tag, and checks the tag
    /// validity.
    /// If any authentication fails, the stream has already been finalized, or if
    /// the tag byte for some reason does not correspond to a valid `Tag`,
    /// returns `Err(())`. Otherwise returns the plaintext and the tag.
    /// Applications will typically use a `while decryptor.is_not_finalized()`
    /// loop to authenticate and decrypt a stream of messages.
    pub fn vdecrypt(&mut self, c: &[u8], ad: Option<&[u8]>) -> Result<(Vec<u8>, Tag),()> {
        if self.is_finalized() {
            return Err(());
        }
        // An empty message will still be at least ABYTES.
        let clen = c.len();
        if clen < ABYTES {
            return Err(());
        }
        let mlen = clen - ABYTES;
        if mlen > messagebytes_max() {
            return Err(());
        }
        let mut m = Vec::with_capacity(mlen);
        let (ad_p, ad_len) = ad.map(|ad| (ad.as_ptr(), ad.len()))
                               .unwrap_or((ptr::null(), 0));
        let mut tag: u8 = unsafe { mem::uninitialized() };

        let rc = unsafe {
            $pull_name(&mut self.state,
                       m.as_mut_ptr(),
                       &mut (mlen as c_ulonglong),
                       &mut tag,
                       c.as_ptr(),
                       clen as c_ulonglong,
                       ad_p,
                       ad_len as c_ulonglong)
        };
        if rc != 0 {
            return Err(());
        }

        let tag = Tag::from_u8(tag)?;
        if tag == Tag::Final {
            self.finalized = true;
        }

        unsafe { m.set_len(mlen) }

        Ok((m, tag))
    }

    /// Explicit rekeying. This updates the internal state of the `Decryptor`,
    /// and should only be called in a synchronized manner with how the
    /// corresponding `Encryptor` called it when encrypting the stream. Returns
    /// `Err(())` if the stream was already finalized, else `Ok(())`.
    pub fn rekey(&mut self) -> Result<(), ()> {
        if self.is_finalized() {
            return Err(());
        }
        unsafe {
            $rekey_name(&mut self.state);
        }
        Ok(())
    }

    /// Check if stream is finalized.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Check if stream is not finalized.
    pub fn is_not_finalized(&self) -> bool {
        !self.finalized
    }
}

));