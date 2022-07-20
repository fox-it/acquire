import io
import hashlib

from collections import defaultdict
from datetime import datetime, timezone

from dissect import cstruct

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Random import get_random_bytes

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

try:
    # Injected by pystandalone builder
    from acquire.config import CONFIG
except ImportError:
    CONFIG = defaultdict(lambda: None)


c_acquire = cstruct.cstruct()
c_acquire.load(
    """
enum HeaderType : uint8 {
    PKCS1_OAEP = 0x1,
};

enum CipherType : uint8 {
    AES_256_GCM = 0x1,
};

struct file {
    char        magic[16];              // ENCRYPTEDACQUIRE
    uint8       version;                // Currently 1
    HeaderType  header_type;            // Currently PKCS1_OAEP
    uint16      header_size;            // Most often 512
    uint64      timestamp;              // Timestamp of write
    char        key_digest[32];         // SHA256(DER)
};

struct header {
    char        magic[12];              // KUSJESVANSRT
    CipherType  cipher_type;            // Currently AES_256_GCM
    uint8       key_length;             // Cipher key length
    uint8       iv_length;              // Cipher IV length
    uint8       _reserved;              // Reserved
    char        key[key_length];        // Cipher key
    char        iv[iv_length];          // Cipher IV
};

struct footer {
    char        magic[6];               // FOOTER
    uint16      length;                 // Digest length (precedes footer)
};
"""
)


FILE_MAGIC = b"ENCRYPTEDACQUIRE"
FILE_VERSION = 1
HEADER_MAGIC = b"KUSJESVANSRT"
FOOTER_MAGIC = b"FOOTER"


class EncryptedStream(io.RawIOBase):
    """Encrypted AES-256-GCM stream.

    Generates a random key and IV and uses AES-256-GCM to encrypt all written data.
    The key and IV are encrypted with the given RSA public key (or from the embedded config)
    and written as header. The header is included as AD to the AEAD cipher.
    The digest is written when the file is closed in the footer.

    Args:
        fh: The file-like object to write to.
        public_key: The RSA public key to encrypt the header with.
    """

    def __init__(self, fh, public_key=None):
        if not HAS_PYCRYPTODOME:
            raise ImportError("PyCryptodome is not available")

        self.fh = fh

        public_key = public_key or CONFIG.get("public_key")
        if not public_key:
            raise ValueError("No public key available (embedded or argument)")

        key = get_random_bytes(32)
        iv = get_random_bytes(12)
        self.cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        rsa = PKCS1_OAEP.new(RSA.import_key(public_key))

        plain_header = c_acquire.header(
            magic=HEADER_MAGIC,
            cipher_type=c_acquire.CipherType.AES_256_GCM,
            key_length=len(key),
            iv_length=len(iv),
            key=key,
            iv=iv,
        )
        sealed_header = rsa.encrypt(plain_header.dumps())

        file_header = c_acquire.file(
            magic=FILE_MAGIC,
            version=FILE_VERSION,
            header_type=c_acquire.HeaderType.PKCS1_OAEP,
            header_size=len(sealed_header),
            timestamp=int(datetime.now(timezone.utc).timestamp()),
            key_digest=key_fingerprint(rsa),
        )
        self.write_header(file_header.dumps() + sealed_header)

    def write_header(self, header):
        self.cipher.update(header)
        self.fh.write(header)

    def write(self, b):
        return self.fh.write(self.cipher.encrypt(b))

    def tell(self):
        return self.fh.tell()

    def seek(self, pos, whence=io.SEEK_CUR):
        raise TypeError("seeking is not allowed")

    def close(self):
        self.finalize()
        super().close()
        self.fh.close()

    def finalize(self):
        digest = self.cipher.digest()
        footer = c_acquire.footer(magic=FOOTER_MAGIC, length=len(digest))

        self.fh.write(digest + footer.dumps())
        self.fh.flush()
        if hasattr(self.cipher, "clean"):
            self.cipher.clean()


def key_fingerprint(pkey):
    if isinstance(pkey, PKCS1_OAEP.PKCS1OAEP_Cipher):
        pkey = pkey._key
    der = pkey.export_key("DER")

    return hashlib.sha256(der).digest()
