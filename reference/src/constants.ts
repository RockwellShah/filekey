// FileKey v0.4.7 protocol constants (spec §3, §5, §6).

export const FORMAT_VERSION = 0x01;
export const SUITE_ID = 0x01;
export const SK_VERSION = 0x01; // share-key encoding version (§4.4)
export const REC_VERSION = 0x01; // recovery-code encoding version (§4.6.3)

export const MAGIC = new Uint8Array([0x46, 0x4b, 0x45, 0x59]); // "FKEY"

export const HEADER_LEN = 12; // magic(4)+ver(1)+suite(1)+flags(1)+reserved(1)+nstag(4)
export const PK_LEN = 65; // SEC1 uncompressed P-256
export const ENC_LEN = 65; // HPKE encapsulated key, P-256 uncompressed
export const COMPRESSED_PK_LEN = 33; // SEC1 compressed P-256
export const NS_TAG_LEN = 4; // SHA-256(canonical_rp_id)[0:4]
export const AAD_LEN = HEADER_LEN + PK_LEN + ENC_LEN; // 142

export const CHUNK_SIZE = 65536; // 64 KiB plaintext per chunk (§5.5)
export const GCM_TAG_LEN = 16;
export const NONCE_LEN = 12;
export const COUNTER_LEN = 11; // big-endian chunk counter (§5.5)
export const MAX_CHUNK_INDEX = 2 ** 32; // reject i >= 2^32 (§5.5 counter cap)

export const METADATA_PLAINTEXT_MAX = 1_048_576; // 1 MiB (§5.4.1 rule 7)
export const METADATA_CT_MAX = 1_048_592; // 1 MiB + 16-byte tag (§5.4.3)
export const METADATA_CT_MIN = 17; // 1 byte version + 16-byte tag (§5.4.3)
export const METADATA_VERSION = 0x01;

// Domain-separation labels (exact bytes are normative).
export const LABEL_PRF_INPUT = "FILEKEY-v1/prf-input/identity"; // SHA-256'd → PRF salt (§4.1)
export const LABEL_MASTER_PRK = "FILEKEY-v1/master-prk"; // HKDF-Extract salt (§4.2)
export const LABEL_IDENTITY_KEM = "FILEKEY-v1/identity-kem"; // HKDF-Expand info (§4.3)
export const LABEL_HPKE_INFO = "FILEKEY-v1/hpke-info"; // HPKE info prefix (§6.2)
export const LABEL_PAYLOAD_KEY = "FILEKEY-v1 payload-key"; // HPKE export ctx (§6.3)
export const LABEL_METADATA_KEY = "FILEKEY-v1 metadata-key"; // HPKE export ctx (§6.3)
export const LABEL_FINGERPRINT = "FILEKEY-v1/fingerprint"; // identity fingerprint (§4.7)

export const SHARE_KEY_HRP = "fkey";
export const RECOVERY_HRP = "fkeyrec";

// The canonical RP-ID for the public FileKey interop namespace (§8.5). Placeholder
// pending ecosystem agreement; deployments override via NamespaceConfig.
export const DEFAULT_CANONICAL_RP_ID = "filekey.app";

export const METADATA_NONCE = new Uint8Array(NONCE_LEN); // 12 zero bytes (§6.3.1)
