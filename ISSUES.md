# Audit Issues

> Generated with [oy-cli](https://github.com/wagov-dtt/oy-cli): `OY_MODEL=copilot:gpt-5.4 oy audit`

>
> **Last audit**: 2026-04-19 · commit `922d04b35` · references: [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) and [grugbrain.dev](https://grugbrain.dev/)
>
> **Scope**: 3022 reviewable files · 1676396 code lines · 2445 counted by sloc

Final phase3 rewrite. Raw phase2 inbox notes were deduped; the most important repo-specific issues stay detailed below and the rest are kept concise.

## Detailed findings

### 1. PKCS#7 decode APIs can overwrite caller buffers
- location: `wolfcrypt/src/pkcs7.c:14568-14599,15250-15272`; public APIs `wolfssl/wolfcrypt/pkcs7.h:550,558,583`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: attacker controls CMS/PKCS#7 input and the application uses a fixed output buffer.
- evidence: `wc_PKCS7_DecodeAuthEnvelopedData()` does `XMEMCPY(output, encryptedContent, encryptedContentSz)`. `wc_PKCS7_DecodeEncryptedData()` copies `encryptedContentSz - padLen` after checking only `output != NULL && outputSz != 0`.
- impact: caller heap/stack overwrite; realistic crash and possible code execution.
- recommendation: calculate required plaintext length first, compare it to `outputSz` on every path, and return `BUFFER_E` plus the required size instead of copying blindly.
- reference: `ASVS 5.0 V5 File Handling`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 2. Linux kernel direct-RSA decrypt can overflow a short kernel heap buffer
- location: `linuxkm/lkcapi_rsa_glue.c:765-836`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: linuxkm direct RSA path enabled; caller supplies `req->dst_len < key_len`.
- evidence: the code allocates `malloc(req->dst_len)` but calls `wc_RsaDirect(..., dec, &out_len, ...)` with `out_len = ctx->key_len`, advertising the short buffer as full-size to wolfCrypt.
- impact: kernel heap overwrite before the later size check runs; local DoS and possible privilege escalation.
- recommendation: reject short destination buffers before decrypt, or pass the real allocation size into `wc_RsaDirect()`.
- reference: `ASVS 5.0 V15 Secure Coding and Architecture`

### 3. QNX CAAM resource manager is world-writable and its owner table is undersized
- location: `wolfcrypt/src/port/caam/caam_qnx.c:66-68,1386,1502-1509,1566-1575`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: local user can open `/dev/wolfCrypt` on a QNX system using this CAAM backend.
- evidence: the device node is created mode `0666`; read/write/free devctls do not enforce partition ownership; `sm_ownerId[MAX_PART]` is sized with `MAX_PART 7` while the driver uses partitions `0..14`.
- impact: any local user can read, overwrite, or free another process's secure partition, and partition tracking itself can write past the owner table.
- recommendation: restrict device permissions, enforce owner checks on every devctl, size the owner table to the real partition range, and reject out-of-range IDs.
- reference: `ASVS 5.0 V8 Authorization`, `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 4. Several hardware AEAD backends can accept forged ciphertext or write past caller buffers
- location: `wolfcrypt/src/port/caam/wolfcaam_seco.c:994-1078`; `wolfcrypt/src/port/intel/quickassist.c:2208-2273,2526-2537`; `wolfcrypt/src/port/intel/quickassist_sync.c:921,1041,1084-1113,1156-1179,1264-1288`; `wolfcrypt/src/port/devcrypto/devcrypto_aes.c:309-364`; `wolfcrypt/src/port/af_alg/afalg_aes.c:558,683,759,860,894`; `wolfcrypt/src/port/aria/aria-crypt.c:203-296`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: affected backend enabled; attacker can submit crafted GCM ciphertext or rely on oversized caller-controlled IV/tag/output lengths.
- evidence: SECO drops `hsm_auth_enc()` failure and returns success; async QAT ignores `verifyResult`; sync QAT ignores `cpaCySymPerformOp()` status and can copy stale/plaintext out on failure; sync QAT GCM copies caller IVs into a fixed 16-byte heap buffer; devcrypto/af_alg/ARIA backends append tags into caller buffers despite the public separate-buffer contract.
- impact: authentication bypass on AEAD decrypt, stale/plaintext disclosure on backend failure, and heap/caller-buffer overflows.
- recommendation: fail closed on every backend error and tag mismatch, propagate auth status back to the caller, and enforce exact public buffer contracts and IV size limits in every backend.
- reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V12 Secure Communication`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 5. Multiple RNG backends are predictable or can report success after entropy failure
- location: `wolfcrypt/src/random.c:1088-1117,2467-2477,2784-2868,3138-3149,3432-3540,3590-3628,3864-3876`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: build selects one of the affected `wc_GenerateSeed()` branches.
- evidence: `USE_TEST_GENSEED` returns deterministic `output[i] = (byte)i`; several branches seed `rand()/rand_r()/random()` from clocks/counters; the Cypress HAL path returns success even when `cyhal_trng_init()` fails.
- impact: predictable or stale DRBG seed material compromises generated keys, IVs, nonces, and session secrets.
- recommendation: remove test and time-based fallbacks from production paths, require a real OS/HW entropy source, and fail closed if seeding fails.
- reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V13 Configuration`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 6. Private-key math backends still use secret-dependent timing and table access
- location: `wolfcrypt/src/sp_arm64.c:4165,4185,4318,4338,5760,5780,5946,5966,6242,6299,6303,6717,6737,6810-6814`; `wolfcrypt/src/integer.c:893-995,1032-1327,2013-2216,3076-3130,3749-3915`; config `wolfssl/wolfcrypt/integer.h:319,350,373`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: attacker can trigger repeated private RSA/DH/ECC operations on affected builds and observe timing/cache behavior.
- evidence: ARM64 SP math uses secret-derived window values directly in table lookups and shifts such as `XMEMCPY(r, t[y], ...)`, `sp_2048_mont_mul_16(..., t[y], ...)`, and `sp_2048_lshift_32(..., y)`; heap math uses secret-dependent windows in `mp_exptmod_fast()` and data-dependent loops in `fast_mp_invmod()`, despite `_ct` naming on some helpers.
- impact: side-channel recovery of RSA CRT exponents, DH secrets, ECDH scalars, or signing nonces.
- recommendation: keep these backends off secret-key paths unless they are made genuinely constant-time; use constant-time selection/ladders and stop aliasing variable-time helpers as `_ct`.
- reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V15 Secure Coding and Architecture`, `grugbrain: local reasoning`

### 7. PKCS#11 fallback private-key lookup can silently select the wrong key
- location: `wolfcrypt/src/wc_pkcs11.c:2029-2057,2924-2971,3994-4028`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: token/HSM contains multiple matching keys and the caller omits a stable identity such as `CKA_ID`, label, bound public key, or `devCtx`.
- evidence: EC private lookup matches only class, key type, curve params, and usage; ML-DSA lookup matches only class, key type, and parameter set; `Pkcs11FindKeyByTemplate()` takes the first `C_FindObjects(..., 1, count)` result and does not reject ambiguity.
- impact: sign, ECDH, or private-key-check operations can bind to the wrong identity or tenant key on shared tokens.
- recommendation: require a stable key identity (`CKA_ID`/label/public-key binding) and fail unless exactly one object matches.
- reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 8. Exported ML-KEM helpers trust caller lengths and can read or write past buffers
- location: `wolfcrypt/src/wc_mlkem_poly.c:3122-3145,3160-3171,3190-3203`; declarations `wolfssl/wolfcrypt/wc_mlkem.h:178,193`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: external caller reaches the exported helpers with malformed lengths.
- evidence: `mlkem_kdf()` fills a fixed local state from `seedLen / 8`, ignores non-8-byte tails, does not cap `seedLen` to local storage, and then `XMEMCPY(out, state, outLen)`; `mlkem_derive_secret()` subtracts a fixed prefix from `word32 ctSz` and hashes the underflowed length.
- impact: stack OOB read/write, wrong derived secrets, and seed-truncation collisions.
- recommendation: replace the shortcuts with validated SHAKE absorb/squeeze over exact byte lengths and reject underflow/oversize inputs.
- reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 9. Post-quantum key export paths overrun caller buffers or leak adjacent private bytes
- location: `wolfcrypt/src/sphincs.c:626-670,984-1019`; `wolfcrypt/src/falcon.c:926-941`; sink `wolfcrypt/src/asn.c:38661-38721`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: application exports SPHINCS or Falcon keys through these public APIs.
- evidence: `wc_sphincs_export_private()` advertises `SPHINCS_LEVELn_PRV_KEY_SIZE` and then copies the public key at `out + SPHINCS_LEVELn_PRV_KEY_SIZE`; Falcon/SPHINCS `*_KeyToDer()` pass private-key sizes as `pubKeyLen`, so DER export over-reads from `key->p` into adjacent `key->k` bytes.
- impact: caller-buffer overflow and private-byte disclosure in serialized key output.
- recommendation: use the real public-key lengths and exact layout sizes; add exact-size export tests for every level.
- reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V14 Data Protection`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 10. Hexagon DSP ECC verify uses 10-limb RPC buffers as 20-limb workspaces
- location: `wolfcrypt/src/sp_dsp32.c:4429-4475,723,4149-4234`; host stub `wolfcrypt/src/wc_dsp.c:272-277,295`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: `WOLFSSL_DSP` P-256 verify path enabled.
- evidence: the host passes `u1/u2/s/x/y/z` buffers sized for 10 limbs, but the DSP code calls `sp_256_mul_10()` and related helpers that write 20 digits (`r[19]`, `2 * 10` copies).
- impact: deterministic OOB writes in DSP verify; realistic crash/DoS and possible code execution depending on RPC layout.
- recommendation: allocate local 20-limb scratch for wide intermediates and validate all caller-supplied workspace sizes before use.
- reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 11. `wolfSSL_X509_set_serialNumber()` copies unbounded ASN.1 INTEGER content into a 32-byte fixed buffer
- location: `src/x509.c:16095-16109`; storage `wolfssl/internal.h:5401-5402`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: caller passes a long ASN.1 INTEGER to the OpenSSL-compat setter.
- evidence: after minimal tag and length checks the code does `XMEMCPY(x509->serial, s->data + 2, s->length - 2); x509->serial[x509->serialSz] = 0;` with no `EXTERNAL_SERIAL_SIZE` bound check.
- impact: adjacent `WOLFSSL_X509` memory corruption.
- recommendation: reject oversize serials or move serial storage to checked dynamic allocation.
- reference: `ASVS 5.0 V1 Encoding and Sanitization`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 12. Persistent session-cache restore rehydrates raw pointers from serialized struct images
- location: `src/ssl_sess.c:487-524,634-683,3910,3982,4092-4108`; pointer-bearing layout `wolfssl/internal.h:4690,4723,4731,4733`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: `PERSIST_SESSION_CACHE` build restores cache data after restart or from non-fully-trusted input.
- evidence: save and restore paths `XMEMCPY` or `XFREAD` entire `WOLFSSL_SESSION` structs even though the struct embeds owning pointers such as `peer`, `ticket`, and `ticketNonce`.
- impact: stale or attacker-controlled pointer values can later be dereferenced or freed during resume/eviction, causing crash, UAF, or heap corruption.
- recommendation: serialize only POD fields and rebuild owned buffers on restore; never persist raw in-memory struct images.
- reference: `ASVS 5.0 V14 Data Protection`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 13. DTLS 1.3 retransmit/ACK handling has lock leaks and unsynchronized queue mutation
- location: `src/dtls13.c:649-675,723-757,1596-1643,2659-2683,2945-2976`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: DTLS 1.3 build enabled, especially `WOLFSSL_RW_THREADED`; peer can retransmit or duplicate handshake records.
- evidence: `Dtls13RtxAddAck()` returns from duplicate and error branches while still holding `dtls13Rtx.mutex`; traversal and unlink/free paths mutate `rtxRecords` without one consistent lock.
- impact: connection deadlock, retransmit-queue corruption, or UAF from network-triggered traffic patterns.
- recommendation: use one unlock/cleanup epilogue and guard all retransmit-queue mutation with a single lock or explicit reference management.
- reference: `ASVS 5.0 V15 Secure Coding and Architecture`, `grugbrain: local reasoning`

### 14. Public-key and parameter validation APIs accept malformed or weak inputs as “checked”
- location: `wolfcrypt/src/evp.c:4045-4132`; `wolfcrypt/src/dh.c:1732-1804,2452-2597,2902-2988`; `wolfcrypt/src/dsa.c:425-466,1006-1117`; `wolfcrypt/src/curve25519.c:662-767,837-932`; callers `src/pk.c:5200,5209`, `wolfcrypt/src/hpke.c:412,818,1061`, `src/internal.c:32433-32449`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: attacker controls imported DH/DSA parameters or peer X25519 public keys.
- evidence: `DH_param_check()` only tests oddness of `p` and leaves safe-prime validation as `TODO`; checked DH import validates only `p`; DSA import accepts unchecked `g`, so `g = 1, y = 1` can make signatures with `r = 1` verify; `wc_curve25519_import_public_ex()` copies bytes and sets `pubSet` without `wc_curve25519_check_public()`, and all-zero shared-secret rejection is only behind an opt-in macro.
- impact: weak or degenerate groups and low-order peer keys can be treated as validated, enabling predictable shared secrets or signature acceptance in code that trusts these APIs.
- recommendation: enforce full domain-parameter and public-key invariants on import, and always reject all-zero X25519 shared secrets.
- reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V15 Secure Coding and Architecture`

### 15. Release artifacts and SDK headers ship reusable private test keys
- location: representative paths `certs/1024/include.am:5-24`, `certs/ed25519/include.am:6-31`, `certs/rsapss/include.am:5-55`, `certs/p521/include.am:6-30`, `certs/ed448/include.am:6-30`, `wolfssl/certs_test.h:707,1510,1880`, `IDE/XCODE/wolfssl.xcodeproj/project.pbxproj:1989-1991,2017,2043-2045,2071`
- category: security
- severity: high
- status: candidate
- exploitability/preconditions: integrator or sample-derived deployment reuses bundled identities or installs `certs_test.h`-backed SDK surfaces.
- evidence: release manifests place root, CA, server, and client private keys in `EXTRA_DIST`; `certs_test.h` embeds arrays such as `client_key_der_*`, `ca_key_der_*`, and `server_key_der_*`; Apple Xcode targets copy `certs_test.h` into installed headers.
- impact: anyone with repo access can clone sample identities or mint certificates under shipped test CAs wherever those fixtures leak into real environments.
- recommendation: stop shipping private keys and test key buffers in release or SDK artifacts; generate lab fixtures during CI/tests and require local credential injection for examples.
- reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V13 Configuration`, `ASVS 5.0 V14 Data Protection`, `ASVS 5.0 V15 Secure Coding and Architecture`

## Other confirmed issues kept concise

- `wolfcrypt/src/chacha_asm.asm:65-68,160-172,203-218,263-266,358-370,401-404` — Windows x64 non-AVX scalar ChaCha MASM fallback overwrites state words and emits duplicated output words, producing a non-standard keystream and remote TLS/ChaCha20-Poly1305 failures on affected builds. Category: security. Severity: high. Status: candidate. Recommendation: delete or regenerate the MASM scalar path from the verified `.S` source. Reference: `ASVS 5.0 V11 Cryptography`, `grugbrain: avoid wrong abstraction`.
- `src/ocsp.c:534-547` — missing OCSP responder URL returns `CERT_GOOD`, a fail-open revocation decision. Category: security. Severity: medium. Status: candidate. Recommendation: treat missing responder data as indeterminate/error, not good. Reference: `ASVS 5.0 V12 Secure Communication`, `ASVS 5.0 V15 Secure Coding and Architecture`.
- Examples and board samples across `examples/*`, `IDE/*`, `mqx/*`, and `wrapper/CSharp/*` repeatedly load a CA but never call `wolfSSL_CTX_set_verify(..., WOLFSSL_VERIFY_PEER, ...)` or bind hostname/IP, and several servers accept unauthenticated `shutdown` or `quit` strings over the network. Category: security. Severity: medium. Status: candidate. Impact: easy MITM or remote DoS when sample code is reused. Reference: `ASVS 5.0 V12 Secure Communication`, `ASVS 5.0 V15 Secure Coding and Architecture`.
- Many shipped embedded profiles (`IDE/Renesas/*/user_settings.h`, `IDE/MDK5-ARM/Conf/user_settings.h`, `IDE/IAR-EWARM/Projects/user_settings.h`, `IDE/KDS/config/user_settings.h`, `IDE/ECLIPSE/RTTHREAD/user_settings.h`, and others) enable deterministic test seeding or fake certificate time by default. Category: security. Severity: high/medium. Status: candidate. Impact: predictable keys/nonces or stale certificate validation in sample-derived builds. Reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V12 Secure Communication`, `ASVS 5.0 V13 Configuration`.
- CI and packaging trust is too loose: `.github/workflows/memcached.yml` bind-mounts host `/` into a container and `chroot`s into it; `.github/workflows/socat.yml` downloads over plain HTTP; several workflows pull mutable `wolfssl/osp` or `master`; `Docker/run.sh` mounts host `~/.ssh`; `Docker/wolfCLU/Dockerfile` and `Docker/yocto/Dockerfile` fetch over HTTP or `git://` and execute as root. Category: security. Severity: high. Status: candidate. Impact: CI/developer supply-chain compromise and credential exfiltration. Reference: `ASVS 5.0 V12 Secure Communication`, `ASVS 5.0 V13 Configuration`, `ASVS 5.0 V15 Secure Coding and Architecture`.
- OpenSSL compatibility surfaces contain security-relevant no-ops: compatibility flags and locking hooks compile but do not enforce equivalent behavior (`wolfssl/openssl/ssl.h` and related compat paths). Category: complexity/security. Severity: medium. Status: candidate. Impact: ported applications can silently lose enforcement while still building cleanly. Reference: `ASVS 5.0 V13 Configuration`, `ASVS 5.0 V15 Secure Coding and Architecture`, `grugbrain: local reasoning`.
- Safe-language wrappers in `wrapper/rust/*`, `wrapper/CSharp/*`, and `wrapper/Ada/*` expose unsound FFI patterns such as borrowed pointers outliving owners, arbitrary typed buffers treated as raw byte outputs, `assume_init()` on uninitialized state, or freeing borrowed native pointers. Category: security. Severity: medium. Status: candidate. Impact: safe-language callers can trigger UB, UAF, or OOB access without `unsafe`. Reference: `ASVS 5.0 V15 Secure Coding and Architecture`.
- Repeated secret-lifetime gaps across PKCS#7, EVP, PQ, and math backends leave sensitive material resident after free or return. Category: security. Severity: medium. Status: candidate. Impact: later disclosure via crash dumps or allocator reuse. Reference: `ASVS 5.0 V11 Cryptography`, `ASVS 5.0 V14 Data Protection`.
- More public helper boundary bugs remain beyond the detailed list: `wolfcrypt/src/asn.c:6606-6660` `EncodeObjectId()` OOB read, `wolfcrypt/src/kdf.c:355-405` HKDF extract writes through caller `ikm`, `wolfcrypt/src/wolfmath.c:223-252` `wc_export_int()` pointer underflow, and size/path bugs in `wolfcrypt/src/coding.c`. Category: security. Severity: medium. Status: candidate. Impact: OOB read/write, truncation, and parser inconsistencies. Reference: `ASVS 5.0 V1 Encoding and Sanitization`, `ASVS 5.0 V15 Secure Coding and Architecture`.
- Backend and assembly duplication is already producing divergent behavior (`chacha_asm.asm` vs `.S`, duplicated PQ NTT cores, many parallel GCM/ASM paths). Category: complexity. Severity: medium. Status: candidate. Impact: fixes are easy to miss and review becomes audit-hostile. Reference: `grugbrain: avoid wrong abstraction`, `grugbrain: local reasoning`.
