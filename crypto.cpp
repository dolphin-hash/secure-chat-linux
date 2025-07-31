// crypto.cpp - v9.1 (带详细错误日志的调试版)
#include "crypto.h"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <sstream>
#include <iomanip>
#include <iostream> // 为调试日志引入

// --- 自定义删除器 ---
struct BIO_deleter { void operator()(BIO* b) const { BIO_free_all(b); } };
using unique_bio_ptr = std::unique_ptr<BIO, BIO_deleter>;

struct PKeyCtxDeleter { void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); } };
using UniquePKeyCtx = std::unique_ptr<EVP_PKEY_CTX, PKeyCtxDeleter>;

struct MdCtxDeleter { void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); } };
using UniqueMdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

struct CipherCtxDeleter { void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); } };
using UniqueCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

#include <openssl/rsa.h>
#include <openssl/ec.h>
struct RsaDeleter { void operator()(RSA* r) const { RSA_free(r); } };
using UniqueRsa = std::unique_ptr<RSA, RsaDeleter>;

struct EcKeyDeleter { void operator()(EC_KEY* ec) const { EC_KEY_free(ec); } };
using UniqueEcKey = std::unique_ptr<EC_KEY, EcKeyDeleter>;

// --- 辅助函数：打印OpenSSL错误栈 ---
void PrintOpenSSLErrors(const std::string& context) {
    std::cerr << "--- OpenSSL Error in " << context << " ---" << std::endl;
    ERR_print_errors_fp(stderr);
    std::cerr << "---------------------------------------" << std::endl;
}


// --- 实现 ---
void InitializeOpenSSL() { ERR_load_crypto_strings(); OpenSSL_add_all_algorithms(); }
void CleanupOpenSSL() { EVP_cleanup(); ERR_free_strings(); }

std::string PublicKeyToPEM(EVP_PKEY* pkey) { if (!pkey) return ""; unique_bio_ptr bio(BIO_new(BIO_s_mem())); if (!PEM_write_bio_PUBKEY(bio.get(), pkey)) return ""; char* data; long len = BIO_get_mem_data(bio.get(), &data); return std::string(data, len); }
std::string PrivateKeyToPEM(EVP_PKEY* pkey, const std::string& password) { if (!pkey) return ""; unique_bio_ptr bio(BIO_new(BIO_s_mem())); if (!bio) return ""; const EVP_CIPHER* cipher = EVP_aes_256_cbc(); if (!PEM_write_bio_PrivateKey(bio.get(), pkey, cipher, (unsigned char*)password.c_str(), password.length(), NULL, NULL)) { return ""; } char* data; long len = BIO_get_mem_data(bio.get(), &data); return std::string(data, len); }

UniquePKey GenerateRsaKeyPair(int bits) {
    UniquePKey pkey(EVP_PKEY_new());
    if (!pkey) return nullptr;
    UniquePKeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL));
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) return nullptr;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) return nullptr;
    EVP_PKEY* temp_pkey = pkey.get();
    if (EVP_PKEY_keygen(ctx.get(), &temp_pkey) <= 0) return nullptr;
    return pkey;
}

UniquePKey GenerateEcKeyPair() {
    UniquePKey params(EVP_PKEY_new());
    UniquePKeyCtx pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
    if (!pctx) return nullptr;
    if (EVP_PKEY_paramgen_init(pctx.get()) <= 0) return nullptr;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0) return nullptr;
    EVP_PKEY* temp_params = params.get();
    if (EVP_PKEY_paramgen(pctx.get(), &temp_params) <= 0) return nullptr;
    UniquePKeyCtx kctx(EVP_PKEY_CTX_new(params.get(), NULL));
    if (!kctx) return nullptr;
    UniquePKey ec_key(EVP_PKEY_new());
    if (EVP_PKEY_keygen_init(kctx.get()) <= 0) return nullptr;
    EVP_PKEY* temp_key = ec_key.get();
    if (EVP_PKEY_keygen(kctx.get(), &temp_key) <= 0) return nullptr;
    return ec_key;
}

UniquePKey PEMToPublicKey(const std::string& pem) { if (pem.empty()) return nullptr; unique_bio_ptr bio(BIO_new_mem_buf(pem.c_str(), -1)); return UniquePKey(PEM_read_bio_PUBKEY(bio.get(), NULL, NULL, NULL)); }
UniquePKey PEMToPrivateKey(const std::string& pem, const std::string& password) { if (pem.empty()) return nullptr; unique_bio_ptr bio(BIO_new_mem_buf(pem.c_str(), -1)); return UniquePKey(PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, (void*)password.c_str())); }
UniquePKey ExtractPublicKey(EVP_PKEY* privateKey) {
    if (!privateKey) return nullptr;

    int key_type = EVP_PKEY_base_id(privateKey);

    if (key_type == EVP_PKEY_RSA) {
        UniqueRsa rsa(EVP_PKEY_get1_RSA(privateKey));
        if (!rsa) return nullptr;
        UniquePKey pubKey(EVP_PKEY_new());
        if (!pubKey) return nullptr;
        if (EVP_PKEY_set1_RSA(pubKey.get(), rsa.get()) <= 0) return nullptr;
        return pubKey;
    }

    if (key_type == EVP_PKEY_EC) {
        UniqueEcKey ec_key(EVP_PKEY_get1_EC_KEY(privateKey));
        if (!ec_key) return nullptr;
        EC_KEY_set_private_key(ec_key.get(), NULL);
        UniquePKey pubKey(EVP_PKEY_new());
        if (!pubKey) return nullptr;
        if (EVP_PKEY_set1_EC_KEY(pubKey.get(), ec_key.get()) <= 0) return nullptr;
        return pubKey;
    }
    return nullptr;
}

bool HkdfSha256(std::vector<unsigned char>& out_key, size_t out_len, const std::vector<unsigned char>& secret, const std::vector<unsigned char>& salt, const std::vector<unsigned char>& info) {
    ERR_clear_error();
    UniquePKeyCtx pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL));
    if (!pctx) { PrintOpenSSLErrors("HkdfSha256 - EVP_PKEY_CTX_new_id"); return false; }
    
    out_key.resize(out_len);

    if (EVP_PKEY_derive_init(pctx.get()) <= 0) { PrintOpenSSLErrors("HkdfSha256 - EVP_PKEY_derive_init"); return false; }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) <= 0) { PrintOpenSSLErrors("HkdfSha256 - EVP_PKEY_CTX_set_hkdf_md"); return false; }
    
    // --- 核心修正 ---
    // 只在 salt 向量不为空时才设置它。如果为空，则让 OpenSSL 使用其默认行为。
    if (!salt.empty()) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.data(), salt.size()) <= 0) { 
            PrintOpenSSLErrors("HkdfSha256 - EVP_PKEY_CTX_set1_hkdf_salt"); 
            return false; 
        }
    }
    // --- 修正结束 ---

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), secret.data(), secret.size()) <= 0) { PrintOpenSSLErrors("HkdfSha256 - EVP_PKEY_CTX_set1_hkdf_key"); return false; }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), info.data(), info.size()) <= 0) { PrintOpenSSLErrors("HkdfSha256 - EVP_PKEY_CTX_add1_hkdf_info"); return false; }
    
    size_t key_len = out_len;
    if (EVP_PKEY_derive(pctx.get(), out_key.data(), &key_len) <= 0) { PrintOpenSSLErrors("HkdfSha256 - EVP_PKEY_derive"); return false; }
    
    out_key.resize(key_len);
    return true;
}

bool DeriveSharedSecret(EVP_PKEY* my_private_key, EVP_PKEY* peer_public_key, std::vector<unsigned char>& shared_secret) {
    ERR_clear_error();
    if (!my_private_key || !peer_public_key) {
        std::cerr << "DEBUG: DeriveSharedSecret received a NULL key." << std::endl;
        return false;
    }

    UniquePKeyCtx ctx(EVP_PKEY_CTX_new(my_private_key, NULL));
    if (!ctx) { PrintOpenSSLErrors("DeriveSharedSecret - EVP_PKEY_CTX_new"); return false; }

    if (EVP_PKEY_derive_init(ctx.get()) <= 0) { PrintOpenSSLErrors("DeriveSharedSecret - EVP_PKEY_derive_init"); return false; }
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key) <= 0) { PrintOpenSSLErrors("DeriveSharedSecret - EVP_PKEY_derive_set_peer"); return false; }

    size_t secret_len;
    if (EVP_PKEY_derive(ctx.get(), NULL, &secret_len) <= 0) { PrintOpenSSLErrors("DeriveSharedSecret - EVP_PKEY_derive (get len)"); return false; }
    
    shared_secret.resize(secret_len);
    if (secret_len == 0) {
        std::cerr << "DEBUG: DeriveSharedSecret resulted in a zero-length secret." << std::endl;
        return false; // A zero length secret is not useful
    }

    if (EVP_PKEY_derive(ctx.get(), shared_secret.data(), &secret_len) <= 0) { PrintOpenSSLErrors("DeriveSharedSecret - EVP_PKEY_derive (get data)"); return false; }
    
    shared_secret.resize(secret_len);
    return true;
}

bool SignData(EVP_PKEY* private_rsa_key, const std::vector<char>& data, std::vector<unsigned char>& signature) {
    if (!private_rsa_key || data.empty()) return false;
    UniqueMdCtx md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) return false;
    size_t sig_len;
    if (EVP_DigestSignInit(md_ctx.get(), NULL, EVP_sha256(), NULL, private_rsa_key) <= 0 || EVP_DigestSignUpdate(md_ctx.get(), data.data(), data.size()) <= 0 || EVP_DigestSignFinal(md_ctx.get(), NULL, &sig_len) <= 0) return false;
    signature.resize(sig_len);
    if (EVP_DigestSignFinal(md_ctx.get(), signature.data(), &sig_len) <= 0) return false;
    signature.resize(sig_len);
    return true;
}

bool VerifySignature(EVP_PKEY* public_rsa_key, const std::vector<char>& data, const std::vector<unsigned char>& signature) {
    if (!public_rsa_key || data.empty() || signature.empty()) return false;
    UniqueMdCtx md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) return false;
    if (EVP_DigestVerifyInit(md_ctx.get(), NULL, EVP_sha256(), NULL, public_rsa_key) <= 0 || EVP_DigestVerifyUpdate(md_ctx.get(), data.data(), data.size()) <= 0) return false;
    return EVP_DigestVerifyFinal(md_ctx.get(), signature.data(), signature.size()) == 1;
}

std::string GetPublicKeyFingerprint(EVP_PKEY* pkey) { if (!pkey) return "[INVALID KEY]"; unsigned char* der_bytes = NULL; int der_len = i2d_PUBKEY(pkey, &der_bytes); if (der_len <= 0) return "[DER ENCODING FAILED]"; unsigned char hash[SHA256_DIGEST_LENGTH]; SHA256(der_bytes, der_len, hash); OPENSSL_free(der_bytes); std::stringstream ss; ss << std::hex << std::setfill('0'); for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) { ss << std::setw(2) << static_cast<int>(hash[i]); if (i < SHA256_DIGEST_LENGTH - 1) { ss << ":"; } } return ss.str(); }

bool AesGcmEncrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& plain, std::vector<unsigned char>& encrypted, std::vector<unsigned char>& tag) {
    UniqueCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return false;
    encrypted.resize(plain.size());
    tag.resize(16);
    int len = 0;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, key.data(), iv.data()) != 1) return false;
    if (EVP_EncryptUpdate(ctx.get(), encrypted.data(), &len, plain.data(), plain.size()) != 1) return false;
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), encrypted.data() + len, &final_len) != 1) return false;
    encrypted.resize(len + final_len);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) return false;
    return true;
}

bool AesGcmDecrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& encrypted, const std::vector<unsigned char>& tag, std::vector<unsigned char>& decrypted) {
    UniqueCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return false;
    decrypted.resize(encrypted.size());
    int len = 0, plaintext_len = 0;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, key.data(), iv.data()) != 1) return false;
    if (EVP_DecryptUpdate(ctx.get(), decrypted.data(), &len, encrypted.data(), encrypted.size()) != 1) return false;
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()) != 1) return false;
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), decrypted.data() + len, &final_len) != 1) {
        decrypted.clear();
        return false;
    }
    plaintext_len += final_len;
    decrypted.resize(plaintext_len);
    return true;
}

bool GenerateRandomBytes(std::vector<unsigned char>& buffer) { if (buffer.empty()) return false; return RAND_bytes(buffer.data(), buffer.size()) == 1; }