#// crypto.h - v9.0 (RAII & HKDF)
#pragma once

#include <openssl/evp.h>
#include <string>
#include <vector>
#include <memory> // 引入智能指针

// --- RAII: 为 EVP_PKEY 设计的智能指针 ---
// 自定义删除器，以便 unique_ptr 知道如何释放 EVP_PKEY
struct PKeyDeleter {
    void operator()(EVP_PKEY* pkey) const {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }
};
// 定义一个易于使用的类型别名
using UniquePKey = std::unique_ptr<EVP_PKEY, PKeyDeleter>;


// --- 函数签名全部更新为使用智能指针 ---

// 初始化和清理OpenSSL库
void InitializeOpenSSL();
void CleanupOpenSSL();

// --- 密钥生成 ---
// 现在返回 UniquePKey，所有权被安全地转移
UniquePKey GenerateRsaKeyPair(int bits);
UniquePKey GenerateEcKeyPair();

// --- 密钥格式转换 (PEM) ---
// 参数为裸指针，因为这些函数不获取所有权
std::string PublicKeyToPEM(EVP_PKEY* pkey);
std::string PrivateKeyToPEM(EVP_PKEY* pkey, const std::string& password);
UniquePKey PEMToPublicKey(const std::string& pem);
UniquePKey PEMToPrivateKey(const std::string& pem, const std::string& password);
UniquePKey ExtractPublicKey(EVP_PKEY* privateKey);

// --- 数字签名 (RSA-SHA256) ---
// 参数为裸指针，因为这些函数不获取所有权
bool SignData(EVP_PKEY* private_rsa_key, const std::vector<char>& data, std::vector<unsigned char>& signature);
bool VerifySignature(EVP_PKEY* public_rsa_key, const std::vector<char>& data, const std::vector<unsigned char>& signature);

// --- 密钥派生 (ECDH & HKDF) ---
bool DeriveSharedSecret(EVP_PKEY* my_private_key, EVP_PKEY* peer_public_key, std::vector<unsigned char>& shared_secret);
// 新增: 标准的 HKDF 函数
bool HkdfSha256(std::vector<unsigned char>& out_key, size_t out_len, const std::vector<unsigned char>& secret, const std::vector<unsigned char>& salt, const std::vector<unsigned char>& info);

// --- 对称加密 ---
bool AesGcmEncrypt(const std::vector<unsigned char>& key,
                   const std::vector<unsigned char>& iv,
                   const std::vector<unsigned char>& plain,
                   std::vector<unsigned char>& encrypted,
                   std::vector<unsigned char>& tag);
bool AesGcmDecrypt(const std::vector<unsigned char>& key,
                   const std::vector<unsigned char>& iv,
                   const std::vector<unsigned char>& encrypted,
                   const std::vector<unsigned char>& tag,
                   std::vector<unsigned char>& decrypted);

// --- 其它 ---
bool GenerateRandomBytes(std::vector<unsigned char>& buffer);
std::string GetPublicKeyFingerprint(EVP_PKEY* pkey);