// client.cpp - 适用于 Linux 的版本
#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <vector>
#include <map>
#include <mutex>
#include <filesystem>
#include <cstdlib>
#include <sstream>
#include <openssl/sha.h>

// --- Linux 网络编程头文件 ---
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> // for close()

#include "crypto.h"

// --- 为跨平台兼容性定义 Windows 类型 ---
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket(s) close(s)
#define SD_SEND SHUT_WR // 在 Linux 中，SD_SEND 等价于 SHUT_WR

#define SERVER_PORT "8888"
#define SERVER_ADDRESS "127.0.0.1"
#define MAX_BUFFER_SIZE 16384
#define RSA_KEY_BITS 2048

#define COL_RESET "\033[0m"
#define COL_GREEN "\033[32m"
#define COL_RED "\033[31m"
#define COL_YELLOW "\033[33m"

enum class MessageType : uint8_t {
    LOGIN_REQUEST_PFS = 10,
    LOGIN_SUCCESS = 2,
    LOGIN_FAILURE = 3,
    USER_LIST_UPDATE_PFS = 11,
    CHAT_MESSAGE_PFS = 12,
};

struct PeerInfo {
    UniquePKey rsa_pub_key;
    UniquePKey ec_pub_key;
};

UniquePKey g_my_rsa_private_key = nullptr;
UniquePKey g_my_ec_session_key = nullptr;
std::string g_my_username;
std::map<std::string, PeerInfo> g_peers;
std::mutex g_peers_mutex;
bool g_is_running = true;

std::map<std::string, std::string> g_trusted_fingerprints;
std::mutex g_fingerprints_mutex;

bool SendPacket(SOCKET sock, const std::vector<char>& packet) {
    if (sock == INVALID_SOCKET || packet.empty()) return false;
    uint32_t packet_size = packet.size();
    if (send(sock, (char*)&packet_size, sizeof(packet_size), 0) == SOCKET_ERROR) return false;
    if (send(sock, packet.data(), packet_size, 0) == SOCKET_ERROR) return false;
    return true;
}

bool ReceivePacket(SOCKET sock, std::vector<char>& out_packet) {
    uint32_t packet_size;
    // 在 Linux 中，recv 的 MSG_WAITALL 行为可能略有不同，但通常是可用的
    int bytes_received = recv(sock, (char*)&packet_size, sizeof(packet_size), MSG_WAITALL);
    if (bytes_received <= 0) return false;
    if (packet_size > MAX_BUFFER_SIZE) {
        std::cerr << "错误: 数据包大小 " << packet_size << " 超出最大缓冲限制。\n";
        return false;
    }
    out_packet.resize(packet_size);
    bytes_received = recv(sock, out_packet.data(), packet_size, MSG_WAITALL);
    if (bytes_received <= 0) return false;
    return true;
}

std::filesystem::path GetTrustedPeersFilePath() {
    // 在 Linux 上使用 getenv("HOME")
    const char* homeDir = getenv("HOME");
    if (homeDir == nullptr) return {};
    return std::filesystem::path(homeDir) / ".securechat" / "keys" / g_my_username / "trusted_peers.dat";
}

void LoadTrustedPeers() {
    std::filesystem::path file_path = GetTrustedPeersFilePath();
    if (!std::filesystem::exists(file_path)) return;
    std::ifstream file(file_path);
    if (!file.is_open()) return;
    std::lock_guard<std::mutex> lock(g_fingerprints_mutex);
    g_trusted_fingerprints.clear();
    std::string line, username, fingerprint;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        if (std::getline(ss, username, ':') && std::getline(ss, fingerprint)) {
            g_trusted_fingerprints[username] = fingerprint;
        }
    }
    file.close();
}

void SaveTrustedPeers() {
    std::filesystem::path file_path = GetTrustedPeersFilePath();
    std::filesystem::create_directories(file_path.parent_path());
    std::ofstream file(file_path);
    if (!file.is_open()) {
        std::cerr << "错误: 无法写入可信指纹文件。\n";
        return;
    }
    std::lock_guard<std::mutex> lock(g_fingerprints_mutex);
    for (const auto& pair : g_trusted_fingerprints) {
        file << pair.first << ":" << pair.second << "\n";
    }
    file.close();
}

struct PrintMessage {
    bool is_warning;
    std::string text;
};

void UpdatePeerKeysPFS(const char* buffer, int len) {
    std::vector<PrintMessage> message_queue;
    std::map<std::string, std::string> verified_peers_for_display;
    bool needs_saving = false;
    uint16_t final_user_count = 0;

    {
        std::scoped_lock lock(g_peers_mutex, g_fingerprints_mutex);
        g_peers.clear();
        const char* p = buffer;
        memcpy(&final_user_count, p, sizeof(uint16_t)); p += sizeof(uint16_t);

        for (int i = 0; i < final_user_count; ++i) {
            uint8_t name_len;
            memcpy(&name_len, p, sizeof(name_len)); p += sizeof(name_len);
            std::string username(p, name_len); p += name_len;
            
            uint16_t rsa_pem_len;
            memcpy(&rsa_pem_len, p, sizeof(rsa_pem_len)); p += sizeof(rsa_pem_len);
            std::string rsa_pem(p, rsa_pem_len); p += rsa_pem_len;
            
            uint16_t ec_pem_len;
            memcpy(&ec_pem_len, p, sizeof(ec_pem_len)); p += sizeof(ec_pem_len);
            std::string ec_pem(p, ec_pem_len); p += ec_pem_len;

            if (username == g_my_username) continue;

            auto rsa_pub_key_tofu = PEMToPublicKey(rsa_pem);
            if (!rsa_pub_key_tofu) {
                message_queue.push_back({true, COL_YELLOW "[警告] " COL_RESET "用户 '" + username + "' 的RSA公钥无效，已忽略。"});
                continue;
            }
            
            std::string current_fingerprint = GetPublicKeyFingerprint(rsa_pub_key_tofu.get());
            auto it = g_trusted_fingerprints.find(username);

            auto handle_peer = [&](auto& rsa_key) {
                auto ec_pub_key = PEMToPublicKey(ec_pem);
                if (!ec_pub_key) {
                    message_queue.push_back({true, COL_YELLOW "[警告] " COL_RESET "用户 '" + username + "' 的EC会话公钥无效，已忽略。"});
                    return;
                }
                g_peers.emplace(username, PeerInfo{std::move(rsa_key), std::move(ec_pub_key)});
                verified_peers_for_display[username] = current_fingerprint;
            };

            if (it == g_trusted_fingerprints.end()) {
                g_trusted_fingerprints[username] = current_fingerprint;
                needs_saving = true;
                message_queue.push_back({false, COL_GREEN "[首次信任] " COL_RESET "用户 '" + username + "' 已添加，其公钥指纹为: " + current_fingerprint});
                handle_peer(rsa_pub_key_tofu);
            } else {
                if (it->second == current_fingerprint) {
                    handle_peer(rsa_pub_key_tofu);
                } else {
                    std::string warning_msg = COL_RED "[严重安全警告] " COL_RESET "用户 '" + username + "' 的公钥已改变！这可能意味着中间人攻击！\n";
                    warning_msg += "  - 已知指纹: " + it->second + "\n";
                    warning_msg += "  - 当前指纹: " + current_fingerprint + "\n";
                    warning_msg += "为保证安全，已拒绝与该用户在此次会话中通信。";
                    message_queue.push_back({true, warning_msg});
                }
            }
        }
    }

    if (needs_saving) SaveTrustedPeers();
    
    std::cout << "\r" << std::string(120, ' ') << "\r";

    for (const auto& msg : message_queue) {
        if (msg.is_warning) std::cerr << msg.text << std::endl;
        else std::cout << msg.text << std::endl;
    }
    
    std::cout << "[SYSTEM] 用户列表更新，当前共 " << (verified_peers_for_display.size() + 1) << " 位可信用户在线。\n";
    UniquePKey my_rsa_pub_key = ExtractPublicKey(g_my_rsa_private_key.get());
    std::cout << "  - " << g_my_username << " (您自己) \n    RSA 指纹: " << GetPublicKeyFingerprint(my_rsa_pub_key.get()) << "\n";
    for (const auto& pair : verified_peers_for_display) {
        std::cout << "  - " << pair.first << "\n    RSA 指纹: " << pair.second << "\n";
    }
    std::cout << g_my_username << "> " << std::flush;
}

void DecryptAndPrintMessagePFS(const char* buffer, int len) {
    const char* p = buffer;
    
    uint8_t sender_name_len;
    memcpy(&sender_name_len, p, sizeof(sender_name_len)); p += sizeof(sender_name_len);
    std::string sender_name(p, sender_name_len); p += sender_name_len;

    std::vector<unsigned char> main_iv(12), main_tag(16);
    memcpy(main_iv.data(), p, 12); p += 12;
    memcpy(main_tag.data(), p, 16); p += 16;

    uint32_t main_ciphertext_len;
    memcpy(&main_ciphertext_len, p, sizeof(main_ciphertext_len)); p += sizeof(main_ciphertext_len);
    std::vector<unsigned char> main_ciphertext(p, p + main_ciphertext_len); p += main_ciphertext_len;

    uint16_t recipient_count;
    memcpy(&recipient_count, p, sizeof(recipient_count)); p += sizeof(recipient_count);

    std::vector<unsigned char> wrapped_aes_key;
    std::vector<unsigned char> wrap_iv(12), wrap_tag(16);
    bool found_my_key = false;

    for (int i = 0; i < recipient_count; ++i) {
        uint8_t name_len;
        memcpy(&name_len, p, sizeof(name_len)); p += sizeof(name_len);
        std::string recipient_name(p, name_len); p += name_len;
        
        memcpy(wrap_iv.data(), p, 12); p += 12;
        memcpy(wrap_tag.data(), p, 16); p += 16;
        uint16_t wrapped_key_len;
        memcpy(&wrapped_key_len, p, sizeof(wrapped_key_len)); p += sizeof(wrapped_key_len);
        
        if (recipient_name == g_my_username) {
            found_my_key = true;
            wrapped_aes_key.assign(p, p + wrapped_key_len);
        }
        p += wrapped_key_len;
    }

    if (!found_my_key) return;

    EVP_PKEY* sender_ec_pub_key = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_peers_mutex);
        auto it = g_peers.find(sender_name);
        if (it == g_peers.end()) {
            std::cerr << "\r" << COL_YELLOW << "[SYSTEM] " << COL_RESET << "已忽略来自未信任用户 '" << sender_name << "' 的消息。\n";
            std::cout << g_my_username << "> " << std::flush;
            return;
        }
        sender_ec_pub_key = it->second.ec_pub_key.get();
    }

    std::vector<unsigned char> shared_secret;
    if (!DeriveSharedSecret(g_my_ec_session_key.get(), sender_ec_pub_key, shared_secret) || shared_secret.empty()) {
        std::cerr << "错误: 无法与 " << sender_name << " 创建共享密钥以解密消息。\n";
        return;
    }
    
    std::vector<unsigned char> key_wrapping_key;
    std::vector<unsigned char> salt;
    const unsigned char* info_start = (const unsigned char*)"p2p-chat-key-wrap-v1";
    std::vector<unsigned char> info(info_start, info_start + 20);
    if (!HkdfSha256(key_wrapping_key, 32, shared_secret, salt, info)) {
        std::cerr << "错误: 解密时HKDF密钥派生失败。\n";
        return;
    }

    std::vector<unsigned char> message_aes_key;
    if (!AesGcmDecrypt(key_wrapping_key, wrap_iv, wrapped_aes_key, wrap_tag, message_aes_key)) return;

    std::vector<unsigned char> decrypted_message;
    if (!AesGcmDecrypt(message_aes_key, main_iv, main_ciphertext, main_tag, decrypted_message)) return;
    
    std::string final_message = "[" + sender_name + "]: " + std::string((char*)decrypted_message.data(), decrypted_message.size());
    std::cout << "\r" << std::string(100, ' ') << "\r";
    std::cout << final_message << std::endl;
    std::cout << g_my_username << "> " << std::flush;
}

void ReceiveThread(SOCKET serverSocket) {
    std::vector<char> packet;
    while (g_is_running && ReceivePacket(serverSocket, packet)) {
        if (packet.empty()) continue;
        MessageType msgType = static_cast<MessageType>(packet[0]);
        const char* p_data = packet.data() + 1;
        int data_len = packet.size() - 1;

        switch (msgType) {
            case MessageType::USER_LIST_UPDATE_PFS: UpdatePeerKeysPFS(p_data, data_len); break;
            case MessageType::CHAT_MESSAGE_PFS: DecryptAndPrintMessagePFS(p_data, data_len); break;
            case MessageType::LOGIN_FAILURE:
                 std::cerr << "登录失败。用户名可能已被占用，或服务器拒绝连接。\n";
                 g_is_running = false;
                 break;
            default: std::cout << "收到未知类型的消息: " << (int)msgType << std::endl; break;
        }
    }
}

std::filesystem::path GetAppDataDirectory() {
    // 在 Linux 上使用 getenv("HOME")
    const char* homeDir = getenv("HOME");
    if (homeDir == nullptr) { return {}; }
    std::filesystem::path app_path(homeDir);
    return app_path / ".securechat";
}

bool ManageKeys() {
    std::cout << "请输入您的用户名: ";
    std::getline(std::cin, g_my_username);
    if (g_my_username.empty()) { std::cerr << "[错误] 用户名不能为空。\n"; return false; }
    auto app_dir = GetAppDataDirectory();
    if (app_dir.empty()) { std::cerr << "[错误] 无法获取用户主目录。\n"; return false; }
    auto key_path = app_dir / "keys" / g_my_username / "private.pem";
    std::string key_password;
    if (std::filesystem::exists(key_path)) {
        std::cout << "检测到现有密钥，请输入私钥密码: ";
        std::getline(std::cin, key_password);
        std::ifstream key_file(key_path);
        if (!key_file.is_open()) { std::cerr << "[错误] 无法打开私钥文件: " << key_path << "\n"; return false; }
        std::string pem_content((std::istreambuf_iterator<char>(key_file)), std::istreambuf_iterator<char>());
        key_file.close();
        g_my_rsa_private_key = PEMToPrivateKey(pem_content, key_password);
        if (!g_my_rsa_private_key) { std::cerr << "[错误] 加载私钥失败。密码错误或文件已损坏。\n"; return false; }
        std::cout << "私钥加载成功。\n";
    } else {
        std::cout << "未找到用户 '" << g_my_username << "' 的密钥。将为您创建新的密钥对。\n";
        std::cout << "请输入一个新密码来保护您的私钥: ";
        std::getline(std::cin, key_password);
        if (key_password.empty()) { std::cerr << "[错误] 密码不能为空。\n"; return false; }
        std::cout << "正在生成 " << RSA_KEY_BITS << "-bit RSA 密钥对，请稍候...\n";
        g_my_rsa_private_key = GenerateRsaKeyPair(RSA_KEY_BITS);
        if (!g_my_rsa_private_key) { std::cerr << "[错误] 生成密钥对失败。\n"; return false; }
        std::string pem_private_key = PrivateKeyToPEM(g_my_rsa_private_key.get(), key_password);
        if (pem_private_key.empty()) {
            std::cerr << "[错误] 转换私钥至PEM格式失败。\n";
            g_my_rsa_private_key.reset();
            return false;
        }
        try {
            std::filesystem::create_directories(key_path.parent_path());
            std::ofstream out_file(key_path);
            out_file << pem_private_key;
            out_file.close();
            // std::wcout 在 Linux 上可能需要额外配置，使用 std::cout 更安全
            std::cout << "密钥已成功生成并保存至: " << key_path.string() << "\n";
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "[错误] 保存密钥文件失败: " << e.what() << "\n";
            g_my_rsa_private_key.reset();
            return false;
        }
    }
    return true;
}

int main() {
    // 移除 Windows 特定的控制台设置代码
    InitializeOpenSSL();
    
    if (!ManageKeys()) {
        CleanupOpenSSL();
        std::cout << "按回车键退出...";
        std::cin.get();
        return 1;
    }

    LoadTrustedPeers();
    std::cout << "已加载 " << g_trusted_fingerprints.size() << " 个已信任的用户公钥指纹。\n";

    g_my_ec_session_key = GenerateEcKeyPair();
    if (!g_my_ec_session_key) {
        std::cerr << "错误: 生成EC会话密钥失败。\n";
        CleanupOpenSSL();
        return 1;
    }
    std::cout << "正在生成临时会话密钥...\n";

    // 移除 WSAStartup
    SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connectSocket == INVALID_SOCKET) {
        std::cerr << "Socket 创建失败\n";
        return 1;
    }
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(atoi(SERVER_PORT));
    inet_pton(AF_INET, SERVER_ADDRESS, &serverAddr.sin_addr);
    if (connect(connectSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "连接服务器失败。\n";
        closesocket(connectSocket);
        return 1;
    }
    
    UniquePKey my_rsa_pub_key = ExtractPublicKey(g_my_rsa_private_key.get());
    UniquePKey my_ec_pub_key = ExtractPublicKey(g_my_ec_session_key.get());
    std::string rsa_pem = PublicKeyToPEM(my_rsa_pub_key.get());
    std::string ec_pem = PublicKeyToPEM(my_ec_pub_key.get());
    std::vector<char> ec_pem_vec(ec_pem.begin(), ec_pem.end());
    std::vector<unsigned char> signature;
    SignData(g_my_rsa_private_key.get(), ec_pem_vec, signature);

    std::vector<char> login_packet;
    login_packet.push_back(static_cast<char>(MessageType::LOGIN_REQUEST_PFS));
    uint8_t name_len = g_my_username.length();
    login_packet.push_back(name_len);
    login_packet.insert(login_packet.end(), g_my_username.begin(), g_my_username.end());
    uint16_t rsa_pem_len = rsa_pem.length();
    login_packet.insert(login_packet.end(), (char*)&rsa_pem_len, (char*)&rsa_pem_len + sizeof(rsa_pem_len));
    login_packet.insert(login_packet.end(), rsa_pem.begin(), rsa_pem.end());
    uint16_t ec_pem_len = ec_pem.length();
    login_packet.insert(login_packet.end(), (char*)&ec_pem_len, (char*)&ec_pem_len + sizeof(ec_pem_len));
    login_packet.insert(login_packet.end(), ec_pem.begin(), ec_pem.end());
    uint16_t sig_len = signature.size();
    login_packet.insert(login_packet.end(), (char*)&sig_len, (char*)&sig_len + sizeof(sig_len));
    login_packet.insert(login_packet.end(), signature.begin(), signature.end());
    
    SendPacket(connectSocket, login_packet);
    
    std::vector<char> response_packet;
    if (!ReceivePacket(connectSocket, response_packet) || response_packet.empty() || static_cast<MessageType>(response_packet[0]) != MessageType::LOGIN_SUCCESS) {
        std::cerr << "登录失败。请检查服务器日志。\n";
        closesocket(connectSocket);
        return 1;
    }
    std::cout << "登录成功！输入 '/exit' 退出聊天。\n";

    std::thread receiveThread(ReceiveThread, connectSocket);
    
    std::string userInput;
    while (g_is_running) {
        std::cout << g_my_username << "> " << std::flush;
        std::getline(std::cin, userInput);

        if (!g_is_running || std::cin.eof()) {
             if (g_is_running) {
                g_is_running = false;
                shutdown(connectSocket, SD_SEND);
            }
            break;
        }

        if (userInput == "/exit") {
            g_is_running = false;
            shutdown(connectSocket, SD_SEND);
            break;
        }
        if (userInput.empty()) continue;

        std::vector<char> chat_packet;
        {
            std::lock_guard<std::mutex> lock(g_peers_mutex);
            if (g_peers.empty()) {
                std::cout << "[SYSTEM] 聊天室中没有其他可信用户。\n";
                continue;
            }

            std::vector<unsigned char> msg_aes_key(32), msg_iv(12), msg_tag(16);
            std::vector<unsigned char> plaintext(userInput.begin(), userInput.end());
            std::vector<unsigned char> main_ciphertext;
            GenerateRandomBytes(msg_aes_key);
            GenerateRandomBytes(msg_iv);
            AesGcmEncrypt(msg_aes_key, msg_iv, plaintext, main_ciphertext, msg_tag);

            chat_packet.push_back(static_cast<char>(MessageType::CHAT_MESSAGE_PFS));
            uint8_t my_name_len = g_my_username.length();
            chat_packet.push_back(my_name_len);
            chat_packet.insert(chat_packet.end(), g_my_username.begin(), g_my_username.end());
            chat_packet.insert(chat_packet.end(), msg_iv.begin(), msg_iv.end());
            chat_packet.insert(chat_packet.end(), msg_tag.begin(), msg_tag.end());
            uint32_t main_ciphertext_len = main_ciphertext.size();
            chat_packet.insert(chat_packet.end(), (char*)&main_ciphertext_len, (char*)&main_ciphertext_len + sizeof(main_ciphertext_len));
            chat_packet.insert(chat_packet.end(), main_ciphertext.begin(), main_ciphertext.end());
            
            uint16_t recipient_count = g_peers.size();
            chat_packet.insert(chat_packet.end(), (char*)&recipient_count, (char*)&recipient_count + sizeof(recipient_count));

            for (const auto& pair : g_peers) {
                std::vector<unsigned char> shared_secret;
                if (!DeriveSharedSecret(g_my_ec_session_key.get(), pair.second.ec_pub_key.get(), shared_secret) || shared_secret.empty()) {
                    std::cerr << COL_RED << "错误: 无法为用户 " << pair.first << " 创建共享密钥，已跳过。\n" << COL_RESET;
                    continue;
                }
                
                std::vector<unsigned char> wrapping_key;
                std::vector<unsigned char> salt;
                const unsigned char* info_start = (const unsigned char*)"p2p-chat-key-wrap-v1";
                std::vector<unsigned char> info(info_start, info_start + 20);
                if (!HkdfSha256(wrapping_key, 32, shared_secret, salt, info)) {
                    std::cerr << COL_RED << "错误: 为用户 " << pair.first << " 派生密钥失败。\n" << COL_RESET;
                    continue;
                }

                std::vector<unsigned char> wrap_iv(12), wrap_tag(16), wrapped_key;
                GenerateRandomBytes(wrap_iv);
                AesGcmEncrypt(wrapping_key, wrap_iv, msg_aes_key, wrapped_key, wrap_tag);

                uint8_t peer_name_len = pair.first.length();
                chat_packet.push_back(peer_name_len);
                chat_packet.insert(chat_packet.end(), pair.first.begin(), pair.first.end());
                chat_packet.insert(chat_packet.end(), wrap_iv.begin(), wrap_iv.end());
                chat_packet.insert(chat_packet.end(), wrap_tag.begin(), wrap_tag.end());
                uint16_t wrapped_key_len = wrapped_key.size();
                chat_packet.insert(chat_packet.end(), (char*)&wrapped_key_len, (char*)&wrapped_key_len + sizeof(wrapped_key_len));
                chat_packet.insert(chat_packet.end(), wrapped_key.begin(), wrapped_key.end());
            }
        }
        if (!chat_packet.empty()) {
            SendPacket(connectSocket, chat_packet);
        }
    }

    if (receiveThread.joinable()) receiveThread.join();
    closesocket(connectSocket);
    
    // 移除 WSACleanup
    CleanupOpenSSL();
    std::cout << "已断开连接。\n";
    return 0;
}