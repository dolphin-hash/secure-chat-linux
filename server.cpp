// server.cpp - 适用于 Linux 的版本
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <algorithm>
#include <map>
#include "crypto.h" // 确保引用 v9.0 的 crypto.h

// --- Linux 网络编程头文件 ---
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h> // for close()

// --- 为跨平台兼容性定义 Windows 类型 ---
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket(s) close(s)

#define DEFAULT_PORT "8888"
#define MAX_BUFFER_SIZE 16384

enum class MessageType : uint8_t {
    LOGIN_REQUEST_PFS = 10,
    LOGIN_SUCCESS = 2,
    LOGIN_FAILURE = 3,
    USER_LIST_UPDATE_PFS = 11,
    CHAT_MESSAGE_PFS = 12,
};

// --- 优化的用户信息结构，包含PEM缓存 ---
struct UserInfo {
    SOCKET socket;
    UniquePKey rsa_pub_key;
    UniquePKey ec_pub_key;
    // 缓存的PEM字符串，避免重复计算
    std::string rsa_pem_cache;
    std::string ec_pem_cache;
};

std::map<std::string, UserInfo> g_clients;
std::mutex g_clients_mutex;

// SendPacket 和 ReceivePacket 保持不变
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
    if (packet_size > MAX_BUFFER_SIZE) return false;
    out_packet.resize(packet_size);
    bytes_received = recv(sock, out_packet.data(), packet_size, MSG_WAITALL);
    if (bytes_received <= 0) return false;
    return true;
}

// --- 优化的广播函数 ---
void BroadcastUserListPFS() {
    std::vector<char> packet;
    std::vector<SOCKET> recipient_sockets;

    // --- 优化锁粒度：第一部分 ---
    // 加锁，快速构建数据包并复制目标sockets，然后立即解锁
    {
        std::lock_guard<std::mutex> lock(g_clients_mutex);
        if (g_clients.empty()) return;

        packet.push_back(static_cast<char>(MessageType::USER_LIST_UPDATE_PFS));
        uint16_t user_count = g_clients.size();
        packet.insert(packet.end(), (char*)&user_count, (char*)&user_count + sizeof(user_count));

        for (const auto& pair : g_clients) {
            const std::string& username = pair.first;
            const UserInfo& info = pair.second;

            // --- 效率提升：直接使用缓存的PEM ---
            const std::string& rsa_pem = info.rsa_pem_cache;
            const std::string& ec_pem = info.ec_pem_cache;
            
            uint8_t name_len = username.length();
            packet.push_back(name_len);
            packet.insert(packet.end(), username.begin(), username.end());
            
            uint16_t rsa_pem_len = rsa_pem.length();
            packet.insert(packet.end(), (char*)&rsa_pem_len, (char*)&rsa_pem_len + sizeof(rsa_pem_len));
            packet.insert(packet.end(), rsa_pem.begin(), rsa_pem.end());

            uint16_t ec_pem_len = ec_pem.length();
            packet.insert(packet.end(), (char*)&ec_pem_len, (char*)&ec_pem_len + sizeof(ec_pem_len));
            packet.insert(packet.end(), ec_pem.begin(), ec_pem.end());

            // 复制socket句柄
            recipient_sockets.push_back(info.socket);
        }
    } // 锁在这里被释放

    // --- 优化锁粒度：第二部分 ---
    // 在锁外执行网络发送操作
    for (SOCKET sock : recipient_sockets) {
        SendPacket(sock, packet);
    }
}

// --- 优化的客户端处理函数 ---
void HandleClient(SOCKET clientSocket) {
    std::string username;
    
    std::vector<char> login_packet;
    if (ReceivePacket(clientSocket, login_packet) && !login_packet.empty() && 
        static_cast<MessageType>(login_packet[0]) == MessageType::LOGIN_REQUEST_PFS) {
        
        const char* p = login_packet.data() + 1;
        uint8_t name_len = *p++;
        std::string requested_name(p, name_len); p += name_len;
        
        uint16_t rsa_pem_len; memcpy(&rsa_pem_len, p, sizeof(rsa_pem_len)); p += sizeof(rsa_pem_len);
        std::string rsa_pem(p, rsa_pem_len); p += rsa_pem_len;
        
        uint16_t ec_pem_len; memcpy(&ec_pem_len, p, sizeof(ec_pem_len)); p += sizeof(ec_pem_len);
        std::string ec_pem(p, ec_pem_len); p += ec_pem_len;

        uint16_t sig_len; memcpy(&sig_len, p, sizeof(sig_len)); p += sizeof(sig_len);
        const unsigned char* uc_p = reinterpret_cast<const unsigned char*>(p);
        std::vector<unsigned char> signature(uc_p, uc_p + sig_len);

        auto rsa_pub_key = PEMToPublicKey(rsa_pem);
        std::vector<char> ec_pem_vec(ec_pem.begin(), ec_pem.end());
        
        if (rsa_pub_key && VerifySignature(rsa_pub_key.get(), ec_pem_vec, signature)) {
            std::lock_guard<std::mutex> lock(g_clients_mutex);
            if (g_clients.find(requested_name) == g_clients.end()) {
                auto ec_pub_key = PEMToPublicKey(ec_pem);
                if (ec_pub_key) {
                    username = requested_name;
                    // --- 效率提升：在登录时生成并缓存PEM ---
                    g_clients[username] = {
                        clientSocket, 
                        std::move(rsa_pub_key), 
                        std::move(ec_pub_key),
                        rsa_pem, // 存储缓存
                        ec_pem   // 存储缓存
                    };
                    SendPacket(clientSocket, { (char)MessageType::LOGIN_SUCCESS });
                }
            }
        }
    }
    
    if (username.empty()) {
        SendPacket(clientSocket, { (char)MessageType::LOGIN_FAILURE });
        closesocket(clientSocket);
        return;
    }
    
    std::cout << "用户 '" << username << "' 登录成功 (Optimized). Socket: " << clientSocket << std::endl;
    BroadcastUserListPFS();
    
    // 消息中继循环
    std::vector<char> chat_packet;
    while(ReceivePacket(clientSocket, chat_packet)) {
        if(chat_packet.empty() || static_cast<MessageType>(chat_packet[0]) != MessageType::CHAT_MESSAGE_PFS) {
            continue;
        }

        std::vector<SOCKET> recipient_sockets;
        // --- 优化锁粒度：第一部分 ---
        // 加锁，快速复制目标sockets，然后立即解锁
        {
            std::lock_guard<std::mutex> lock(g_clients_mutex);
            for(const auto& pair : g_clients) {
                if (pair.first != username) {
                    recipient_sockets.push_back(pair.second.socket);
                }
            }
        } // 锁在这里被释放

        // --- 优化锁粒度：第二部分 ---
        // 在锁外执行网络发送操作
        for (SOCKET sock : recipient_sockets) {
            SendPacket(sock, chat_packet);
        }
    }

    // 清理工作
    std::cout << "用户 '" << username << "' 已断开连接。" << std::endl;
    {
        std::lock_guard<std::mutex> lock(g_clients_mutex);
        g_clients.erase(username); // RAII 会自动释放 UserInfo 中的 UniquePKey
    }
    closesocket(clientSocket);
    BroadcastUserListPFS();
}


int main() {
    // 移除 Windows 特定的控制台设置
    InitializeOpenSSL();
    
    // 移除 WSAStartup
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Socket 创建失败\n";
        return 1;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(atoi(DEFAULT_PORT));
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind 失败\n";
        closesocket(listenSocket);
        return 1;
    }
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen 失败\n";
        closesocket(listenSocket);
        return 1;
    }

    std::cout << "加密聊天室服务器 (v10.0 - Optimized Final, Linux) 已启动...\n";

    while (true) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket != INVALID_SOCKET) {
             std::thread clientThread(HandleClient, clientSocket);
             clientThread.detach(); 
        }
    }

    closesocket(listenSocket);
    // 移除 WSACleanup
    CleanupOpenSSL();
    return 0;
}