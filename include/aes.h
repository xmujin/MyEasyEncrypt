#ifndef AES_H_
#define AES_H_
#include <vector>
#include <string>

namespace MyEasyEncrypt
{

    enum class AESKeyLength
    {
        AES_128,
        AES_192,
        AES_256
    };

    enum class FillMode
    {
        NONE,      // 不进行填充，必须是16字节的整数倍
        PKCS7,     // 以缺少的字节数填充每个字节
        ZERO,      // 缺少的字节以0填充
        ANSI923,   // 最后字节填充缺少的字节数，其余填充0
        ISO7816_4, // 填充第一字节位0x80,剩下填充0
        ISO10126   // Todo 最后字节填充缺少的字节数，其余填充随机字节
    };

    class AES
    {

    public:
        explicit AES(const AESKeyLength keyLength = AESKeyLength::AES_128, const FillMode fillMode = FillMode::ZERO);
        
        AES(const AES&) = delete;
        AES(const AES&&) = delete;
        AES& operator=(const AES&) = delete;
        ~AES() {}

        /**
         * @brief 使用ECB进行加密，单位为一个块（16字节）
         * @param plain 明文
         * @param key 密钥
         * @return std::vector<unsigned char> 返回已加密报文
         */
        std::vector<unsigned char> EncryptBlockByECB(const std::vector<unsigned char>& plain, const std::vector<unsigned char>& key);

        
        std::vector<unsigned char> EncryptByECB(const std::vector<unsigned char>& plain, const std::vector<unsigned char>& key);
        std::string EncryptByECB(const std::string& plain, const std::string& key);

    private:

        unsigned int Nr; // 加密轮数(128位为10轮)
        unsigned int Nk; // 密钥字数(32位bit/字)
        unsigned int Nb; // 状态(分组)字数(32位bit/字)
        FillMode _fillMode;
        std::vector<std::vector<int>> myVector;
        std::vector<unsigned char> Expansion(const std::vector<unsigned char>& plain); // 填充明文


        static const std::string base64_chars;

        std::string _Encode_Base64(const std::string& str);
        // 轮常量
        static const unsigned char _Recon128[];
        static const unsigned char _SBox[];;
        static const unsigned char _Mix[]; // 列混合矩阵

        /**
         * @brief 检查密钥长度
         * @param len 
         */
        void CheckKeyLength(unsigned int len);

        /**
         * @brief 对密钥进行扩展，以支持轮密钥加
         * @param key 传入的密钥
         */
        void KeyExpansion(std::vector<unsigned char> &key);

        /**
         * @brief 字节替换
         * @param target 目标矩阵
         */
        void SubBytes(std::vector<unsigned char> &target);

        /**
         * @brief 行移位
         * @param target 目标矩阵
         */
        void ShiftRows(std::vector<unsigned char> &target);

        /**
         * @brief 用于计算列混合，用于计算02·a.
         * 
         * @param a 需要*02的值
         * @return unsigned char 返回*02的结果
         * 
         * 当a的最高位为0时，直接左移1位
         * 当a的最高位为1时，先左移一位，最后和
         * 0x1b(即00011011)进行异或
         */
        unsigned char xtime(const unsigned char &a);


        /**
         * @brief 列混合的实现
         * @param target 目标矩阵
         */
        void MixColumns(std::vector<unsigned char> &target);

        /**
         * @brief 轮密钥加
         * @param block1 
         * @param block2 
         * @return std::vector<unsigned char> 
         */
        std::vector<unsigned char> AddRoundKey(const std::vector<unsigned char> &block1, const std::vector<unsigned char> &block2);
    };

}

#endif // AES_H_