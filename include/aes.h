#ifndef AES_H_
#define AES_H_
#include <vector>


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
        ISO7816_4, // 填充第一字节位0x80,剩下填充另
        ISO10126   // 最后字节填充缺少的字节数，其余填充随机字节
    };

    class AES
    {

    public:
        explicit AES(const AESKeyLength keyLength = AESKeyLength::AES_128);
        void expansion(); // 填充明文
    private:
        // std::vector<int>
        unsigned int Nr; // 加密轮数
        unsigned int Nk; // 密钥字数(32位bit/字)
        unsigned int Nb; // 状态(分组)字数(32位bit/字)



        std::vector<unsigned char> XorBlock(const std::vector<const unsigned char> &block1, const std::vector<unsigned char> &block2);
        // void SubBytes(unsigned char state[][]); // 字节替换
    };

}

#endif // AES_H_