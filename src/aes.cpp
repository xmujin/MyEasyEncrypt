#include "aes.h"
using namespace MyEasyEncrypt;



AES::AES(const AESKeyLength keyLength)
{
    switch (keyLength)
    {
    case AESKeyLength::AES_128:
        this->Nk = 4; 
        this->Nb = 4;
        this->Nr = 10; // 10轮加密
        break;
    }
}



std::vector<unsigned char> AES::XorBlock(const std::vector<const unsigned char> &block1, const std::vector<unsigned char> &block2)
{

    std::vector<unsigned char> t;
    
    for (int i = 0; i < 4 * Nb; i++)
    {
        t[i] = block1[i] ^ block2[i];
    }
    return t;
}

