#include "aes.h"
#include <cassert>
#include <iostream>
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



std::vector<unsigned char> AES::AddRoundKey(const std::vector<unsigned char> &block1, const std::vector<unsigned char> &block2)
{

    std::vector<unsigned char> t(4 * Nk);
    
    for (int i = 0; i < 4 * Nb; i++)
    {
        t[i] = block1[i] ^ block2[i];
    }
    return t;
}

void AES::KeyExpansion(std::vector<unsigned char> &key)
{
    
    key.resize((Nr + 1) * 4 * Nk);
    assert(key.size() == 176);

    int i = 4 * Nk;
    while(i < 4 * Nk * (Nr + 1))
    {
        if(i / Nk % 4 == 0)
        {
            // 字循环
            unsigned char t = key[i];
            key[i + 0] = key[i + 1];
            key[i + 1] = key[i + 2];
            key[i + 2] = key[i + 3];
            key[i + 3] = t;
            // 字节代换
            key[i + 0] = _SBox[key[i + 0]];
            key[i + 1] = _SBox[key[i + 1]];
            key[i + 2] = _SBox[key[i + 2]];
            key[i + 3] = _SBox[key[i + 3]];
            // 轮常量异或
            key[i + 0] ^= _Recon128[((i / (4 * Nk)) - 1) * Nk + 0];
            key[i + 1] ^= _Recon128[((i / (4 * Nk)) - 1) * Nk + 1];
            key[i + 2] ^= _Recon128[((i / (4 * Nk)) - 1) * Nk + 2];
            key[i + 3] ^= _Recon128[((i / (4 * Nk)) - 1) * Nk + 3];
        }
        else
        {
            key[i + 0] = key[i + 0 - 4 * Nk] ^ key[i + 0 - 4 * 1];
            key[i + 1] = key[i + 1 - 4 * Nk] ^ key[i + 1 - 4 * 1];
            key[i + 2] = key[i + 2 - 4 * Nk] ^ key[i + 2 - 4 * 1];
            key[i + 3] = key[i + 3 - 4 * Nk] ^ key[i + 3 - 4 * 1];
        }
        i += 4;
    }
    
}


unsigned char AES::xtime(const unsigned char &a)
{
    return (a << 1) ^ ((a >> 7) * 0x1b);
}


std::vector<unsigned char> AES::EncryptECB(std::vector<unsigned char> plain, std::vector<unsigned char> key)
{
    int round;
    std::vector<unsigned char> c = AddRoundKey(plain, key);
    // 对密钥进行扩展
    KeyExpansion(key);
    std::vector<unsigned char> curRound(4 * Nk);
    // 进行九轮循环
    for (round = 1; round <= Nr - 1; round++)
    {
        SubBytes(c); // 字节代换
        ShiftRows(c); // 行移位
        MixColumns(c); // 列混合
        
        auto start = key.begin() + 4 * Nk * round; // 排除原始密钥
        auto end   = start + 4 * Nk;
        curRound.assign(start, end);
        c = AddRoundKey(c, curRound);
    }

    SubBytes(c); // 字节代换
    ShiftRows(c); // 行移位
    assert(round == 10);
    auto start = key.begin() + 4 * Nk * round; // 排除原始密钥
    auto end   = start + 4 * Nk;
    curRound.assign(start, end);
    c = AddRoundKey(c, curRound);
    return c;
}


void AES::SubBytes(std::vector<unsigned char> &target)
{
    for (int i = 0; i < 4 * Nb; i++)
    {
        target[i] = _SBox[i];
    }
    
}

void AES::ShiftRows(std::vector<unsigned char> &target)
{
    // 第一行不变
    // 第二行向左移动1个字节
    unsigned char t = target[1];
    target[1] = target[5];
    target[5] = target[9];
    target[9] = target[13];
    target[13] = t;

    // 第三行向左移动2个字节
    std::swap(target[2], target[10]);
    std::swap(target[6], target[14]);

    // 第四行向左移动3个字节(相当于向右移动一个字节)
    t = target[15];
    target[15] = target[11];
    target[11] = target[7];
    target[7] = target[3];
    target[3] = t;
}




void AES::MixColumns(std::vector<unsigned char> &target)
{
    // 固定的矩阵，左乘状态数组
    // 0x02, 0x03, 0x01, 0x01,
    // 0x01, 0x02, 0x03, 0x01,
    // 0x01, 0x01, 0x02, 0x03,
    // 0x03, 0x01, 0x01, 0x02,


    for (int i = 0; i < Nb; i++)
    {
        unsigned char s0 = target[i * Nb + 0];
        unsigned char s1 = target[i * Nb + 1];
        unsigned char s2 = target[i * Nb + 2];
        unsigned char s3 = target[i * Nb + 3];
        target[i * Nb + 0] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
        target[i * Nb + 1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
        target[i * Nb + 2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
        target[i * Nb + 3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
    }
}