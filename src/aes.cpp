#include "aes.h"
#include <cassert>
#include <iostream>
using namespace MyEasyEncrypt;

const std::string AES::base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

const unsigned char AES::_Recon128[] = {
    0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00,
    0x1b, 0x00, 0x00, 0x00,
    0x36, 0x00, 0x00, 0x00,
};

const unsigned char AES::_SBox[] = 
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


const unsigned char AES::_Inv_SBox[] = 
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};


const unsigned char AES::_Mix[] = {
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
}; // 列混合矩阵

const unsigned char AES::_Inv_Mix[] = {
    0x0E, 0x0B, 0x0D, 0x09,
    0x09, 0x0E, 0x0B, 0x0D,
    0x0D, 0x09, 0x0E, 0x0B,
    0x0B, 0x0D, 0x09, 0x0E
}; // 列混合矩阵

AES::AES(const AESKeyLength keyLength, const FillMode fillMode) : _fillMode(fillMode)
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
    CheckKeyLength(key.size());
    key.resize((Nr + 1) * 4 * Nk);
    assert(key.size() == 176);

    unsigned int i = 4 * Nk;
    while(i < 4 * Nk * (Nr + 1))
    {
        if(i / Nk % 4 == 0)
        {
            std::vector<unsigned char> temp(4);
            temp[0] = key[i + 0 - 4 * 1];
            temp[1] = key[i + 1 - 4 * 1];
            temp[2] = key[i + 2 - 4 * 1];
            temp[3] = key[i + 3 - 4 * 1];

            // 字循环
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // 字节代换
            temp[0] = _SBox[temp[0]];
            temp[1] = _SBox[temp[1]];
            temp[2] = _SBox[temp[2]];
            temp[3] = _SBox[temp[3]];


            // 轮常量异或
            temp[0] ^= _Recon128[((i / (4 * Nk)) - 1) * Nk + 0];
            temp[1] ^= _Recon128[((i / (4 * Nk)) - 1) * Nk + 1];
            temp[2] ^= _Recon128[((i / (4 * Nk)) - 1) * Nk + 2];
            temp[3] ^= _Recon128[((i / (4 * Nk)) - 1) * Nk + 3];
            // 最终异或w[i - 4] ^ T(w[i - 1])
            key[i + 0] = key[i + 0 - 4 * Nk] ^ temp[0];
            key[i + 1] = key[i + 1 - 4 * Nk] ^ temp[1];
            key[i + 2] = key[i + 2 - 4 * Nk] ^ temp[2];
            key[i + 3] = key[i + 3 - 4 * Nk] ^ temp[3];
        }
        else
        {
            // w[i - 4] ^ w[i - 1]
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
    return (a << 1) ^ (((a >> 7) & 1) * 0x1b);
}

unsigned char AES::xtime_mul_9(const unsigned char &a)
{
    return xtime(xtime(xtime(a))) ^ a;
}

// 11
unsigned char AES::xtime_mul_B(const unsigned char &a)
{
    return xtime(xtime(xtime(a))) ^ xtime(a) ^ a;
}

unsigned char AES::xtime_mul_D(const unsigned char &a)
{
    return xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ a;
}

unsigned char AES::xtime_mul_E(const unsigned char &a)
{
    return xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ xtime(a);
}

std::vector<unsigned char> AES::EncryptBlockByECB(const std::vector<unsigned char>& plain, const std::vector<unsigned char>& key)
{
    CheckKeyLength(key.size());
    int round;
    std::vector<unsigned char> keyCopy(key.size());
    keyCopy.assign(key.begin(), key.end());

    std::vector<unsigned char> c = AddRoundKey(plain, key);
    // 对密钥进行扩展
    KeyExpansion(keyCopy);
    std::vector<unsigned char> curRound(4 * Nk);
    // 进行九轮循环
    for (round = 1; round <= Nr - 1; round++)
    {
        SubBytes(c); // 字节代换
        ShiftRows(c); // 行移位
        MixColumns(c); // 列混合
        
        auto start = keyCopy.begin() + 4 * Nk * round; // 排除原始密钥
        auto end   = start + 4 * Nk;
        curRound.assign(start, end);
        c = AddRoundKey(c, curRound);
    }

    SubBytes(c); // 字节代换
    ShiftRows(c); // 行移位
    assert(round == 10);
    auto start = keyCopy.begin() + 4 * Nk * round; // 排除原始密钥
    auto end   = start + 4 * Nk;
    curRound.assign(start, end);
    c = AddRoundKey(c, curRound);
    return c;
}


std::vector<unsigned char> AES::DecryptBlockByECB(const std::vector<unsigned char>& cipher, const std::vector<unsigned char>& key)
{
    CheckKeyLength(key.size());
    int round;
    std::vector<unsigned char> res(cipher);
    std::vector<unsigned char> roundKey(key);
    KeyExpansion(roundKey);
    assert(roundKey.size() == 16 * 11);
    std::vector<unsigned char> block(16);
    block.assign(roundKey.begin() + 16 * 10, roundKey.end());
    // 轮密钥加
    res = AddRoundKey(res, block);
    // 逆行位移
    ShiftRows_Inv(res);
    // 逆字节代换
    SubBytes_Inv(res);

    for (round = Nr - 1; round >= 1; round--)
    {
        auto start = roundKey.begin() + 4 * Nk * round; // 排除原始密钥
        auto end   = start + 4 * Nk;
        block.assign(start, end);
        // 轮密钥加
        res = AddRoundKey(res, block);
        // 逆列混淆
        MixColumns_Inv(res);
        // 逆行位移
        ShiftRows_Inv(res);
        // 逆字节代换
        SubBytes_Inv(res);
    }
    res = AddRoundKey(res, key);
    return res;
}

std::vector<unsigned char> AES::DecryptByECB(const std::vector<unsigned char>& cipher, const std::vector<unsigned char>& key)
{
    std::vector<unsigned char> block;
    std::vector<unsigned char> res(cipher.size());
    int index = 0;
    for (int i = 0; i < cipher.size() / 16; i++)
    {
        auto start = cipher.begin() + 16 * i;
        auto end = start + 16;
        block.assign(start, end);
        assert(block.size() == 16);
        auto t = DecryptBlockByECB(block,key);
        assert(t.size() == 16);
        for (auto i : t)
        {
            res[index++] = i;
        }
    }
    return res;
}

std::string AES::DecryptByECB(const std::string& cipher, const std::string& key)
{
    std::string cipherOrigin = _Decode_Base64(cipher);
    // assert(cipherOrigin.size() == 16);

    std::vector<unsigned char> cipherArray, k, resArray;
    
    k.assign(key.begin(), key.end());

    std::string resStr;

    cipherArray.assign(cipherOrigin.begin(), cipherOrigin.end());
    resArray = DecryptByECB(cipherArray, k);
    resStr.assign(resArray.begin(), resArray.end());
    return resStr;
}



void AES::SubBytes(std::vector<unsigned char> &target)
{
    for (int i = 0; i < 4 * Nb; i++)
    {
        target[i] = _SBox[target[i]];
    } 
}

void AES::SubBytes_Inv(std::vector<unsigned char> &target)
{
    for (int i = 0; i < 4 * Nb; i++)
    {
        target[i] = _Inv_SBox[target[i]];
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


void AES::ShiftRows_Inv(std::vector<unsigned char> &target)
{
    // 第一行不变
    // 第二行向右移动1个字节
    // 0 4 8  12 
    // 1 5 9  13
    // 2 6 10 14
    // 3 7 11 15
    unsigned char t = target[13];
    target[13] = target[9];
    target[9] = target[5];
    target[5] = target[1];
    target[1] = t;

    // 第三行向右移动2个字节
    std::swap(target[2], target[10]);
    std::swap(target[6], target[14]);

    // 第四行向右移动3个字节(相当于向左移动一个字节)
    t = target[3];
    target[3] = target[7];
    target[7] = target[11];
    target[11] = target[15];
    target[15] = t;
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

void AES::MixColumns_Inv(std::vector<unsigned char> &target)
{
    // 固定的矩阵，左乘状态数组
    // 0x0E, 0x0B, 0x0D, 0x09,
    // 0x09, 0x0E, 0x0B, 0x0D,
    // 0x0D, 0x09, 0x0E, 0x0B,
    // 0x0B, 0x0D, 0x09, 0x0E
    for (int i = 0; i < Nb; i++)
    {
        unsigned char s0 = target[i * Nb + 0];
        unsigned char s1 = target[i * Nb + 1];
        unsigned char s2 = target[i * Nb + 2];
        unsigned char s3 = target[i * Nb + 3];
        target[i * Nb + 0] = xtime_mul_E(s0) ^ xtime_mul_B(s1) ^ xtime_mul_D(s2) ^ xtime_mul_9(s3);
        target[i * Nb + 1] = xtime_mul_9(s0) ^ xtime_mul_E(s1) ^ xtime_mul_B(s2) ^ xtime_mul_D(s3);
        target[i * Nb + 2] = xtime_mul_D(s0) ^ xtime_mul_9(s1) ^ xtime_mul_E(s2) ^ xtime_mul_B(s3);
        target[i * Nb + 3] = xtime_mul_B(s0) ^ xtime_mul_D(s1) ^ xtime_mul_9(s2) ^ xtime_mul_E(s3);
    }
}

std::vector<unsigned char> AES::EncryptByECB(const std::vector<unsigned char>& plain, const std::vector<unsigned char>& key)
{
    CheckKeyLength(key.size());
    std::vector<unsigned char> plainCopy = Expansion(plain);
    std::vector<unsigned char> res(plainCopy.size());
    int index = 0;
    for (int i = 0; i < plainCopy.size() / 16; i++)
    {
        std::vector<unsigned char> plainSingle(16);
        auto s = plainCopy.begin() + 16 * i;
        auto e = s + 16;
        plainSingle.assign(s, e);
        auto t = EncryptBlockByECB(plainSingle, key);
        
        for(auto v : t)
        {
            res[index++] = v;
        }
    }
    return res;
}


std::vector<unsigned char> AES::Expansion(const std::vector<unsigned char>& plain)
{
    int blocks, leave;
    std::vector<unsigned char> res;
    leave = plain.size() % 16;
    blocks = (plain.size() + 16 - 1) / 16;
    res.assign(plain.begin(), plain.end());
    res.resize(blocks * 16);
    if(_fillMode == FillMode::ZERO && leave != 0)
    {
        for (auto i = res.begin() + plain.size(); i < res.end(); i++)
        {
            *i = 0;
        }
    }
    else if(_fillMode == FillMode::PKCS7)
    {
        if(leave == 0)
        {
            res.resize(plain.size() + 16);
        }
        else
        {
            for (auto i = res.begin() + plain.size(); i < res.end(); i++)
            {
                *i = 16 - leave;
            }
        }
    }
    else if(_fillMode == FillMode::ANSI923 && leave != 0)
    {
        for (auto i = res.begin() + plain.size(); i != res.end(); i++)
        {
            *i = 0;
            if(i == res.end() - 1)
            {
                *i = 16 - leave;
            }
        }
        
    }
    else if(_fillMode == FillMode::ANSI923 && leave != 0)
    {
        for (auto i = res.begin() + plain.size(); i != res.end(); i++)
        {
            *i = 0;
            if(i == res.end() - 1)
            {
                *i = 0x80;
            }
        }
    }
    else if(_fillMode == FillMode::ISO10126) // Todo 最后字节填充缺少的字节数，其余填充随机字节
    {

    }
    
    return res;
}


std::string AES::EncryptByECB(const std::string& plain, const std::string& key)
{
    CheckKeyLength(key.size());
    std::vector<unsigned char> p, k, r;
    p.assign(plain.begin(), plain.end());
    k.assign(key.begin(), key.end());
    r = EncryptByECB(p, k);
    std::string res;
    res.assign(r.begin(), r.end());

    return _Encode_Base64(res);
}




std::string AES::_Encode_Base64(const std::string& str)
{

    std::string res;
    int val = 0;
    int valb = -6; // 缓冲区初始还差6位
    for (unsigned char c : str) {
        val = (val << 8) + c; 
        valb += 8; // 填充了8位数据
        while (valb >= 0) // 检查是否达到缓冲位数
        {
            // 右移删除多余位数并取低6位
            res.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6; // 消耗了6位用于生成base64编码，如果为负数则还需要进行补充
        }
    }
    // 8 % 6 = 2，16 % 6 = 4, 
    // 00xx0000    00xxxx 00 
    if (valb > -6) // 如果字符都用完，但还剩余一些位没被使用
    {
        // 补充8位零，并移除多余的零
        res.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (res.size() % 4) // 不为4的倍数时则填充=
    {
        res.push_back('=');
    }
    return res;
}


std::string AES::_Decode_Base64(const std::string& str)
{

    std::string strCopy(str);
    std::string res;
    // 删除=号
    while(!strCopy.empty() && strCopy.back() == '=')
    {
        strCopy.pop_back();
    }

    int value = 0;
    int valueBuffer = -8;
    for (auto c : strCopy)
    {
        value = (value << 6) + base64_chars.find(c);
        valueBuffer += 6;
        while(valueBuffer >= 0)
        {
            res.push_back((char)((value >> valueBuffer) & 0xFF));
            valueBuffer -= 8;
        }
    }
    return res;
}



void AES::CheckKeyLength(unsigned int len) 
{
  if (len != 16) {
    throw std::length_error("key length must be 16 bytes");
  }
}