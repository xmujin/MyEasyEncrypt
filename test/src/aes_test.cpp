#include "aes.h"
#include <gtest/gtest.h>
#include "absl/strings/str_format.h"

namespace MyEasyEncrypt
{

    class AESTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            a = new AES;
        }

        void TearDown() override
        {
            delete a;
        }
        AES *a;
    };

    class Base64Test : public testing::TestWithParam<std::pair<std::string, std::string>>
    {
    protected:
        void SetUp() override
        {
            a = new AES;
        }

        void TearDown() override
        {
            delete a;
        }
        AES *a;
    };

    /**
     * @brief base64的解码
     */
    TEST_P(Base64Test, Decode_Base64_Normal)
    {
        auto cur = GetParam();
        std::string expect = cur.first;
        std::string actual = a->_Decode_Base64(cur.second);
        ASSERT_EQ(expect, actual);
    }

    INSTANTIATE_TEST_SUITE_P(NomalStr,
                             Base64Test,
                             testing::Values(
                                 std::make_pair("1234567890abcdef", "MTIzNDU2Nzg5MGFiY2RlZg=="),
                                 std::make_pair("1234567890abcdefcvbdfgdsgdfsgcvb", "MTIzNDU2Nzg5MGFiY2RlZmN2YmRmZ2RzZ2Rmc2djdmI="),
                                 std::make_pair("sdfcxvbxcv", "c2RmY3h2Ynhjdg=="),
                                 std::make_pair("cvbghjtyhgu", "Y3ZiZ2hqdHloZ3U="),
                                 std::make_pair("xcfgdr34565fghxcv", "eGNmZ2RyMzQ1NjVmZ2h4Y3Y=")
                                     ));


    TEST(ECB, EncryptOneBlock) // 一个16字节块的加密,返回Base64编码
    {
        AES a;
        std::string plain = "1234567890abcdef";
        std::string key = "1234567890abcdef";
        std::string ok = "lbASsLyJjlw37u1liGNfCQ==";
        std::string res = a.EncryptByECB(plain, key);
        ASSERT_EQ(ok, res);
    }

    TEST(ECB, EncryptString) // 非块的倍数加密
    {
        AES a;
        std::string plain = "sdfsdfsdfdsfdsfdsfsdfdsfdsfsdf";
        std::string key = "1234567890abcdef";
        std::string ok = "zxtYgPZxImGgRNtQEA8pxwTS7uIPKiJU2BMU7lrE3hA=";
        std::string res = a.EncryptByECB(plain, key);
        ASSERT_EQ(ok, res);
    }

    TEST(ECB, EncryptByErrorKey) // 非块的倍数加密
    {
        AES a;
        std::string plain = "sdfsdfsdfdsfdsfdsfsdfdsfdsfsdf";
        std::string key = "1234567";
        EXPECT_THROW(a.EncryptByECB(plain, key), std::length_error);
    }

    TEST(ECB, EncryptByOkKey) // 非块的倍数加密
    {
        AES a;
        std::string plain = "sdfsdfsdfdsfdsfdsfsdfdsfdsfsdf";
        std::string key = "1234567890abcdef";
        EXPECT_NO_THROW(a.EncryptByECB(plain, key));
    }

    // 逆列混淆
    TEST(Decrypt, MixColumns_Inv_)
    {
        AES a;
        std::vector<unsigned char> expect =
            {
                0xC7, 0xF8, 0x1D, 0x33,
                0x5B, 0xBC, 0x92, 0xAC,
                0x8A, 0x05, 0x17, 0xEB,
                0x5B, 0xBE, 0x4E, 0xFE};
        std::vector<unsigned char> t =
            {
                0xA8, 0x38, 0x50, 0xD1,
                0x57, 0x39, 0x37, 0x80,
                0xFC, 0x52, 0x87, 0x5A,
                0xDF, 0x10, 0x60, 0xFA};
        a.MixColumns_Inv(t);

        ASSERT_EQ(expect, t);
    }

    // 逆行位移
    TEST(Decrypt, ShiftRows_Inv_)
    {
        AES a;
        std::vector<unsigned char> expect =
            {
                0xC7, 0xBE, 0x17, 0xAC,
                0x5B, 0xF8, 0x4E, 0xEB,
                0x8A, 0xBC, 0x1D, 0xFE,
                0x5B, 0x05, 0x92, 0x33};
        std::vector<unsigned char> t =
            {
                0xC7, 0xF8, 0x1D, 0x33,
                0x5B, 0xBC, 0x92, 0xAC,
                0x8A, 0x05, 0x17, 0xEB,
                0x5B, 0xBE, 0x4E, 0xFE};
        a.ShiftRows_Inv(t);

        ASSERT_EQ(expect, t);
    }

    // 逆字节代换
    TEST(Decrypt, SubBytes_Inv_)
    {
        AES a;
        std::vector<unsigned char> expect =
            {
                0x31, 0x5A, 0x87, 0xAA,
                0x57, 0xE1, 0xB6, 0x3C,
                0xCF, 0x78, 0xDE, 0x0C,
                0x57, 0x36, 0x74, 0x66};
        std::vector<unsigned char> t =
            {
                0xC7, 0xBE, 0x17, 0xAC,
                0x5B, 0xF8, 0x4E, 0xEB,
                0x8A, 0xBC, 0x1D, 0xFE,
                0x5B, 0x05, 0x92, 0x33};
        a.SubBytes_Inv(t);

        ASSERT_EQ(expect, t);
    }

    // 块解密（使用vector）
    TEST(Decrypt, DecryptOneBlock_Vector)
    {
        AES a;
        std::vector<unsigned char> plain =
            {
                '1',
                '2',
                '3',
                '4',
                '5',
                '6',
                '7',
                '8',
                '9',
                '0',
                'a',
                'b',
                'c',
                'd',
                'e',
                'f',
            };

        std::vector<unsigned char> key =
            {
                '1',
                '2',
                '3',
                '4',
                '5',
                '6',
                '7',
                '8',
                '9',
                '0',
                'a',
                'b',
                'c',
                'd',
                'e',
                'f',
            };

        std::vector<unsigned char> cipher =
            {
                0x95,
                0xb0,
                0x12,
                0xb0,
                0xbc,
                0x89,
                0x8e,
                0x5c,
                0x37,
                0xee,
                0xed,
                0x65,
                0x88,
                0x63,
                0x5f,
                0x09,
            };
        auto sb = a.EncryptBlockByECB(plain, key);
        ASSERT_EQ(cipher, sb);
        auto res = a.DecryptBlockByECB(cipher, key);
        ASSERT_EQ(plain, res);
    }


    TEST(Decrypt, Decrypt_Normal_String)
    {
        AES a;
        std::string plain = "zxcvbnasdfghjkrtzxcvbnasdfghjkrt";
        std::string key = "1234567890abcdef";
        std::string cipher = "uGspNlMGR7PJCny7X4HRq7hrKTZTBkezyQp8u1+B0as";
        std::string res = a.DecryptByECB(cipher, key);
        ASSERT_EQ(plain, res);
    }

}
