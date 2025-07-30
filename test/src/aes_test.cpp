#include "aes.h"
#include <gtest/gtest.h>
using namespace MyEasyEncrypt;


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