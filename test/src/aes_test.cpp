#include "aes.h"
#include <gtest/gtest.h>
using namespace MyEasyEncrypt;

TEST(EncryptTest, KeyExpansion_normal)
{
  AES a;
  std::vector<unsigned char> plain = {'1', '2', '3', '4', '5',
                                      '6', '7', '8', '9', '0',
                                      'a', 'b', 'c', 'd',
                                      'e', 'f'

  };

  std::vector<unsigned char> key = {'1', '2', '3', '4', '5',
                                    '6', '7', '8', '9', '0',
                                    'a', 'b', 'c', 'd',
                                    'e', 'f'

  };

  std::vector<unsigned char> ok = {
      0x95, 0xb0, 0x12, 0xb0, 0xbc, 0x89, 0x8e, 0x5c,
      0x37, 0xee, 0xed, 0x65, 0x88, 0x63, 0x5f, 0x09};
  std::vector<unsigned char> res = a.EncryptECB(plain, key);

  ASSERT_EQ(ok, res);
}

TEST(ECB, OneBlockEncryptVector)
{
  AES aes(AESKeyLength::AES_128);
  std::vector<unsigned char> plain = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                      0xcc, 0xdd, 0xee, 0xff};
  std::vector<unsigned char> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
  std::vector<unsigned char> right = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                      0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                      0x70, 0xb4, 0xc5, 0x5a};
  std::vector<unsigned char> out = aes.EncryptECB(plain, key);

  ASSERT_EQ(right, out);
}
