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
  std::vector<unsigned char> res = a.EncryptECB(plain, key);
  EXPECT_EQ(0x95, (int)res[0]);
}



