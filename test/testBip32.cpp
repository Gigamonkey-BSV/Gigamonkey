// Copyright (c) 2019 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include <gigamonkey/schema/hd.hpp>
#include <gmock/gmock.h>


class Bip32Test :
        public testing::TestWithParam<const char*> {

};

namespace Gigamonkey::Bitcoin::hd {

TEST(Bip32,Basic)
{
    bip32::secret secret=bip32::secret::read("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
}

std::vector<char> HexToBytes(const std::string& hex) {
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}


TEST(Bip32,DeriveChain) {
    bip32::secret secret=bip32::secret::read("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
    bip32::secret expected=bip32::secret::read("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");
    bip32::secret derived=bip32::derive(secret,"0\'");
    ASSERT_EQ(expected,derived);
    ASSERT_EQ(derived.to_public().write(),bip32::pubkey::read("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw").write());
    bip32::secret expected2=bip32::secret::read("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");
    ASSERT_EQ(expected2,bip32::derive(secret,"0\'/1"));
}


TEST(Bip32,PublicRead) {
    bip32::pubkey read=bip32::pubkey::read("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
    ASSERT_EQ(read.Sequence,0) << "Invalid Sequence";
    ASSERT_EQ(read.Depth,0) << "Invalid Depth";
    ASSERT_EQ(read.Parent,0) << "Invalid Parent Fingerprint";
    ASSERT_EQ(read.Net,0x78) << "Invalid Network";
    ASSERT_THAT(read.ChainCode,testing::ElementsAre(0x87,0x3D,0xFF,0x81,0xC0,0x2F,0x52,0x56,0x23,0xFD,0x1F,0xE5,0x16,0x7E,0xAC,0x3A,0x55,0xA0,0x49,0xDE,0x3D,0x31,0x4B,0xB4,0x2E,0xE2,0x27,0xFF,0xED,0x37,0xD5,0x08)) << "Invalid ChainCode";
    ASSERT_THAT(read.Pubkey.Value,testing::ElementsAre(0x03,0x39,0xA3,0x60,0x13,0x30,0x15,0x97,0xDA,0xEF,0x41,0xFB,0xE5,0x93,0xA0,0x2C,0xC5,0x13,0xD0,0xB5,0x55,0x27,0xEC,0x2D,0xF1,0x05,0x0E,0x2E,0x8F,0xF4,0x9C,0x85,0xC2)) << "Invalid Secret Key";
}

TEST(Bip32,PublicWrite) {
    bip32::pubkey expected=bip32::pubkey::read("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
    ASSERT_EQ(expected.write(),"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
}

TEST(Bip32,ToPublic) {
    std::vector<char> input=HexToBytes("000102030405060708090a0b0c0d0e0f");

    Gigamonkey::bytes seed(input.size());
    std::copy(input.begin(),input.end(),seed.begin());

    bip32::secret secret=bip32::secret::from_seed(seed,bip32::main);
    bip32::secret secret2=bip32::secret::read("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
    bip32::pubkey pubkey=secret.to_public();
    bip32::pubkey expected=bip32::pubkey::read("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");

}

}
