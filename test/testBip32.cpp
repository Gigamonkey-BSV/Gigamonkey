// Copyright (c) 2019 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include <gigamonkey/schema/hd.hpp>
#include <gmock/gmock.h>


class Bip32Test :
    public testing::TestWithParam<const char *> {
};

namespace Gigamonkey::HD {

    TEST (Bip32, Basic) {
        BIP_32::secret secret =
            BIP_32::secret::read
                ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
    }

    TEST (Bip32, DeriveChain) {
        string path1 = "0\'";
        string path2 = "0\'/1";

        string secret_string = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        BIP_32::secret secret = BIP_32::secret::read (secret_string);

        EXPECT_EQ (string (secret), secret_string);

        BIP_32::secret derived = BIP_32::derive (secret, path1);
        BIP_32::pubkey derived_pubkey = derived.to_public ();

        BIP_32::secret expected =
            BIP_32::secret::read
                ("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");

        BIP_32::pubkey expected_pubkey =
            BIP_32::pubkey::read
                ("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");

        EXPECT_EQ (expected, derived);
        ASSERT_EQ (derived.to_public (), expected_pubkey);

        ASSERT_EQ (derived.to_public ().write (), expected_pubkey.write ());

        EXPECT_NE (secret.to_public ().derive (path1), expected_pubkey);
        EXPECT_FALSE (secret.to_public ().derive (path1).valid ());

        BIP_32::secret expected2 =
            BIP_32::secret::read
                ("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");

            ASSERT_EQ (expected2, BIP_32::derive (secret, path2));
    }


    TEST (Bip32, PublicRead) {
        BIP_32::pubkey read = BIP_32::pubkey::read
            ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
        ASSERT_EQ (read.Sequence, 0) << "Invalid Sequence";
        ASSERT_EQ (read.Depth, 0) << "Invalid Depth";
        ASSERT_EQ (read.Parent, 0) << "Invalid Parent Fingerprint";
        ASSERT_EQ (read.Network, Bitcoin::net::Main) << "Invalid Network";
        ASSERT_EQ ((static_cast<data::array<byte, 32>> (read.ChainCode)), (data::array<byte, 32>
            {0x87, 0x3D, 0xFF, 0x81, 0xC0, 0x2F, 0x52, 0x56, 0x23, 0xFD, 0x1F, 0xE5, 0x16, 0x7E, 0xAC, 0x3A, 0x55, 0xA0, 0x49,
             0xDE, 0x3D, 0x31, 0x4B, 0xB4, 0x2E, 0xE2, 0x27, 0xFF, 0xED, 0x37, 0xD5, 0x08})) << "Invalid ChainCode";
        ASSERT_THAT (read.Pubkey, testing::ElementsAre
            (0x03, 0x39, 0xA3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xDA, 0xEF, 0x41, 0xFB, 0xE5, 0x93, 0xA0, 0x2C, 0xC5, 0x13, 0xD0,
             0xB5, 0x55, 0x27, 0xEC, 0x2D, 0xF1, 0x05, 0x0E, 0x2E, 0x8F, 0xF4, 0x9C, 0x85, 0xC2)) << "Invalid Secret Key";
    }

    TEST (Bip32, PublicWrite) {
        BIP_32::pubkey expected = BIP_32::pubkey::read
            ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
        ASSERT_EQ (expected.write (),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
    }

    TEST (Bip32, ToPublic) {
        data::bytes seed = *data::encoding::hex::read ("000102030405060708090a0b0c0d0e0f");

        BIP_32::secret secret = BIP_32::secret::from_seed (seed, Bitcoin::net::Main);
        BIP_32::secret secret2 = BIP_32::secret::read
            ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
        BIP_32::pubkey pubkey = secret.to_public ();
        BIP_32::pubkey expected = BIP_32::pubkey::read
            ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");

    }

    TEST (Bip32, ReadEmptyString) {
        BIP_32::secret x {""};
        EXPECT_FALSE (x.valid ());
    }

}
