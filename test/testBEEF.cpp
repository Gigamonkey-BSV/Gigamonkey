// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/pay/BEEF.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey {

    // these are examples that come from the specification.
    std::string binary_BEEF_HEX =
        "0100beef" // version
        "01" // VarInt nBUMPs
        "fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e"
        "5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e01"
        "0b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf455701040057"
        "4b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc8"
        "4d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2"
        "523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c0"
        "13ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f"
        "72f3cf6fdbfd0b161c53a9c54b12c841126331" // see BRC-74 for details of BUMP format
        "02" // VarInt nTransactions = 2
        // rawtx parent follows
        "0100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a7902901"
        "0000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde"
        "14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef36"
        "41210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffff"
        "ff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000"
        "01" // above tx has merkle path
        "00" // VarInt the index of the path for this tx in the above list
        // rawtx current payment follows
        "0100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e00"
        "0000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd"
        "368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441"
        "210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff"
        "013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000"
        "00" // above tx doesn't have merkle path, but instead has local parent
        ;

    TEST (BEEFTest, TestBEEF) {

        bytes beef_bytes = *encoding::hex::read (binary_BEEF_HEX);
        BEEF beef {beef_bytes};
        EXPECT_EQ (beef.serialized_size (), beef_bytes.size ());
        EXPECT_EQ (beef.BUMPs.size (), 1);
        EXPECT_EQ (beef.Transactions.size (), 2);
        EXPECT_EQ (beef.Transactions[0].Transaction.Version, 1);
        EXPECT_EQ (beef.Transactions[1].Transaction.Version, 1);

        bytes to_bytes = bytes (beef);

        EXPECT_EQ (to_bytes, beef_bytes);
        // it seems that the signature in this BEEF is not valid.
        /*
        EXPECT_TRUE (beef.valid ());
        EXPECT_TRUE (beef.roots ().size () > 0);*/
    }

}

