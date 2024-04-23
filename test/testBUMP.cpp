// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/BUMP.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Merkle {

    // these are examples that come from the specification.
    std::string binary_BUMP_HEX =
        "fe8a6a0c00" // blockHeight (813706), VarInt
        "0c" // treeHeight (12), byte
        // Level 0, client TXIDs and sibling TXIDs (TXIDs required only to compute internal tree hash).
        "04" // nLeaves, VarInt
        "fde80b" // offset, VarInt
        "00" // flags
        "11774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30" // hash
        "fde90b" // offset VarInt
        "02" // flags = CLIENT_TXID
        "004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8" // hash
        "fdea0b" // offset VarInt
        "02" // flags = CLIENT_TXID
        "5e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998" // hash
        "fdeb0b" // offset VarInt
        "01" // flags = DUPLICATE_WORKING_HASH
        // Level 1, internal merkle tree hashes
        "02" // nLeaves, VarInt
        "fdf405" // offset, VarInt
        "00" // flags
        "0671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81" // hash
        "fdf505" // offset VarInt
        "00" // flags
        "262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a5282" // hash
        // Level 2, internal merkle tree hashes
        "01" // nLeaves VarInt at level 2
        "fdfb02" // offset VarInt
        "01" // flags = DUPLICATE_WORKING_HASH
        // Level 3, internal merkle tree hashes
        "01" // nLeaves VarInt at level 3
        "fd7c01" // offset VarInt (three hundred and eighty)
        "00" // flags
        "93b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e85" // hash
        // Level 4, internal merkle tree hashes
        "01" // nLeaves VarInt at level 4
        "bf" // offset VarInt
        "01" // flags = DUPLICATE_WORKING_HASH
        // Level 5, internal merkle tree hashes
        "01" // nLeaves VarInt at level 5
        "5e" // offset VarInt
        "00" // flags
        "5881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8" // hash
        // Level 6, internal merkle tree hashes
        "01" // nLeaves VarInt at level 6
        "2e" // offset VarInt
        "00" // flags
        "e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff3" // hash
        // Level 7, internal merkle tree hashes
        "01" // nLeaves VarInt at level 7
        "16" // offset VarInt
        "00" // flags
        "8120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d" // hash
        // Level 8, internal merkle tree hashes
        "01" // nLeaves VarInt at level 8
        "0a" // offset VarInt
        "00" // flags
        "502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae43" // hash
        // Level 9, internal merkle tree hashes
        "01" // nLeaves VarInt at level 9
        "04" // offset VarInt
        "00" // flags
        "1ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45" // hash
        // Level 10, internal merkle tree hashes
        "01" // nLeaves VarInt at level 10
        "03" // offset VarInt
        "01" // flags = DUPLICATE_WORKING_HASH
        // Level 11, internal merkle tree hashes
        "01" // nLeaves VarInt at level 11
        "00" // offset VarInt
        "00" // flags
        "af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4" // hash
        ;

    std::string JSON_BUMP_string = R"({
        "blockHeight": 813706,
        "path": [
            [
                {
                    "offset": 3048,
                    "hash": "304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711"
                },
                {
                    "offset": 3049,
                    "txid": true,
                    "hash": "d888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00"
                },
                {
                    "offset": 3050,
                    "txid": true,
                    "hash": "98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e"
                },
                {
                    "offset": 3051,
                    "duplicate": true
                }
            ],
            [
                {
                    "offset": 1524,
                    "hash": "811ae75c80fecd27efff5ef272c2adf7edb6e535447f27a4087d23724f397106"
                },
                {
                    "offset": 1525,
                    "hash": "82520a4501a06061dd2386fb92fa5e9ceaed14747acc00edf34a6cecabcc2b26"
                }
            ],
            [
                {
                    "offset": 763,
                    "duplicate": true
                }
                ],
            [
                {
                    "offset": 380,
                    "hash": "858e41febe934b4cbc1cb80a1dc8e254cb1e69acff8e4f91ecdd779bcaefb393"
                }
            ],
            [
                {
                    "offset": 191,
                    "duplicate": true
                }
            ],
            [
                {
                    "offset": 94,
                    "hash": "f80263e813c644cd71bcc88126d0463df070e28f11023a00543c97b66e828158"
                }
            ],
            [
                {
                    "offset": 46,
                    "hash": "f36f792fa2b42acfadfa043a946d4d7b6e5e1e2e0266f2cface575bbb82b7ae0"
                }
            ],
            [
                {
                    "offset": 22,
                    "hash": "7d5051f0d4ceb7d2e27a49e448aedca2b3865283ceffe0b00b9c3017faca2081"
                }
            ],
            [
                {
                    "offset": 10,
                    "hash": "43aeeb9b6a9e94a5a787fbf04380645e6fd955f8bf0630c24365f492ac592e50"
                }
            ],
            [
                {
                    "offset": 4,
                    "hash": "45be5d16ac41430e3589a579ad780e5e42cf515381cc309b48d0f4648f9fcd1c"
                }
            ],
            [
                {
                    "offset": 3,
                    "duplicate": true
                }
            ],
            [
                {
                    "offset": 0,
                    "hash": "d40cb31af3ef53dd910f5ce15e9a1c20875c009a22d25eab32c11c7ece6487af"
                }
            ]
        ]
    })";

    TEST (BUMPTest, TestBUMP) {
        bytes bump_bytes = *encoding::hex::read (binary_BUMP_HEX);
        BUMP from_bytes {bump_bytes};

        EXPECT_EQ (from_bytes.serialized_size (), bump_bytes.size ());

        JSON JSON_BUMP = JSON::parse (JSON_BUMP_string);

        BUMP from_JSON {JSON_BUMP};
        EXPECT_EQ (from_JSON.serialized_size (), bump_bytes.size ());

        EXPECT_EQ (JSON (from_JSON), JSON_BUMP);
        EXPECT_EQ (JSON (from_bytes), JSON_BUMP);

        EXPECT_EQ (encoding::hex::write (bytes (from_JSON)), binary_BUMP_HEX);
        EXPECT_EQ (encoding::hex::write (bytes (from_bytes)), binary_BUMP_HEX);

        auto expected_merkle_root = digest {"0x57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4"};

        EXPECT_EQ (expected_merkle_root, from_JSON.root ());

        EXPECT_EQ (expected_merkle_root, from_bytes.root ());

        auto paths = from_bytes.paths ();
        bool paths_are_valid = dual {paths, expected_merkle_root}.valid ();
        EXPECT_TRUE (paths_are_valid);
        BUMP from_paths {from_bytes.BlockHeight, paths};

        EXPECT_EQ (expected_merkle_root, from_paths.root ());

    }

}
