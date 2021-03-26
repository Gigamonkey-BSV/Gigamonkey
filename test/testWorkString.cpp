// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/string.hpp>
#include <gigamonkey/timechain.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {

    TEST(WorkStringTest, TestWorkSTring) {
        
        std::string genesis_header_string = std::string{} + 
            // version
            "01000000" + 
            // prev block
            "0000000000000000000000000000000000000000000000000000000000000000" + 
            // merkle root
            "3BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4A" + 
            // timestamp
            "29AB5F49" + 
            // bits
            "FFFF001D" + 
            // nonce 
            "1DAC2B7C";
        
        encoding::hex::view genesis_header_hex(genesis_header_string);
        
        ASSERT_TRUE(genesis_header_hex.valid());
        
        bytes genesis_header_bytes = bytes_view(genesis_header_hex);
        
        digest256 genesis_hash = hash256(genesis_header_bytes);
        
        EXPECT_EQ(genesis_hash, digest256("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        
        work::string work_string{slice<80>(genesis_header_bytes.data())}; 
        
        Bitcoin::header header(slice<80>(genesis_header_bytes.data()));
        
        EXPECT_EQ(work_string, work::string(header));
        
        uint<80> work_string_written = work_string.write();
        
        uint<80> header_written = header.write();
        
        EXPECT_EQ(work_string_written, header_written);
        
        EXPECT_EQ(work_string.hash(), digest256("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        
        EXPECT_EQ(header.hash(), digest256("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        
        EXPECT_TRUE(work_string.valid());
        
        EXPECT_TRUE(header.valid());
        
    }
    
    TEST(WorkStringTest, TestASICBoost) {
        
        int32 VERSIONBITS_IGNORE_MASK = 0xE0001FFFUL;
        int32 VERSIONBITS_IGNORE_LEFT = 0xE0000000UL;
        int32 VERSIONBITS_IGNORE_RIGHT = 0x00001FFFUL;
        int32 combined = 0x63E2BC85UL;
        int32 version = combined & VERSIONBITS_IGNORE_MASK;
        int32 general_purpose_bits = (combined & ~VERSIONBITS_IGNORE_MASK) >> 13;
        int32 magic_number = ((combined & VERSIONBITS_IGNORE_LEFT) >> 16) + (combined & VERSIONBITS_IGNORE_RIGHT);
        
        int32_little combined_little = combined;
        int32_little version_little = work::ASICBoost::version(combined);
        uint16_little gpurpose_little = work::ASICBoost::bits(combined);
        uint16_little magicnum_little = work::ASICBoost::magic_number(combined);
        
        EXPECT_EQ(version_little, version);
        EXPECT_EQ(gpurpose_little, general_purpose_bits);
        EXPECT_EQ(magicnum_little, magic_number);
        EXPECT_EQ(combined_little, work::ASICBoost::category(magicnum_little, gpurpose_little));
        
    }

}

