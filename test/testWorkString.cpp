// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/string.hpp>
#include <gigamonkey/timechain.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {

    // can result in stack smashing
    TEST(WorkStringTest, TestWorkSTring) {
        
        std::string genesis_header_hex_string = std::string{"0x"} + 
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
        
        uint<80> genesis_header(genesis_header_hex_string);
        
        EXPECT_EQ(data::encoding::hexidecimal::write(genesis_header, endian::little), genesis_header_hex_string);
        
        digest256 header_hash = hash256(genesis_header);
        
        std::cout << "Hash of genesis header " << genesis_header_hex_string << " calculated as " << header_hash << std::endl;
        
        EXPECT_EQ(hash256(genesis_header), digest256("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        
        work::string work_string(genesis_header); 
        
        EXPECT_TRUE(work_string.valid());
        
        EXPECT_EQ(work_string.hash(), digest256("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        
        work::string header(genesis_header);
        
        EXPECT_TRUE(header.valid());
        
        EXPECT_EQ(work_string, work::string(header));
    }

}

