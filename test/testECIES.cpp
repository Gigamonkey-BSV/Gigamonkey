// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/wif.hpp>
#include <gigamonkey/ecies/bitcore.hpp>
#include <gigamonkey/ecies/electrum.hpp>
#include <data/encoding/base64.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::ECIES {

    TEST(ECIESTest, TestBitcore) {
        using namespace bitcore;
        
        Bitcoin::secret aliceKey {"L1Ejc5dAigm5XrM3mNptMEsNnHzS7s51YxU7J61ewGshZTKkbmzJ"};
        Bitcoin::secret bobKey {"KxfxrUXSMjJQcb3JgnaaA6MqsrKQ1nBSxvhuigdKRyFiEm6BZDgG"};
        
        // bitcore
        std::string message{"attack at dawn"};
        std::string encrypted{ "0339e504d6492b082da96e11e8f039796b06cd4855c101e2492a6f10f3e056a9e712c732611c6917ab5c57a1926973bc44a1586e94a783f81d05ce72518d9b0a80e2e13c7ff7d1306583f9cc7a48def5b37fbf2d5f294f128472a6e9c78dede5f5"};
        
        bytes message_bytes(message.size ());
        std::copy (message.begin(), message.end (), message_bytes.begin());
        
        bytes encrypted_bytes = encrypt(message_bytes, bobKey.Secret.to_public());
        
        EXPECT_EQ (encrypted, encoding::hex::write(message_bytes));
        
        bytes decrypted_bytes = decrypt(encrypted_bytes, bobKey.Secret);
        
        EXPECT_EQ (decrypted_bytes, message_bytes);
        
        bytes decrypted_bytes_alice = decrypt (encrypt(message_bytes, aliceKey.Secret.to_public()), aliceKey.Secret);
        
        EXPECT_EQ (message_bytes, decrypted_bytes_alice);
        
    }

    TEST (ECIESTest, TestElectrum) {
        using namespace electrum;
        
        Bitcoin::secret aliceKey {"L1Ejc5dAigm5XrM3mNptMEsNnHzS7s51YxU7J61ewGshZTKkbmzJ"};
        Bitcoin::secret bobKey {"KxfxrUXSMjJQcb3JgnaaA6MqsrKQ1nBSxvhuigdKRyFiEm6BZDgG"};
        
        // bitcore
        std::string message {"attack at dawn"};
        std::string encrypted {"QklFMQM55QTWSSsILaluEejwOXlrBs1IVcEB4kkqbxDz4Fap56+ajq0hzmnaQJXwUMZ/DUNgEx9i2TIhCA1mpBFIfxWZy+sH6H+sqqfX3sPHsGu0ug=="};
        
        bytes message_bytes (message.size ());
        std::copy (message.begin (), message.end (), message_bytes.begin ());
        
        bytes encrypted_bytes = encrypt (message_bytes, bobKey.Secret.to_public ());
        
        EXPECT_EQ (encrypted, encoding::base64::write (message_bytes));
        
        bytes decrypted_bytes = decrypt (encrypted_bytes, bobKey.Secret);
        
        EXPECT_EQ (decrypted_bytes, message_bytes);
        
        bytes decrypted_bytes_alice = decrypt (encrypt(message_bytes, aliceKey.Secret.to_public ()), aliceKey.Secret);
        
        EXPECT_EQ (message_bytes, decrypted_bytes_alice);
        
    }

}

