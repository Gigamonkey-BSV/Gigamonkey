// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/secp256k1.hpp>
#include <gigamonkey/address.hpp>
#include "gtest/gtest.h"
#include <gigamonkey/wif.hpp>
#include <boost/algorithm/string.hpp>

namespace Gigamonkey::Bitcoin {
    
    TEST (Format, WIF) {
        std::string wiki_wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        EXPECT_TRUE (secret {wiki_wif}.encode () == wiki_wif);
    }
    
    TEST (Format, Address) {
        std::string addr = "127NVqnjf8gB9BFAW2dnQeM6wqmy1gbGtv";
        EXPECT_TRUE (address {addr}.decode ().encode () == addr);
    }
    
    struct test_data {
        string SecretWIFCompressed;
        string SecretWIFUncompressed;
        string PubkeyHexCompressed;
        string PubkeyHexUncompressed;
        string AddressBase58;
        
        test_data (
            string secret_wif_compressed, 
            string secret_wif_uncompressed, 
            string pubkey_hex_compressed, 
            string pubkey_hex_uncompressed, 
            string address_base_58) : 
            SecretWIFCompressed {secret_wif_compressed},
            SecretWIFUncompressed {secret_wif_uncompressed},
            PubkeyHexCompressed {pubkey_hex_compressed},
            PubkeyHexUncompressed {pubkey_hex_uncompressed},
            AddressBase58 {address_base_58} {}
        
        bool operator == (const test_data& t) const {
            return SecretWIFCompressed == t.SecretWIFCompressed && 
                SecretWIFUncompressed == t.SecretWIFUncompressed && 
                PubkeyHexCompressed == t.PubkeyHexCompressed && 
                PubkeyHexUncompressed == t.PubkeyHexUncompressed &&
                AddressBase58 == t.AddressBase58;
        }
    };
    
    struct test_case {
        secret SecretWIFCompressed;
        secret SecretWIFUncompressed;
        pubkey PubkeyHexCompressed;
        pubkey PubkeyHexUncompressed;
        address AddressBase58;
        
        test_case (test_data data) :
                SecretWIFCompressed {data.SecretWIFCompressed},
                SecretWIFUncompressed {data.SecretWIFUncompressed},
                PubkeyHexCompressed {data.PubkeyHexCompressed},
                PubkeyHexUncompressed {data.PubkeyHexUncompressed},
                AddressBase58 {data.AddressBase58} {}
                
        test_data write () const {
            return test_data {SecretWIFCompressed.encode (),
                SecretWIFUncompressed.encode (),
                boost::to_upper_copy (string (PubkeyHexCompressed)),
                boost::to_upper_copy (string (PubkeyHexUncompressed)),
                AddressBase58.decode ().encode ()
            };
        }
                                
        bool valid () const {
            return SecretWIFCompressed.valid () && SecretWIFUncompressed.valid () &&
                SecretWIFCompressed.Secret == SecretWIFUncompressed.Secret &&
                PubkeyHexCompressed.valid () && PubkeyHexUncompressed.valid () &&
                AddressBase58.valid () &&
                PubkeyHexCompressed == PubkeyHexUncompressed.compress () &&
                PubkeyHexCompressed.decompress () == PubkeyHexUncompressed &&
                SecretWIFCompressed.to_public ().compress () == PubkeyHexCompressed &&
                SecretWIFUncompressed.to_public ().decompress () == PubkeyHexUncompressed &&
                SecretWIFCompressed.address ().encode () == AddressBase58;
            
        }
    };
    
    TEST(Format, Format) {
    
        auto positive_tests = list<test_data> {} <<
                test_data ("L2rW8amvjR19iSZ1wVU9keXBqEjQ9fMSCw9bsSKSmSCXTxqfz2Bn",
                        "5K6KqPc6q8FXyWogBXvH2jV8tiB4S5AALUDpmxadei44jTV6p4S",
                        "02DE7A990579BCA352633D340F05E7E7158661B0DCA0BA40A5AB5E0328A312216F",
                        "04DE7A990579BCA352633D340F05E7E7158661B0DCA0BA40A5AB5E0328A312216F"
                        "F40F50C2B6E03D863B19B9B679787FB75634F8BD00C2F2400196999CC9AB8E76",
                        "1AWfki61q1phyV1SA6Ytp38c9Ft5kipwV8") << 
                test_data ("KzmVx4hyCB6GAQoxMQae8GnokPG2hrJCP6Z7EjZS9MJZhf7pbpmW",
                        "5Jcun6poGDi4tXKLnrkRGhHGaPiU7zPUW2FyhGXupf8c3xFKwA5",
                        "023EA79C33BC21008356CA4C0E06A896014D94AD5216F54C44A3A94E1C8B39B1B1",
                        "043EA79C33BC21008356CA4C0E06A896014D94AD5216F54C44A3A94E1C8B39B1B1"
                        "F252B4B35D4CA96B8C6D7601A75D36F06BDB333B0E4F0C13C5E4004E49C5FE2A",
                        "1DKsEVtWQ6QGWBQ32fVDuCYQasxawApdqm") << 
                test_data ("L2HMpTWtyCdQkhL1tTQDSP4ssw7DVazacTBEzkAv1DSi8jjask6a",
                        "5JxpK17mrSHrnhQLgkbG42q1CYHpEj94Y9CPCixGBUHhb32UErf",
                        "03F063CDE7542B8FA3BC55739B44DA63B38AEE8583CD9E3C351D0BB2F5968D6805",
                        "04F063CDE7542B8FA3BC55739B44DA63B38AEE8583CD9E3C351D0BB2F5968D6805"
                        "BBB8F5C9ACEBB8DA15610B68DE0B2EE6441BD54D1893E06618C8E320010DCA17",
                        "13GYJRir1xn5cyVWqLzQPaiZr9BLJdfKAv") << 
                test_data ("L1vXPxhPFAe5taRGcmxcUuKKmmnbV1Q59TazBTFwHsVugRhQbGJU",
                        "5Jt6XaTpdjxyqqojWQKwiDJkDs2GWuerRaDEQfaHqEFhwGeMMo3",
                        "035A5CA5E685803CB8CD54198F3CFD71187F85F940EAECCE0D5D6551911306738C",
                        "045A5CA5E685803CB8CD54198F3CFD71187F85F940EAECCE0D5D6551911306738C"
                        "636205F2C171613EBDA6A345D1078D359B985C829B6E4715BC93BBEDD4E7740B",
                        "1DXj3zwApeKaSCyEZD5Pjkzai8p5XmwxzY");

        auto negative_tests = list<test_data> {} <<
                test_data ("IamJUNK",
                        "IamJUNK",
                        "IamJUNK",
                        "IamJUNK",
                        "IamJUNK") << 
                test_data ("KzmVx4hyCB6GAQoxMQae8GnokPG2hMJCP6Z7EjZS9MJZhf7pbpmW",
                        "5Jcun6poGDi4tXKLnrkMGhHGaPiU7zPUW2FyhGXupf8c3xFKwA5",
                        "023EA79C33BC21008356CA4C0E06AF96014D94AD5216F54C44A3A94E1C8B39B1B1",
                        "043EA79C33BC2100835ACA4C0E06A896014D94AD5216F54C44A3A94E1C8B39B1B1F252B4B35D4CA96B8C6D7601A75D36F06BDB333B0E4F0C13C5E4004E49C5FE2A",
                        "1DKsEVtWQ6QGWBQ32fVDuCYQasxaCApdqm");
        
        list<bool> success = data::lift ([] (test_data t) -> bool {
            bool b;
            test_case x {t};
            EXPECT_TRUE (b = x.valid ());
            EXPECT_TRUE (x.write () == t);
            return b;
        }, positive_tests);

        list<bool> failure = data::lift ([] (test_data t) -> bool {
            bool b;
            EXPECT_FALSE (b = test_case {t}.valid ());
            return b;
        }, negative_tests);
        
    }

}
