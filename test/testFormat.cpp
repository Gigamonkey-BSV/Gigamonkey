// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/secp256k1.hpp>
#include <gigamonkey/address.hpp>
#include "gtest/gtest.h"
#include <gigamonkey/wif.hpp>

namespace gigamonkey::bitcoin {
    
    struct test_data {
        string secret_wif;
        string secret_wif_uncompressed;
        string pubkey_hex;
        string pubkey_hex_uncompressed;
        string addr_58;
        string cashaddr;
        
        test_data(string pSecret_wif,
                string pSecret_wif_uncompressed,
                string pPubkey_hex,
                string pPubkey_hex_uncompressed,
                string pAddr_58,
                string pCashaddr) : secret_wif{pSecret_wif}, secret_wif_uncompressed{pSecret_wif_uncompressed},
                                            pubkey_hex{pPubkey_hex}, pubkey_hex_uncompressed{pPubkey_hex_uncompressed},
                                            addr_58{pAddr_58}, cashaddr{pCashaddr} {}
    };
    
    test_data test_dat[] = {
            test_data("L2rW8amvjR19iSZ1wVU9keXBqEjQ9fMSCw9bsSKSmSCXTxqfz2Bn",
                    "5K6KqPc6q8FXyWogBXvH2jV8tiB4S5AALUDpmxadei44jTV6p4S",
                    "02DE7A990579BCA352633D340F05E7E7158661B0DCA0BA40A5AB5E0328A312216F",
                    "04DE7A990579BCA352633D340F05E7E7158661B0DCA0BA40A5AB5E0328A312216FF40F50C2B6E03D863B19B9B679787FB75634F8BD00C2F2400196999CC9AB8E76",
                    "1AWfki61q1phyV1SA6Ytp38c9Ft5kipwV8",
                    "bitcoincash:qp59tzmez92uts6y8pk72ax0dvee6an9agq3wk4zkh"),
            test_data("KzmVx4hyCB6GAQoxMQae8GnokPG2hrJCP6Z7EjZS9MJZhf7pbpmW",
                    "5Jcun6poGDi4tXKLnrkRGhHGaPiU7zPUW2FyhGXupf8c3xFKwA5",
                    "023EA79C33BC21008356CA4C0E06A896014D94AD5216F54C44A3A94E1C8B39B1B1",
                    "043EA79C33BC21008356CA4C0E06A896014D94AD5216F54C44A3A94E1C8B39B1B1F252B4B35D4CA96B8C6D7601A75D36F06BDB333B0E4F0C13C5E4004E49C5FE2A",
                    "1DKsEVtWQ6QGWBQ32fVDuCYQasxawApdqm",
                    "bitcoincash:qzrn9mwtv7hm8ezuanh3wk78wumtflc9msjqmh7pu4"),
            test_data("L2HMpTWtyCdQkhL1tTQDSP4ssw7DVazacTBEzkAv1DSi8jjask6a",
                    "5JxpK17mrSHrnhQLgkbG42q1CYHpEj94Y9CPCixGBUHhb32UErf",
                    "03F063CDE7542B8FA3BC55739B44DA63B38AEE8583CD9E3C351D0BB2F5968D6805",
                    "04F063CDE7542B8FA3BC55739B44DA63B38AEE8583CD9E3C351D0BB2F5968D6805BBB8F5C9ACEBB8DA15610B68DE0B2EE6441BD54D1893E06618C8E320010DCA17",
                    "13GYJRir1xn5cyVWqLzQPaiZr9BLJdfKAv",
                    "bitcoincash:qqvwp852xycjuf5erjyq0d7rnvyc0vsj0vjrmn0rpw"),
            test_data("L1vXPxhPFAe5taRGcmxcUuKKmmnbV1Q59TazBTFwHsVugRhQbGJU",
                    "5Jt6XaTpdjxyqqojWQKwiDJkDs2GWuerRaDEQfaHqEFhwGeMMo3",
                    "035A5CA5E685803CB8CD54198F3CFD71187F85F940EAECCE0D5D6551911306738C",
                    "045A5CA5E685803CB8CD54198F3CFD71187F85F940EAECCE0D5D6551911306738C636205F2C171613EBDA6A345D1078D359B985C829B6E4715BC93BBEDD4E7740B",
                    "1DXj3zwApeKaSCyEZD5Pjkzai8p5XmwxzY",
                    "bitcoincash:qzyhz96ud6hz40mmzw4nlgv5f7pk7dzxnqe9dp23lh")
    };
    
    test_data invalid_test_dat[] = {
            test_data("IamJUNK",
                    "IamJUNK",
                    "IamJUNK",
                    "IamJUNK",
                    "IamJUNK",
                    "IamJUNK"),
            test_data("KzmVx4hyCB6GAQoxMQae8GnokPG2hMJCP6Z7EjZS9MJZhf7pbpmW",
                    "5Jcun6poGDi4tXKLnrkMGhHGaPiU7zPUW2FyhGXupf8c3xFKwA5",
                    "023EA79C33BC21008356CA4C0E06AF96014D94AD5216F54C44A3A94E1C8B39B1B1",
                    "043EA79C33BC2100835ACA4C0E06A896014D94AD5216F54C44A3A94E1C8B39B1B1F252B4B35D4CA96B8C6D7601A75D36F06BDB333B0E4F0C13C5E4004E49C5FE2A",
                    "1DKsEVtWQ6QGWBQ32fVDuCYQasxaCApdqm",
                    "bitcoincash:qzrn9mwtv7hm8ezuanh3wk78wumt8lc9msjqmh7pu4"),
    };
    
    class FormatTest : public testing::TestWithParam<test_data> {
    public:
        secret SecretWIF;
        secret SecretWIFUncompressed;
        pubkey PubkeyHex;
        pubkey PubkeyHexUncompressed;
        address AddressBase58;
    protected:
        void SetUp() override {
            SecretWIF = secret(GetParam().secret_wif);
            SecretWIFUncompressed = secret(GetParam().secret_wif_uncompressed);
            PubkeyHex = pubkey(GetParam().pubkey_hex);
            PubkeyHexUncompressed = pubkey(GetParam().pubkey_hex_uncompressed);
            AddressBase58=address(GetParam().addr_58);
        }
    
    };
    
    class FormatInvalidTest : public testing::TestWithParam<test_data> {
    public:
        secret SecretWIF;
        secret SecretWIFUncompressed;
        pubkey PubkeyHex;
        pubkey PubkeyHexUncompressed;
        address AddressBase58;
    protected:
        void SetUp() override {
            SecretWIF = secret(GetParam().secret_wif);
            SecretWIFUncompressed = secret(GetParam().secret_wif_uncompressed);
            PubkeyHex = pubkey(GetParam().pubkey_hex);
            PubkeyHexUncompressed = pubkey(GetParam().pubkey_hex_uncompressed);
            AddressBase58=address(GetParam().addr_58);
        }
    
    };
    
    TEST_P(FormatTest, WIF) {
        EXPECT_TRUE(this->SecretWIF.valid()) << "Secret WIF is not valid";
        EXPECT_TRUE(this->SecretWIFUncompressed.valid()) << "Uncompressed Secret Wif is not valid";
        EXPECT_EQ(this->SecretWIF, this->SecretWIFUncompressed) << "Can't get public key from compressed secret";
    }
    
    TEST_P(FormatTest, PubHexValid) {
        EXPECT_TRUE(this->PubkeyHex.valid()) << "Public Key is not valid";
        EXPECT_TRUE(this->PubkeyHexUncompressed.valid()) << "Uncompressed Public Key is not valid";
        EXPECT_EQ(this->SecretWIF.to_public(), PubkeyHex) << "Can't get compressed public key from secret";
        EXPECT_EQ(this->SecretWIFUncompressed.to_public().decompress(), PubkeyHexUncompressed) << "Can't get uncompressed public key from secret";
        //EXPECT_TRUE(this->PubkeyHexUncompressed.compress() == this->PubkeyHex)
    }
    
    TEST_P(FormatTest, Addr58Valid) {
        EXPECT_TRUE(this->AddressBase58.valid()) << "Address in base 58 is not valid";
    }
    
    TEST_P(FormatTest, SecretWIFDecompression) {
        EXPECT_EQ(this->SecretWIF, this->SecretWIFUncompressed) << "Secret Wif not equal to it's decompressed version";
    }
    
    TEST_P(FormatTest, GetAddressFromPublicKey) {
        EXPECT_EQ(bitcoin::address{this->PubkeyHex}, this->AddressBase58) << "Can't get address from public key";
    }
    
    TEST_P(FormatTest, WriteSecretWIF) {
        wif Wif{wif::MainNet, this->SecretWIF, true};
        EXPECT_EQ(Wif.write(), GetParam().secret_wif) << "cannot derive wif " << GetParam().secret_wif << " from key " << SecretWIF.Value;
    }
    
    TEST_P(FormatTest, WritePubKey) {
        EXPECT_EQ(this->PubkeyHex.write_string(), GetParam().pubkey_hex);
    }
    
    TEST_P(FormatTest, WriteAddress) {
        EXPECT_EQ(this->AddressBase58.write(), GetParam().addr_58);
    }
    
    // Invalid Tests
    
    TEST_P(FormatInvalidTest, SecretWIFInvalid) {
        EXPECT_FALSE(this->SecretWIF.valid()) << "Secret WIF is valid";
    }
    
    TEST_P(FormatInvalidTest, SecretWIFUncompressedInvalid) {
        EXPECT_FALSE(this->SecretWIFUncompressed.valid()) << "Uncompressed Secret Wif is valid";
    }
    
    TEST_P(FormatInvalidTest, PubHexInvalid) {
        EXPECT_FALSE(this->PubkeyHex.valid()) << "Public Key isvalid";
    }
    
    TEST_P(FormatInvalidTest, PubHexUncompressedInvalid) {
        EXPECT_FALSE(this->PubkeyHexUncompressed.valid()) << "Uncompressed Public Key is valid";
    }
    
    TEST_P(FormatInvalidTest, Addr58Invalid) {
        EXPECT_FALSE(this->AddressBase58.valid()) << "Address in base 58 is valid";
    }
    
    INSTANTIATE_TEST_SUITE_P(Stage1Tests, FormatTest, testing::ValuesIn(test_dat));
    INSTANTIATE_TEST_SUITE_P(Stage1InvalidTests, FormatInvalidTest, testing::ValuesIn(invalid_test_dat));

}
