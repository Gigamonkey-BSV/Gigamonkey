#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err58-cpp"
// Copyright (c) 2020 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include <gigamonkey/schema/bip_39.hpp>
#include <gigamonkey/schema/electrum.hpp>
#include <random>
#include <utility>
std::vector<char> HexToBytes(const std::string& hex) {
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }

    return bytes;
}



  class ElectrumTests : public ::testing::TestWithParam<std::tuple<Gigamonkey::HD::BIP_39::language, std::string, std::string, Gigamonkey::HD::Electrum::prefix, std::string, std::string, std::string>>
{

};

//TEST_P(ElectrumTests,EntropyToWords)
//{
//    std::vector<char> example=HexToBytes(std::get<1>(GetParam()));
//    Gigamonkey::HD::entropy ent(example.size());
//    std::copy(example.begin(),example.end(),ent.begin());
//    std::string output=Gigamonkey::HD::BIP_39::generate(ent,std::get<0>(GetParam()));
//    ASSERT_EQ(output,std::get<2>(GetParam())) << "Given Entropy doesn't match the expected word list";
//}
std::string hexStr(Gigamonkey::byte *data, int len)
{
     std::stringstream ss;
     ss << std::hex;

     for( int i(0) ; i < len; ++i )
         ss << std::setw(2) << std::setfill('0') << (int)data[i];

     return ss.str();
}

TEST_P(ElectrumTests,WordsToSeed) {
	const std::string &words = std::get<2>(GetParam());
	Gigamonkey::HD::seed seed = Gigamonkey::HD::Electrum::read(words, std::get<4>(GetParam()), std::get<0>(GetParam()));
	ASSERT_EQ(hexStr(seed.data(), seed.size()), std::get<5>(GetParam())) << "output seed not matching";

}

TEST_P(ElectrumTests,WordsToKey) {
    const std::string& words=std::get<2>(GetParam());
    Gigamonkey::HD::seed seed=Gigamonkey::HD::Electrum::read(words,std::get<4>(GetParam()),std::get<0>(GetParam()));
	std::cout << hexStr(seed.data(),seed.size()) << std::endl;
    Gigamonkey::HD::BIP_32::secret secret=Gigamonkey::HD::BIP_32::secret::from_seed(seed,Gigamonkey::HD::BIP_32::main);
    ASSERT_EQ(secret.write(),std::get<6>(GetParam())) << "Words do not become the right key";
}

TEST_P(ElectrumTests,WordsToVersion) {
	const std::string& words=std::get<2>(GetParam());
	std::string version=Gigamonkey::HD::Electrum::version(words);

	ASSERT_EQ(Gigamonkey::HD::Electrum::stringToPrefix(version), std::get<3>(GetParam())) << "Words do not become the right version";

}
//TEST_P(ElectrumTests,EntropyToKey) {
//
//    std::vector<char> example=HexToBytes(std::get<1>(GetParam()));
//    Gigamonkey::HD::entropy ent(example.size());
//    std::copy(example.begin(),example.end(),ent.begin());
//    std::string output=Gigamonkey::HD::BIP_39::generate(ent);
//    Gigamonkey::HD::seed seed=Gigamonkey::HD::BIP_39::read(output,std::get<3>(GetParam()),std::get<0>(GetParam()));
//
//    Gigamonkey::HD::BIP_32::secret secret=Gigamonkey::HD::BIP_32::secret::from_seed(seed,Gigamonkey::HD::BIP_32::main);
//    ASSERT_EQ(secret.write(),std::get<5>(GetParam())) << "Entropy does not become the right key";
//
//}

//TEST_P(ElectrumTests,WrongPassphraseFails) {
//    const std::string& words=std::get<2>(GetParam());
//    Gigamonkey::HD::seed seed=Gigamonkey::HD::BIP_39::read(words,"IFailToPassOrCode",std::get<0>(GetParam()));
//
//    Gigamonkey::HD::BIP_32::secret secret=Gigamonkey::HD::BIP_32::secret::from_seed(seed,Gigamonkey::HD::BIP_32::main);
//    ASSERT_NE(secret.write(),std::get<5>(GetParam())) << "Words become right key without correct passphrase";
//}
//
//TEST_P(ElectrumTests,CheckChecksum) {
//    std::string& words= const_cast<std::string &>(std::get<2>(GetParam()));
//    ASSERT_TRUE(Gigamonkey::HD::BIP_39::valid(words,std::get<0>(GetParam()))) << "Checksum should be valid";
//    std::replace(words.begin(),words.end(),'a','e');
//    std::replace(words.begin(),words.end(),'o','i');
//    ASSERT_FALSE(Gigamonkey::HD::BIP_39::valid(words,std::get<0>(GetParam()))) << "Checksum should not valid on altered string";
//}

INSTANTIATE_TEST_SUITE_P(Electrum,ElectrumTests,::testing::Values(
    std::make_tuple(
            Gigamonkey::HD::BIP_39::language::english, // Language
        "", // Entropy
        "erode grain wire stand swap resist solve fog remind day auction reveal", // Words
			Gigamonkey::HD::Electrum::prefix::standard, // Version
        "", // passphrase
        "2d550530ba3a3706e00d96557fd0d3a31cf21789b2942e19ee26373b7bc57c39698edbf3f51815352bbcc52b2ac93003953aac659de40fdff2e698e7019f5cb5", // seed
        "xprv9s21ZrQH143K2J6FTkJHXyH3qih1qVWyWWvnNB3XGJvDjrQzsXGEGAJrLBtoRtgPaHDucxhAyzjyz7miqX8HGGorEmG7oa7S27wsJsNy4kq"), // key
    std::make_tuple(
            Gigamonkey::HD::BIP_39::language::english,
        "",
        "flat banner visa wealth various industry moment fury outside popular school juice",
		Gigamonkey::HD::Electrum::prefix::standard,
        "",
        "7d735171bf542c12c4c2bd5bcd3b133b7b67d58f1adf286d5966d495bf0a8326dd5be05240b46523a665fadbe74894d40fa90cbdd10601eced21e8f8cf2d5b10",
        "xprv9s21ZrQH143K2Sy9X5n4L7bgVoCpyFgcJjagBD7wjAVXpFCGS6HjRp7XMLQhziQSUr9GxpZ4z2t8ER1egvZCQSCzAwPyaoA4RfDykcyv5bG"),
	std::make_tuple(
		Gigamonkey::HD::BIP_39::language::english,
		"",
		"denial blade soon chase vocal odor strike kiss mercy behind actress action",
		Gigamonkey::HD::Electrum::prefix::standard,
		"",
		"75c7eaab07aa8e0e5c813d456a28773b6d201458bc06b678ea4f64a7763afcb8413202ef6923ec99c2fbb061d7f8d547210edbc59ef670159b4864d48c3df475",
		"xprv9s21ZrQH143K32T8VWbfT1jBbt6eRj23GD4wQt61uG2AC718yx37cwqkeuaNwtjFsknMU5sPUER4AidPx3PSmjpiV56xiwqjWz5FLxZoh1c")
));
#pragma clang diagnostic pop
