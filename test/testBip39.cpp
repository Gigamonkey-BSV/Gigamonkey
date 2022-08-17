#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err58-cpp"
// Copyright (c) 2020 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include <gigamonkey/schema/hd.hpp>
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



class Bip39Tests : public ::testing::TestWithParam<std::tuple<Gigamonkey::hd::bip39::language,std::string,std::string,std::string,std::string,std::string>>
{

};

TEST_P(Bip39Tests,EntropyToWords)
{
    std::vector<char> example=HexToBytes(std::get<1>(GetParam()));
    Gigamonkey::hd::entropy ent(example.size());
    std::copy(example.begin(),example.end(),ent.begin());
    std::string output=Gigamonkey::hd::bip39::generate(ent,std::get<0>(GetParam()));
    ASSERT_EQ(output,std::get<2>(GetParam())) << "Given Entropy doesn't match the expected word list";
}
std::string hexStr(Gigamonkey::byte *data, int len)
{
     std::stringstream ss;
     ss << std::hex;

     for( int i(0) ; i < len; ++i )
         ss << std::setw(2) << std::setfill('0') << (int)data[i];

     return ss.str();
}

TEST_P(Bip39Tests,WordsToSeed) {
    const std::string& words=std::get<2>(GetParam());
    Gigamonkey::hd::seed seed=Gigamonkey::hd::bip39::read(words,std::get<3>(GetParam()),std::get<0>(GetParam()));
    ASSERT_EQ(hexStr(seed.data(),seed.size()),std::get<4>(GetParam())) <<  "output seed not matching";

}

TEST_P(Bip39Tests,WordsToKey) {
    const std::string& words=std::get<2>(GetParam());
    Gigamonkey::hd::seed seed=Gigamonkey::hd::bip39::read(words,std::get<3>(GetParam()),std::get<0>(GetParam()));

    Gigamonkey::hd::bip32::secret secret=Gigamonkey::hd::bip32::secret::from_seed(seed,Gigamonkey::hd::bip32::main);
    ASSERT_EQ(secret.write(),std::get<5>(GetParam())) << "Words do not become the right key";
}
TEST_P(Bip39Tests,EntropyToKey) {

    std::vector<char> example=HexToBytes(std::get<1>(GetParam()));
    Gigamonkey::hd::entropy ent(example.size());
    std::copy(example.begin(),example.end(),ent.begin());
    std::string output=Gigamonkey::hd::bip39::generate(ent);
    Gigamonkey::hd::seed seed=Gigamonkey::hd::bip39::read(output,std::get<3>(GetParam()),std::get<0>(GetParam()));

    Gigamonkey::hd::bip32::secret secret=Gigamonkey::hd::bip32::secret::from_seed(seed,Gigamonkey::hd::bip32::main);
    ASSERT_EQ(secret.write(),std::get<5>(GetParam())) << "Entropy does not become the right key";

}
TEST_P(Bip39Tests,WrongPassphraseFails) {
    const std::string& words=std::get<2>(GetParam());
    Gigamonkey::hd::seed seed=Gigamonkey::hd::bip39::read(words,"IFailToPassOrCode",std::get<0>(GetParam()));

    Gigamonkey::hd::bip32::secret secret=Gigamonkey::hd::bip32::secret::from_seed(seed,Gigamonkey::hd::bip32::main);
    ASSERT_NE(secret.write(),std::get<5>(GetParam())) << "Words become right key without correct passphrase";
}

TEST_P(Bip39Tests,CheckChecksum) {
    std::string& words= const_cast<std::string &>(std::get<2>(GetParam()));
    ASSERT_TRUE(Gigamonkey::hd::bip39::valid(words,std::get<0>(GetParam()))) << "Checksum should be valid";
    std::replace(words.begin(),words.end(),'a','e');
    std::replace(words.begin(),words.end(),'o','i');
    ASSERT_FALSE(Gigamonkey::hd::bip39::valid(words,std::get<0>(GetParam()))) << "Checksum should not valid on altered string";
}

INSTANTIATE_TEST_SUITE_P(Bip39,Bip39Tests,::testing::Values(
        /*std::make_tuple(
                Gigamonkey::hd::bip39::language::japanese,
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかめ",
                "TREZOR",
                "9d269b22155b3c915b09abfefd4e1104573c528f6977cde89c6a68152c3c714dc6c7e0e62f221c322f3f76e4d0bcca66c06e3d2f6a8d70d612c87dd6dee63976",
                "xprv9s21ZrQH143K3kavBMu7K49k18vjQHhNL1ciMgn7S9kDMKdyK1vEpF46UWyoXCvdBLEp8U2bhissPkC6iwXjMgRXyQ6SHbyYYGcnFqNXTW1"),
        std::make_tuple(
                Gigamonkey::hd::bip39::language::japanese,
                "00000000000000000000000000000000",
                "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
                "TREZOR",
                "5a6c23b5abdd5c3e1f7d77ad25ecd715647bdafb44dab324c730a76a45d7421daccee1a4ff0739715a2c56a8a9f1e527a5e3496224d91293bfcd9b5393bfff83",
                "xprv9s21ZrQH143K2TDo8AAss7eUkUqLFzBnypFpqjQUMVUrSMvrrgLiRxQPrYnhfoS9NPp3rex725rcuN8pkDL6pwqWfdPtiqa9ib1B37vZwfy"),*/
    std::make_tuple(
            Gigamonkey::hd::bip39::language::english,
        "3d842f35702e353e9871e6c450e81cca",
        "diesel cannon snap theory today palm gift devote session mansion already night",
        "",
        "a3cfb4e09b8297c8a4da01d57979a105e43b98a2f3b32f8161bd092636cb07444b60c979b1a1f9469a3cc11c416f2879b9f87b72a49f9dc7e5d2530ed648d55d",
        "xprv9s21ZrQH143K4PEL4MhLUSJAF2inysJ1tKwxbe3bZHr6Q1aNUkaLgb4RUt1Z4ZbNwAtQMGFnvcKtBDaWoY5BT2FpWFpgGeTHG7P64JKS2iy"),
    std::make_tuple(
            Gigamonkey::hd::bip39::language::english,
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "TREZOR",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"),
    std::make_tuple(
            Gigamonkey::hd::bip39::language::english,
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "TREZOR",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"
    ),
    std::make_tuple(
            Gigamonkey::hd::bip39::language::english,
        "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "TREZOR",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
                "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "TREZOR",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "TREZOR",
        "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "TREZOR",
        "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "TREZOR",
        "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "TREZOR",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "TREZOR",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "TREZOR",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "TREZOR",
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "TREZOR",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "TREZOR",
        "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
        "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        "TREZOR",
        "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
        "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "TREZOR",
        "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
        "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "c0ba5a8e914111210f2bd131f3d5e08d",
        "scheme spot photo card baby mountain device kick cradle pact join borrow",
        "TREZOR",
        "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
        "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
        "TREZOR",
        "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
        "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "TREZOR",
        "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
        "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "23db8160a31d3e0dca3688ed941adbf3",
        "cat swing flag economy stadium alone churn speed unique patch report train",
        "TREZOR",
        "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
        "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
        "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        "TREZOR",
        "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
        "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "TREZOR",
        "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
        "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "f30f8c1da665478f49b001d94c5fc452",
        "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        "TREZOR",
        "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
        "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        "TREZOR",
        "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
        "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX"
),
std::make_tuple(
        Gigamonkey::hd::bip39::language::english,
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "TREZOR",
        "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
        "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
)
));
#pragma clang diagnostic pop
