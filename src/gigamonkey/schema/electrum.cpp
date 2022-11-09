// Copyright (c) 2020-2022 Katrina Knight
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/schema/electrum.hpp>
#include <gigamonkey/schema/bip_39.hpp>
#include <data/encoding/base58.hpp>
#include <data/encoding/endian/endian.hpp>
#include <data/io/unimplemented.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hmac.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <boost/locale.hpp>
#include <utility>


namespace Gigamonkey::HD::Electrum {

	std::string version(std::string words) {
		const char* seed_phrase="Seed version";
		std::string output;
		CryptoPP::HMAC<CryptoPP::SHA512> hmac((byte*) seed_phrase,strlen(seed_phrase));
		output.clear();
		CryptoPP::StringSource source(words,true,new CryptoPP::HashFilter(hmac,new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
		return output.substr(0,2);

	}


	std::string prefixToString(prefix p) {
		switch(p) {
			case prefix::standard:
				return "01";
				default:
					throw std::runtime_error("Invalid prefix");
		}
	}
	prefix stringToPrefix(std::string p) {
		if(p=="01") return prefix::standard;
		else return prefix::non_electrum_key;
	}


	bool is_electrum_words(std::string words) {
		return stringToPrefix(version(std::move(words)))!=prefix::non_electrum_key;
	}

	seed read(std::string words, const string &passphrase, BIP_39::language lang) {
		std::string salt="electrum"+passphrase;
		CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
		byte key[64];
		pbkdf2.DeriveKey(key,sizeof(key),0,(const byte *)words.data(),words.length(),(const byte *)salt.data(),salt.length(),2048);
		seed seedObj(64);
		std::copy(std::begin(key),std::end(key),seedObj.begin());
		return seedObj;
	}

}