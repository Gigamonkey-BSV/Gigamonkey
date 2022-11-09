// Copyright (c) 2020-2022 Katrina Knight
// Distributed under the Open BSV software license, see the accompanying file LICENSE.


#ifndef GIGAMONKEY_INCLUDE_GIGAMONKEY_SCHEMA_ELECTRUM_HPP_
#define GIGAMONKEY_INCLUDE_GIGAMONKEY_SCHEMA_ELECTRUM_HPP_

#include <gigamonkey/schema/hd.hpp>
#include <gigamonkey/schema/bip_39.hpp>
namespace Gigamonkey::HD::Electrum {
	enum prefix {
		non_electrum_key,
		standard,
	};

	seed read(std::string words, const string& passphrase="", BIP_39::language lang=BIP_39::language::english);

	std::string generate(entropy, BIP_39::language lang=BIP_39::language::english);
	std::string generate(entropy, cross<std::string> word_list=BIP_39::english_words());
	bool valid(std::string words, BIP_39::language lang=BIP_39::language::english);

	std::string version(std::string words);
	std::string prefixToString(prefix p);
	prefix stringToPrefix(std::string p);
	bool is_electrum_words(std::string words);
}
#endif //GIGAMONKEY_INCLUDE_GIGAMONKEY_SCHEMA_ELECTRUM_HPP_
