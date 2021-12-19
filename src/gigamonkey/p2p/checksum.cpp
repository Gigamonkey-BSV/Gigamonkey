// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/p2p/checksum.hpp>
#include <gigamonkey/hash.hpp>
#include <data/encoding/base58.hpp>

namespace Gigamonkey::Bitcoin {

Gigamonkey::checksum checksum(bytes_view b) {
	Gigamonkey::checksum x;
	digest256 digest = Hash256(b);
	std::copy(digest.Value.begin(), digest.Value.begin() + 4, x.begin());
	return x;
}

bytes_view remove_checksum(bytes_view b) {
	if (b.size() < 4) return {};
	Gigamonkey::checksum x;
	std::copy(b.end() - 4, b.end(), x.begin());
	bytes_view without = b.substr(0, b.size() - 4);
	if (x != checksum(without)) return {};
	return without;
}

}

namespace Gigamonkey::base58 {

string check::encode() const {
	bytes data = Bitcoin::append_checksum(static_cast<bytes>(*this));
	size_t leading_zeros = 0;
	while (leading_zeros < data.size() && data[leading_zeros] == 0) leading_zeros++;
	string b58 = data::encoding::base58::write(bytes_view(data).substr(leading_zeros));
	string ones(leading_zeros, '1');
	std::stringstream ss;
	ss << ones << b58;
	return ss.str();
}

check check::decode(string_view s) {
	size_t leading_ones = 0;
	while (leading_ones < s.size() && s[leading_ones] == '1') leading_ones++;
	encoding::base58::view b58(s.substr(leading_ones));
	if (!b58.valid()) return {};
	bytes_view decoded = bytes_view(b58);
	return {Bitcoin::remove_checksum(write(leading_ones + decoded.size(), bytes(leading_ones, 0x00), decoded))};
}

// try all single letter replacements, insertions, and deletions
// to see if we can find a valid base58 check encoded string.
check check::recover(const string_view invalid) {

	{
		check x(invalid);
		if (x.valid()) return x;
	}

	string test{invalid};

	string characters = data::encoding::base58::characters();

	// replacements
	for (int i = 0; i < test.size(); i++) {
		string replace = test;

		for (char c: characters) {
			if (replace[i] == c) continue;
			replace[i] = c;
			check x(replace);
			if (x.valid()) return x;
		}
	}

	// insertions
	for (int i = 0; i <= test.size(); i++) {
		string insert{};
		insert.resize(test.size() + 1);
		std::copy(test.begin(), test.begin() + i, insert.begin());
		std::copy(test.begin() + i, test.end(), insert.begin() + i + 1);

		for (char c: characters) {
			insert[i] = c;
			check x(insert);
			if (x.valid()) return x;
		}
	}

	// deletions
	for (int i = 0; i < test.size(); i++) {
		string deletions{};
		deletions.resize(test.size() - 1);

		std::copy(test.begin(), test.begin() + i, deletions.begin());
		std::copy(test.begin() + i + 1, test.end(), deletions.begin() + i);

		check x(deletions);
		if (x.valid()) return x;

	}

	return {};

}
}