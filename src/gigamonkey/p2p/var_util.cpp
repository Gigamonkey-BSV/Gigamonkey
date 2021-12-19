// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gigamonkey/p2p/var_util.hpp"
#include "data/encoding/endian/arithmetic.hpp"
namespace Gigamonkey::Bitcoin::P2P {

	data::uint64_little readVarInt(data::bytes::iterator &input) {
		unsigned char indicator = *input++;
		data::uint64_little result = indicator;
		if (indicator < 0xFD)
			return indicator;
		if (indicator == 0xFD) {
			data::uint16_little out;
			std::copy(input, input + 2, out.begin());
			input += 2;
			return static_cast<data::uint64_little>(out);
		} else if (indicator == 0xFE) {
			data::uint32_little out;
			std::copy(input, input + 4, out.begin());
			input += 4;
			return static_cast<data::uint64_little>(out);
		} else {
			data::uint64_little out;
			std::copy(input, input + 8, out.begin());
			input += 8;
			return out;
		}
	}

	data::bytes writeVarInt(data::uint64_little input) {
		data::bytes ret;
		data::bytes val;
		if (input < 0xFD)
			ret.push_back(input);
		else if (input <= 0xFFFF) {
			ret.push_back(0xFD);
			data::uint16_little data = static_cast<data::uint16_little>(input);
			val.reserve(2);
			std::copy(data.begin(), data.end(), val.begin());
		} else if (input <= 0xFFFFFFFF) {
			ret.push_back(0xFE);
			data::uint32_little data = static_cast<data::uint32_little>(input);
			val.reserve(4);
			std::copy(data.begin(), data.end(), val.begin());
		} else {
			ret.push_back(0xFF);
			val.reserve(8);
			std::copy(input.begin(), input.end(), val.begin());

		}
		for (int i = 0; i < val.size(); i++) {
			ret.push_back(val[i]);
		}
		return ret;
	}
}