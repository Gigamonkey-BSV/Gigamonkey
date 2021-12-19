// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gigamonkey/p2p/networks.hpp"
namespace Gigamonkey::Bitcoin::P2P {

	boost::array<unsigned char, 4> getMagicNum(Networks network) {
		switch (network) {

			case Networks::MainNet:return {0xe3, 0xe1, 0xf3, 0xe8};
			case Networks::TestNet:return {0xf4, 0xe5, 0xf3, 0xf4};
			case Networks::RegTest:return {0xda, 0xb5, 0xbf, 0xfa};
			case Networks::ScaleTest:return {0xfb, 0xce, 0xc4, 0xf9};
		}
	}
}