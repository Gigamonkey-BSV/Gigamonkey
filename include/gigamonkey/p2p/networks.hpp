// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_NETWORKS_HPP
#define GIGAMONKEY_NETWORKS_HPP

#include <boost/array.hpp>

namespace Gigamonkey::Bitcoin::P2P {
enum class Networks {
  MainNet,
  TestNet,
  RegTest,
  ScaleTest,
};

boost::array<unsigned char, 4> getMagicNum(Networks network);
}
#endif //GIGAMONKEY_NETWORKS_HPP
