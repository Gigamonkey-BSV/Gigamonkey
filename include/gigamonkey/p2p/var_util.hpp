// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_VAR_INT_HPP_
#define GIGAMONKEY_P2P_VAR_INT_HPP_

#include <cstdint>
#include "data/cross.hpp"
#include "data/encoding/endian/arithmetic.hpp"
namespace Gigamonkey::Bitcoin::P2P {
data::uint64_little readVarInt(data::bytes::iterator &input);
data::bytes writeVarInt(data::uint64_little input);
}
#endif //GIGAMONKEY_P2P2_VAR_INT_HPP_
