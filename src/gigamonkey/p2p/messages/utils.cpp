// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <utility>
#include <gigamonkey/p2p/messages/utils.hpp>
#include <openssl/sha.h>
#include "data/cross.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages {

    void forward(std::istream &is, size_t amount, data::byte *to) {
        for (size_t i = 0; i < amount; i++) {
            is >> *to;
            to++;
        }
    }

//    template<boost::endian::order Order, bool is_signed, std::size_t bytes>
//    void decode(std::istream &reader, data::endian::arithmetic<Order, is_signed, bytes> &x) {
//        forward(reader, bytes, (data::byte *) (x.data()));
//    }
//
//    template<boost::endian::order Order, bool is_signed, std::size_t bytes>
//    void encode(std::ostream &writer, data::endian::arithmetic<Order, is_signed, bytes> &x) {
//        auto tmp=(data::bytes_view)x;
//        for(unsigned char i : tmp) {
//            writer << i;
//        }
//    }

}

