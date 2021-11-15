// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/p2p/messages/message_payload.hpp>
#include "data/types.hpp"
#include "data/cross.hpp"
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/beast/core/ostream.hpp>

namespace Gigamonkey::Bitcoin::P2P::Messages
{

    MessagePayload::operator data::bytes() {
        data::bytes output;
        std::vector<unsigned char,std::allocator<unsigned char>> tmp;
        boost::asio::dynamic_vector_buffer<unsigned char,std::allocator<unsigned char>> buf(tmp);
        auto buffer = boost::beast::ostream(buf);
        serialize(buffer);
        buffer.flush();
        output.resize(tmp.size());
        std::copy(tmp.begin(),tmp.end(),output.begin());
        return output;
    }

    uint32_t MessagePayload::getSize() const {
        return size;
    }

    void MessagePayload::setSize(uint32_t size) {
        MessagePayload::size = size;
    }
}