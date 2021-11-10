// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/smart_ptr.hpp>
#ifndef GIGAMONKEY_MESSAGE_HPP
#define GIGAMONKEY_MESSAGE_HPP
#include <gigamonkey/p2p/messages/message_payload.hpp>
#include "message_header.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages
{
    //template<typename T, std::enable_if_t<std::is_base_of_v<MessagePayload, T>, bool> = true>
    class Message{

    private:
        MessageHeader body;
        boost::shared_ptr<MessagePayload> payload;
    };
}
#endif //GIGAMONKEY_MESSAGE_HPP
