// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_MESSAGES_HPP
#define GIGAMONKEY_MESSAGES_HPP
#include "version_message.hpp"
#include "reject_message.hpp"
#include "unknown_message.hpp"
#include <boost/shared_ptr.hpp>
namespace Gigamonkey::Bitcoin::P2P::Messages {

    boost::shared_ptr<MessagePayload> makePayload(const std::string& payloadName) {
        if(payloadName == "version")
            return boost::shared_ptr<Messages::VersionMessage>(new Messages::VersionMessage());
        if(payloadName == "reject")
            return boost::shared_ptr<Messages::RejectMessage>(new Messages::RejectMessage());
        return boost::shared_ptr<Messages::UnknownMessage>(new Messages::UnknownMessage());
    }
}
#endif //GIGAMONKEY_MESSAGES_HPP
