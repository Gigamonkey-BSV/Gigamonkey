// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_VERSION_MESSAGE_HPP
#define GIGAMONKEY_VERSION_MESSAGE_HPP
#include <gigamonkey/p2p/messages/message_payload.hpp>
#include "gigamonkey/p2p/address.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages {
    class VersionMessage : public MessagePayload {
    public:
        VersionMessage(bool initial): _initial(initial) {}
        void deserialize(std::istream &in) override {
            std::cout << "Called Version" << std::endl;
            in >> _addr_to;
        }

        void serialize(std::ostream &out) override {

        }

    private:
        bool _initial;
        int32_t _version;
        uint64_t _services;
        int64_t _timestamp;
        Address _addr_to;
        Address _addr_from;
        uint64_t _nonce;
        std::string _user_agent;
        int32_t _start_height;
        bool _relay;
    };
}
#endif //GIGAMONKEY_VERSION_MESSAGE_HPP
