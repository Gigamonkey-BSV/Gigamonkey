// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_UNKNOWN_MESSAGE_HPP
#define GIGAMONKEY_UNKNOWN_MESSAGE_HPP

#include <sstream>
#include "message_payload.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages {
    class UnknownMessage : public MessagePayload {
    public:
        void deserialize(std::istream &in) override {
            for(int i=0;i<getSize();i++)
            {
                unsigned char tmp;
                in >> tmp;
                data.push_back(tmp);
            }
        }

        void serialize(std::ostream &out) override {

        }

        explicit operator std::string() const override {
            std::stringstream ss;
            ss << "Data: " << data;
            return ss.str();
        }

    private:
        data::bytes data;
    };
}
#endif //GIGAMONKEY_UNKNOWN_MESSAGE_HPP
