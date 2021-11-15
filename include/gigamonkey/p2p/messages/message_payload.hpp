// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef GIGAMONKEY_MESSAGE_PAYLOAD_HPP
#define GIGAMONKEY_MESSAGE_PAYLOAD_HPP

#include <iostream>
#include <data/types.hpp>
#include "data/cross.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages
{
    class MessagePayload {
    public:
        virtual void deserialize(std::istream& in)=0;
        virtual void serialize(std::ostream& out)=0;
        explicit operator data::bytes();
        friend inline std::istream& operator>> (std::istream& in, MessagePayload& d) {
            d.deserialize(in);
            return in;
        }

        friend std::ostream& operator<< (std::ostream& out, MessagePayload& d) {
            d.serialize(out);
            return out;
        }
        virtual explicit operator std::string() const =0;

        uint32_t getSize() const;

        void setSize(uint32_t size);

    private:
        uint32_t size;
    };
}
#endif //GIGAMONKEY_MESSAGE_PAYLOAD_HPP
