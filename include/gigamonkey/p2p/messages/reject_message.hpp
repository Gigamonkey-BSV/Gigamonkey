// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_REJECT_MESSAGE_HPP
#define GIGAMONKEY_REJECT_MESSAGE_HPP

#include "message_payload.hpp"
#include "gigamonkey/p2p/constants.hpp"
#include "gigamonkey/p2p/var_int.hpp"
#include "gigamonkey/p2p/var_string.hpp"
#include "utils.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages {
    class RejectMessage: public MessagePayload {
    public:
        void deserialize(std::istream &in) override {
            message=read_var_string(in);
            uint8_little ccode;
            decode(in,ccode);
            code= (RejectCodes) (int)ccode;
            reason= read_var_string(in);
            while(in.peek()!=EOF) {
                unsigned char tmp;
                in >> tmp;
                data.push_back(tmp);
            }
        }

        void serialize(std::ostream &out) override {
            write_var_string(out,message);
            uint8_little ccode=(int)code;
            encode(out,ccode);
            write_var_string(out,reason);
            for(unsigned char tmp:data) {
                out << tmp;
            }


        }

        explicit operator std::string() const override {
            std::stringstream ss;
            ss << " message: " << message << " code: " << (int)code
               << " reason: " << reason << " extra: " << data;
            return ss.str();
        }

    private:
        std::string message;
        RejectCodes code;
        std::string reason;
        data::bytes data;
    };
}
#endif //GIGAMONKEY_REJECT_MESSAGE_HPP
