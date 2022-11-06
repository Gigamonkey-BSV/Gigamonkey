// Copyright (c) 2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/p2p/reject.hpp>

namespace Gigamonkey::Bitcoin::p2p {
    
    void session::receive(bytes_view b) {
        try {
            Buffer << b;
            message_type type = Buffer.message_type();
            if (type == nullptr) return;
            else if (message_type<transaction>() == type) {
                transaction tx{};
                Buffer >> tx;
                handle(tx);
            } else if (message_type<block>() == type) {
                block bl{};
                Buffer >> bl;
                handle(bl);
            } else if (message_type<reject>() == type) {
                reject r{};
                Buffer >> r;
                handle(r);
            } 
            // etc
        } catch (const reject &r) {
            send_message(r);
        }
    }
}
