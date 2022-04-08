// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/json_bi_stream.hpp>

namespace Gigamonkey::Stratum {
    
    void json_bi_stream::wait_for_message() {
        boost::asio::async_read_until(Socket, Buffer, "\n",  
            [self = shared_from_this()](const io_error& error, size_t bytes_transferred) -> void {
                if (error) return self->handle_error(error);
                
                std::stringstream ss;
                ss << std::istream(&self->Buffer).rdbuf();
                self->Buffer.consume(bytes_transferred);
                try {
                    self->receive(json{ss.str()});
                    self->wait_for_message();
                } catch (...) {
                    self->Socket.close();
                }
            });
    }
    
    void json_bi_stream::send(const json &j) {
        boost::asio::async_write(Socket, io::buffer(string(j) + "\n"), io::transfer_all(), 
            [self = shared_from_this()](const io_error& error, size_t) -> void {
                if (error) self->handle_error(error);
            });
    }
    
}
