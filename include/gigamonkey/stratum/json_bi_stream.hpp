// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_JSON_BI_STREAM
#define GIGAMONKEY_STRATUM_JSON_BI_STREAM

#include <gigamonkey/types.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio.hpp>
#include <future>

namespace Gigamonkey::Stratum {
    namespace io = boost::asio;
    using mutex = std::mutex;
    using lock_guard = std::lock_guard<mutex>;
    using io_error = boost::system::error_code;
    using tcp = io::ip::tcp;
    
    // https://dens.website/tutorials/cpp-asio
    
    // we need to use enable_shared_from_this because of the possibility that 
    // tcp_stream will go out of scope and be deleted before one of the 
    // handlers is called from async_read_until or async_write. 
    class json_bi_stream : public std::enable_shared_from_this<json_bi_stream> {
        
        tcp::socket Socket;
        io::streambuf Buffer;
        
        virtual void receive(const json&) = 0;
        virtual void error(const io_error&) = 0;
        
        void wait_for_message() {
            boost::asio::async_read_until(Socket, Buffer, "\n",  
                [self = shared_from_this()](const io_error& error, size_t bytes_transferred) -> void {
                    if (error) return self->error(error);
                    
                    std::stringstream ss;
                    ss << std::istream(&self->Buffer).rdbuf();
                    self->Buffer.consume(bytes_transferred);
                    self->receive(json{ss.str()});
                    self->wait_for_message();
                });
        }
        
    public:
        
        // note: message cannot be longer than 65536 bytes or this function 
        // is not thread-safe. 
        void send(const json &j) {
            boost::asio::async_write(Socket, io::buffer(string(j) + "\n"), io::transfer_all(), 
                [self = shared_from_this()](const io_error& error, size_t) -> void {
                    if (error) self->error(error);
                });
        }
        
        json_bi_stream(tcp::socket &&x) : Socket{std::move(x)}, Buffer{65536} {
            wait_for_message();
        }
        
        virtual ~json_bi_stream();
    
    };
    
}

#endif
