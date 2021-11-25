// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_REMOTE
#define GIGAMONKEY_STRATUM_REMOTE

#include <gigamonkey/stratum/extensions.hpp>
#include <gigamonkey/stratum/mining_configure.hpp>
#include <gigamonkey/stratum/mining_authorize.hpp>
#include <gigamonkey/stratum/mining_subscribe.hpp>
#include <gigamonkey/stratum/mining_notify.hpp>
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
    
    // can be used for a remote server or a remote client. 
    class remote : json_bi_stream {
        
        virtual void notify(const notification &) = 0;
        
        virtual void request(const Stratum::request &) = 0;
        
        // Number of requests sent in this session. It is used as the 
        // message id. 
        uint64 Requests;
        
        // we keep track of requests that were made of the remote peer and
        // promises to the requestor. 
        std::list<std::pair<Stratum::request, std::promise<response>*>> AwaitingResponse;
        
        std::mutex Mutex;
        
        void handle_response(const response &p) {
            std::lock_guard<std::mutex> lock(Mutex);
            
            // find the message that is beind responded to. 
            auto it = std::find_if(AwaitingResponse.begin(), AwaitingResponse.end(), 
                [&p](const std::pair<Stratum::request, std::promise<response>*> r) -> bool {
                    return p.id() == r.first.id();
                });
            
            if (it == AwaitingResponse.end()) throw std::logic_error {"invalid message id"};
            
            it->second->set_value(p);
            delete it->second;
            AwaitingResponse.erase(it); 
            
        }
        
        void error(const io_error&) final override;
        
        void receive(const json &next) final override {
            if (notification::valid(next)) notify(notification{next});
            if (response::valid(next)) handle_response(response{next});
            if (Stratum::request::valid(next)) request(Stratum::request{next});
            // TODO handle an error if the message is ill-formed. 
        }
        
    public:
        // there are two ways to talk to a server: request and notify. 
        // request expects a response and notify does not. 
        std::future<response> request(method m, parameters p) {
            std::lock_guard<std::mutex> lock(Mutex);
            AwaitingResponse.push_back(std::pair{Stratum::request{message_id(Requests), m, p}, new std::promise<response>()});
            this->send(AwaitingResponse.back().first);
            Requests++;
            return AwaitingResponse.back().second->get_future();
        }
        
        void notify(method m, parameters p) {
            this->send(notification{m, p});
        }
        
        remote(tcp::socket &&s) : json_bi_stream{std::move(s)} {}
        
        virtual ~remote();
        
    };
    
}

#endif 

