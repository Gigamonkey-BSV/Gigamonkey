// Copyright (c) 2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_SESSION
#define GIGAMONKEY_P2P_SESSION

#include <gigamonkey/p2p/p2p.hpp>
#include <gigamonkey/p2p/checksum.hpp>
#include <data/networking/session.hpp>

namespace Gigamonkey::Bitcoin::p2p {
    
    class session : virtual networking::session<bytes_view> {
    
        struct message_writer : data::writer<byte>{
            message_writer(bytes &);
            
            bytes_writer Bytes;
            checksum_writer Hash;
            
            // write to both the hash writer and the bytes_writer
            void write(const word*, size_t size) final override;
            
            void append_checksum();
            message_writer();
        };
        
        // We may need overloads for certain types of messages
        // that don't fit this format. 
        template <typename message> void send_message(const message &m) {
            // TODO keep track of last message sent so that we 
            // can send it again if the peer doesn't receive it properly. 
            bytes serialized{m.serialized_size() + 20};
            message_writer w{serialized};
            write_magic_bytes(w);
            w << message_type<message>();
            w << m;
            w.append_checksum();
            this->send(serialized);
        }
        
        struct buffer final : data::writer<byte>, data::reader<byte> {
            // throw away information until magic bytes are found. 
            // remember where the magic bytes are and keep all data
            // after that until a message can be read. 
            // Try to read a header after the message bytes and calculate
            // the checksum of the complete message. If that fails, throw
            // a reject message to be sent back to the peer. 
            void write(const byte*, size_t size) final override;
            // Returns a message type string once a message is ready to be read. 
            // this is only after the header has been read and checksum has been
            // verified. 
            const char *message_type();
            
            // only use these to read the message after it is ready. 
            void read(byte*, size_t size) final override;
            void skip(size_t) final override;
        };
        
        buffer Buffer;
        
        // message handlers for each type of message. 
        virtual void handle(const ping &) = 0;
        virtual void handle(const pong &) = 0;
        virtual void handle(const version &) = 0;
        virtual void handle(const verack &) = 0;
        virtual void handle(const addr &) = 0;
        virtual void handle(const getaddr &) = 0;
        virtual void handle(const inv &) = 0;
        virtual void handle(const getdata &) = 0;
        virtual void handle(const headers &) = 0;
        virtual void handle(const getheaders &) = 0;
        virtual void handle(const getblocks &) = 0;
        virtual void handle(const transaction &) = 0;
        virtual void handle(const block &) = 0;
        virtual void handle(const notfound &) = 0;
        virtual void handle(const reject &) = 0;
        
        void receive(bytes_view b) final override;
    public:
        session();
    };
    
}

#endif
