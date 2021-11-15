// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/smart_ptr.hpp>
#ifndef GIGAMONKEY_MESSAGE_HPP
#define GIGAMONKEY_MESSAGE_HPP
#include <gigamonkey/p2p/messages/message_payload.hpp>
#include <utility>
#include "message_header.hpp"
#include "gigamonkey/address.hpp"
#include "gigamonkey/p2p/networks.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages {
    /**
     * P2P Message
     */
    class Message{
    public:
        static Message create(string commandName,Networks network);

        Message(Networks network) : payload(),network(network),head(network) {};

/**
         * Gets the message header
         * @return Message header
         */
        [[nodiscard]] MessageHeader &getHead() {
            return head;
        }

        /**
         * Sets the message header
         * @param head message header
         */
        void setHead(const MessageHeader &new_head) {
            Message::head = new_head;
            setupPayload();

        }

        /**
         * Gets the Message payload
         * @return Message Payload
         */
        [[nodiscard]] boost::shared_ptr<MessagePayload> getPayload() {
            return payload;
        }

        /**
         * Sets the Message Payload
         * @param payload Message Payload
         */
        [[maybe_unused]] void setPayload(boost::shared_ptr<MessagePayload> new_payload) {
            Message::payload = std::move(new_payload);
        }

        /**
         * Input Stream Operator to decode the Message Payload from stream
         * @param in Input Stream
         * @param d Message
         * @return Input Stream
         */
        friend std::istream& operator>> (std::istream& in, Message& d);

        /**
         * Output Stream Operator to encode a Message into stream
         * @note This does not output a human friendly string
         * @param out Output Stream
         * @param d Message
         * @return Output Stream
         */
        friend std::ostream& operator<< (std::ostream& out, Message& d);

        /**
         * Converts a Message  to a human friendly string
         * @return String containing the message.
         */
        explicit operator std::string();

        /**
         * Sets the header up with size and checksum
         */
        void setupHeader();

        /**
         * Sets the payload to the correct object
         */
        void setupPayload();

        /**
         * Checks if the message is valid.
         * Just checks size and checksum
         * @return true if valid false otherwise
         */
        bool isValid();

        /**
         * Gets the command name message represents
         * @return command name
         */
        inline std::string getName() {
            return head.getCommandName();
        }

        /**
         * Gets the network this message is on
         * @return Network message is on
         */
        Networks getNetwork() const;

        /**
         * Sets the network this message is on
         * @param network network the message is on
         */
        void setNetwork(Networks network);

    private:
        MessageHeader head;
        boost::shared_ptr<MessagePayload> payload;
        Networks network;
    };


}
#endif //GIGAMONKEY_MESSAGE_HPP
