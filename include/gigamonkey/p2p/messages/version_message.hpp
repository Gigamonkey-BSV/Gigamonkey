// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_VERSION_MESSAGE_HPP
#define GIGAMONKEY_VERSION_MESSAGE_HPP
#include <gigamonkey/p2p/messages/message_payload.hpp>
#include "gigamonkey/p2p/address.hpp"
#include "utils.hpp"
#include "gigamonkey/p2p/constants.hpp"
#include "gigamonkey/p2p/var_int.hpp"
#include "gigamonkey/p2p/var_string.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages {
    /**
     * Payload for a Version Message
     */
    class VersionMessage : public MessagePayload {
    public:

        /**
         * Constructs a Version Message Payload
         */
        explicit VersionMessage(): _initial(false) {}

        /**
         * Constructs a Message Payload
         * @param initial is this the initial version packet?
         */
        explicit VersionMessage(bool initial): _initial(initial) {}

        /**
         * Deserialize the payload from an input stream
         * @param in Input stream to deserialize from
         */
        void deserialize(std::istream &in) override {

            decode(in,_version);
            decode(in,_services);
            decode(in,_timestamp);
            _addr_to.setInitial(_initial);
            in >> _addr_to;
            if(_version >= GIGAMONKEY_P2P_VERSION_MINIMUM) {
                _addr_from.setInitial(_initial);
                in >> _addr_from;
                decode(in,_nonce);
                _user_agent=read_var_string(in);

            }
            if(_version >= GIGAMONKEY_P2P_VERSION_HEIGHT) {
                decode(in,_start_height);
            }
            if(_version >= GIGAMONKEY_P2P_VERSION_RELAY) {
                unsigned char relay;
                in >> relay;
                _relay = relay == 1;
            }
        }

        /**
         * Serializes a payload to stream
         * @param out OutStream to stream to
         */
        void serialize(std::ostream &out) override {
            encode(out,_version);
            encode(out,_services);
            encode(out,_timestamp);
            out << _addr_to;
            if(_version >= GIGAMONKEY_P2P_VERSION_MINIMUM) {
                out << _addr_from;
                encode(out,_nonce);
                write_var_string(out,_user_agent);

            }
            if(_version >= GIGAMONKEY_P2P_VERSION_HEIGHT) {
                encode(out,_start_height);
            }
            if(_version >= GIGAMONKEY_P2P_VERSION_RELAY) {
                data::uint8_big relay=_relay;
                encode(out,relay);
                //out << (int)(_relay ? 0x1 : 0x0);
            }
        }
        /**
         * Outputs human readable version of payload
         * @return string in a human readable format
         */
        explicit operator std::string() const {
            std::stringstream str;
            str  << " version: " << _version << " services: "
                << _services << " timestamp: " << _timestamp << " addr_to: " << (std::string)_addr_to
                << " addr_from: " << (string)_addr_from << " nonce: " << _nonce << " user_agent: "
                << _user_agent << " start_height: " << _start_height << " relay: " << _relay;
            return str.str();
        }

        /**
         * Is this the initial message
         * @return true if initial
         */
        [[nodiscard]] bool isInitial() const {
            return _initial;
        }

        /**
         * Sets if this is the initial version packet
         * @param initial true if initial
         */
        void setInitial(bool initial) {
            _initial = initial;
        }

        /**
         * Gets the version number this packet represents
         * @return version number
         */
        [[nodiscard]] const int32_little &getVersion() const {
            return _version;
        }

        /**
         * Sets the version number this packet represents
         * @param version version number
         */
        void setVersion(const int32_little &version) {
            _version = version;
        }

        /**
         * Gets the services field of services this packet represents
         * @return Servies bit field
         */
        [[nodiscard]] const uint64_little &getServices() const {
            return _services;
        }

        /**
         * Sets the services field
         * @param services Services bit field
         */
        void setServices(const uint64_little &services) {
            _services = services;
        }

        /**
         * Timestamp the payload was sent
         * @return timestamp of the payload sent
         */
        [[nodiscard]] const int64_little &getTimestamp() const {
            return _timestamp;
        }

        /**
         * Sets the timestamp the payload was sent
         * @param timestamp timestamp payload sent
         */
        void setTimestamp(const int64_little &timestamp) {
            _timestamp = timestamp;
        }

        /**
         * Gets the network address of the node recieving this payload
         * @return Address to
         */
        [[nodiscard]] Address &getAddressTo() {
            return _addr_to;
        }

        /**
         * Sets the network address of the node this payload is for
         * @param addrTo Address to
         */
        void setAddressTo(const Address &addrTo) {
            _addr_to = addrTo;
        }

        /**
         * Gets the network address this payload is from.
         * @note 26 dummy bytes usually sent now.
         * @return Address from
         */
        [[nodiscard]] Address &getAddressFrom() {
            return _addr_from;
        }

        /**
         * Sets the network address this payload is from
         * @note 26 dummy bytes usually sent now.
         * @param addrFrom address from
         */
        void setAddressFrom(const Address &addrFrom) {
            _addr_from = addrFrom;
        }

        /**
         * Gets the random nonce this node uses.
         * Randomly generated every time a version packet is sent.
         * This nonce is used to detect connections to self.
         * @return nonce this node uses
         */
        [[nodiscard]] const uint64_little &getNonce() const {
            return _nonce;
        }

        /**
         * Sets the nonce this node uses
         * Randomly generated every time a version packet is sent.
         * This nonce is used to detect connections to self.
         * @param nonce Nonce the node uses
         */
        void setNonce(const uint64_little &nonce) {
            _nonce = nonce;
        }

        /**
         * Gets the node user agent
         * @return User agent of the node
         */
        [[nodiscard]] const string &getUserAgent() const {
            return _user_agent;
        }

        /**
         * Sets the node user agent
         * @param userAgent User agent of the node
         */
        void setUserAgent(const string &userAgent) {
            _user_agent = userAgent;
        }

        /**
         * Gets the last block received by the emitting node
         * @return Last block height
         */
        [[nodiscard]] const int32_little &getStartHeight() const {
            return _start_height;
        }

        /**
         * Sets the last block received by the emitting node
         * @param startHeight last block height
         */
        void setStartHeight(const int32_little &startHeight) {
            _start_height = startHeight;
        }

        /**
         * Whether the peer should announce relayed transactions or not
         * @return true if node announces
         */
        [[nodiscard]] bool isRelay() const {
            return _relay;
        }

        /**
         * Sets whether the peer announces relayed transactions or not
         * @param relay true if announces relayed transactions
         */
        void setRelay(bool relay) {
            _relay = relay;
        }

    private:
        bool _initial;
        data::int32_little _version{};
        data::uint64_little _services{};
        data::int64_little _timestamp{};
        Address _addr_to;
        Address _addr_from;
        data::uint64_little _nonce{};
        std::string _user_agent;
        data::int32_little _start_height{};
        bool _relay{};
    };
}
#endif //GIGAMONKEY_VERSION_MESSAGE_HPP
