// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef GIGAMONKEY_P2P_MESSAGES_VERSIONPAYLOAD_HPP_
#define GIGAMONKEY_P2P_MESSAGES_VERSIONPAYLOAD_HPP_
#include <ostream>
#include <boost/make_shared.hpp>
#include <boost/uuid/nil_generator.hpp>
#include "messagePayload.hpp"
#include "gigamonkey/p2p/address.hpp"
#include "gigamonkey/p2p/var_util.hpp"
#include "gigamonkey/p2p/var_int.hpp"
#include "gigamonkey/p2p/association_id.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
	class VersionPayload : public MessagePayload {
	  public:

		/**
		 * Constructs a Version Payload from data
		 * @param input input data
		 * @param network network to use
		 */
		VersionPayload(data::bytes input, int size,Networks network) : MessagePayload(input, size, network) {
			auto cur = input.begin();
			std::copy(cur, cur + _version.size(), _version.begin());
			cur += _version.size();
			std::copy(cur, cur + _services.size(), _services.begin());
			cur += _services.size();
			std::copy(cur, cur + _timestamp.size(), _timestamp.begin());
			cur += _timestamp.size();
			data::bytes addr_to(26);
			std::copy(cur, cur + 26, addr_to.begin());
			cur += 26;
			_addr_to = Address(addr_to, true);
			if (_version >= 106) {
				data::bytes addr_from(26);
				std::copy(cur, cur + 26, addr_from.begin());
				cur += 26;
				_addr_from = Address(addr_from, true);
				std::copy(cur, cur + _nonce.size(), _nonce.begin());
				cur += _nonce.size();
				uint64_little user_agent_size = readVarInt(cur);
				data::bytes user_agent(user_agent_size);
				for (int i = 0; i < user_agent_size; i++) {
					user_agent[i] = *cur++;
				}
				_user_agent = std::string(reinterpret_cast<char const *>(user_agent.data()));
				std::copy(cur, cur + _start_height.size(), _start_height.begin());
				cur += _start_height.size();
				if (_version >= 70001)
					_relay = *cur++ == 1;
			}
			int assocSize = readVarInt(cur);
			cur++;
			if(assocSize!=0) {
				auto temp=data::bytes(assocSize);
				std::copy(cur,cur+assocSize,temp.begin());
				_assocId = AssociationID::create(temp);
			}
			else {
				_assocId=boost::make_shared<UUIDAssociationId>();
			}
		}

		/**
		 * Constructs a blank Version Payload
		 * @param network network to use
		 */
		explicit VersionPayload(int size,Networks network) : MessagePayload(size,network) {
			_addr_from = Address(true);
			_addr_to = Address(true);
			_assocId=boost::make_shared<UUIDAssociationId>();
			//if(_assocId.)
		}
		/**
		 * Gets the bytes of the payload
		 * @return bytes of the payload
		 */
		explicit operator data::bytes() override {
			int size = 4 + 8 + 8 + 26;
			if (_version >= 106)
				size += 26 + 8 + 4 + var_int::size(_user_agent.size()) + _user_agent.size();
			if (_version >= 70001)
				size += 1;
			data::bytes output(size);
			auto cur = output.begin();
			std::copy(_version.begin(), _version.end(), cur);
			cur += _version.size();
			std::copy(_services.begin(), _services.end(), cur);
			cur += _services.size();
			std::copy(_timestamp.begin(), _timestamp.end(), cur);
			cur += _timestamp.size();
			data::bytes addr_to = static_cast<bytes>(_addr_to);
			std::copy(addr_to.begin(), addr_to.end(), cur);
			cur += addr_to.size();
			if (_version >= 106) {
				data::bytes addr_from = static_cast<bytes>(_addr_from);
				std::copy(addr_from.begin(), addr_from.end(), cur);
				cur += addr_from.size();
				std::copy(_nonce.begin(), _nonce.end(), cur);
				cur += _nonce.size();
				data::bytes user_agent_size = writeVarInt(_user_agent.size());
				std::copy(user_agent_size.begin(), user_agent_size.end(), cur);
				cur += user_agent_size.size();
				std::copy(_user_agent.begin(), _user_agent.end(), cur);
				cur += _user_agent.size();
				std::copy(_start_height.begin(), _start_height.end(), cur);
				cur += _start_height.size();
				if (_version >= 70001) {
					*cur = _relay ? 1 : 0;
					cur++;
				}
				if(_assocId != NULL) {
					data::bytes temp = static_cast<bytes>(*_assocId);
					if(temp.size()>0) {
						data::bytes siz = writeVarInt(temp.size());

						output.resize(output.size() + var_int::size(temp.size()) + temp.size());
						std::copy(siz.begin(), siz.end(), cur);
						cur += siz.size();
						if (temp.size() > 0) {
							std::copy(temp.begin(), temp.end(), cur);
							cur += temp.size();
						}
					}
				}

			}
			return output;
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

		/**
		 * Gets the association ID
		 * @return associationID
		 */
		[[nodiscard]] const boost::shared_ptr<AssociationID> &getAssocId() {
			return _assocId;
		}

		/**
		 * Sets the associationID
		 * @param assoc_id associationID
		 */
		void setAssocId(const boost::shared_ptr<AssociationID> &assoc_id) {
			_assocId = assoc_id;
		}

		friend ostream &operator<<(ostream &os, const VersionPayload &payload) {
			os << " version: " << payload._version << " services: "
			   << payload._services << " timestamp: " << payload._timestamp << " addr_to: " << payload._addr_to
			   << " addr_from: " << payload._addr_from << " nonce: " << payload._nonce << " user_agent: "
			   << payload._user_agent << " start_height: " << payload._start_height << " relay: " << payload._relay
			   << "association ID: " << payload._assocId.get();
			return os;
		}
		reader &read(reader &stream) override {
			std::cout << "Reading version" << std::endl;
			stream >> _version;
			stream >> _services;
			stream >> _timestamp;
			_addr_to= Address(_initial);
			stream >> _addr_to;
			if(_version >= 106) {
				stream >> _addr_from;
				stream >> _nonce;
				data::bytes agent;
				stream >> var_string(agent);
				_user_agent.resize(agent.size());
				std::copy(agent.begin(), agent.end(),_user_agent.begin());
				stream >> _start_height;
				if(_version >= 70001) {
					unsigned char relay;
					stream >> relay;
					_relay = (relay == 1);
				}
				int size = 4 + 8 + 8 + 26;
				if (_version >= 106)
					size += 26 + 8 + 4 + var_int::size(_user_agent.size()) + _user_agent.size();
				if (_version >= 70001)
					size += 1;
				if(getSize() > size) {
					_assocId = AssociationID::create(stream);
				}
			}
			return stream;
		}

		writer &write(writer &stream) const override {
			std::cout << "Writing version" << std::endl;

			stream << _version;
			stream << _services;
			stream << _timestamp;
			stream << _addr_to;
			if(_version >= 106) {
				stream << _addr_from;
				stream << _nonce;
				data::bytes agent;
				agent.resize(_user_agent.size());
				std::copy(_user_agent.begin(), _user_agent.end(),agent.begin());
				stream << var_string(agent);
				stream << _start_height;
				if(_version >= 70001) {
					stream << (_relay? 1:0);

				}
				if(_assocId) {
					lazy_bytes_writer assoc;
					assoc << *_assocId;
					stream << var_int(((data::bytes)assoc).size());
					stream << *_assocId;
				}
			}
			return stream;
		}
		~VersionPayload() override = default;
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
		boost::shared_ptr<AssociationID> _assocId;
	};
}
#endif //GIGAMONKEY_P2P2_MESSAGES_VERSIONPAYLOAD_HPP_
