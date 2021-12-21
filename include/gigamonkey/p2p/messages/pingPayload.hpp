// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_MESSAGES_PINGPAYLOAD_HPP_
#define GIGAMONKEY_P2P_MESSAGES_PINGPAYLOAD_HPP_
#include "messagePayload.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
	class PingPayload : public MessagePayload {
	  private:
		data::uint64_little _nonce{};
	  public:
		const uint64_little &GetNonce() const {
			return _nonce;
		}
		void SetNonce(const uint64_little &nonce) {
			_nonce = nonce;
		}
		PingPayload(const data::bytes &input, Networks network)
			: MessagePayload(input, network) {
			std::copy(input.begin(),input.begin()+_nonce.size(),_nonce.begin());
		}
		explicit PingPayload(Networks network): MessagePayload(network) {}

		explicit operator data::bytes() override {
			data::bytes out(_nonce.size());
			std::copy(_nonce.begin(), _nonce.end(),out.begin());

			return out;
		}
	};
}
#endif //GIGAMONKEY_P2P_MESSAGES_PINGPAYLOAD_HPP_
