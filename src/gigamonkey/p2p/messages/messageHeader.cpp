// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gigamonkey/p2p/messages/messageHeader.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {

MessageHeader::operator data::bytes() {
	data::bytes output(24);
	auto cur = output.begin();
	std::copy(_magicBytes.begin(), _magicBytes.end(), cur);
	cur = cur + _magicBytes.size();
	std::copy(std::begin(_commandName), std::end(_commandName), cur);
	cur = cur + 12;
	std::copy(_payloadSize.begin(), _payloadSize.end(), cur);
	cur = cur + _payloadSize.size();
	std::copy(_checksum.begin(), _checksum.end(), cur);
	cur = cur + _checksum.size();
	return output;
}
MessageHeader::MessageHeader(data::bytes input, Networks network) {
	_network = network;
	bool valid = true;
	boost::array<unsigned char, 4> magic = getMagicNum(network);
	boost::array<unsigned char, 4> magicIn{};
	auto cur = input.begin();
	std::copy(cur, cur + boost::array<unsigned char, 4>::size(), magicIn.begin());
	if (magicIn != magic) {
		return;
	}
	_magicBytes = magicIn;
	cur = cur + boost::array<unsigned char, 4>::size();

	std::copy(cur, cur + 12, std::begin(_commandName));
	cur = cur + 12;
	std::copy(cur, cur + _payloadSize.size(), _payloadSize.begin());
	cur = cur + _payloadSize.size();
	std::copy(cur, cur + _checksum.size(), _checksum.begin());
	cur = cur + _checksum.size();
}

MessageHeader::MessageHeader(Networks network) {
	_network = network;
}
const boost::array<unsigned char, 4> &MessageHeader::getMagicBytes() const {
	return _magicBytes;
}
void MessageHeader::setMagicBytes(const boost::array<unsigned char, 4> &magicBytes) {
	_magicBytes = magicBytes;
}
std::string MessageHeader::getCommandName() const {
	return {_commandName};
}

void MessageHeader::setCommandName(std::string name) {
	for (int i = 0; i < 12; i++) {
		if (name.length() > i)
			[[likely]]
				_commandName[i] = name[i];
		else
			[[unlikely]]
				_commandName[i] = 0x00;
	}
}
data::uint32_little MessageHeader::getPayloadSize() const {
	return _payloadSize;
}
void MessageHeader::setPayloadSize(data::uint32_little payloadSize) {
	_payloadSize = payloadSize;

}
const Gigamonkey::checksum &MessageHeader::getChecksum() const {
	return _checksum;
}
void MessageHeader::setChecksum(const Gigamonkey::checksum &checksum) {
	_checksum = checksum;
}
ostream &operator<<(ostream &os, const MessageHeader &header) {
	os << "Magic bytes: ";
	for (unsigned char i: header.getMagicBytes()) {
		os << std::hex << (unsigned int)i << ", ";
	}
	os << " Command Name: " << header.getCommandName() << " Payload Size: "
	   << header.getPayloadSize() << " Checksum: ";
	for (unsigned char i: header.getChecksum())
		os << std::hex << (unsigned int)i << ", ";
	return os;
}
}
