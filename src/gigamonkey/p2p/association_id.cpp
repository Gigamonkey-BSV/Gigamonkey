// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sstream>
#include <boost/make_shared.hpp>
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"
#include "gigamonkey/p2p/association_id.hpp"

namespace Gigamonkey::Bitcoin::P2P {

	boost::shared_ptr<AssociationID> AssociationID::create(data::bytes data) {
		auto type=data[0];
		data::bytes temp(data.size()-1);
		std::copy(data.begin()+1, data.end(),temp.begin());
		if(type==0) {
			// UUID
			return boost::shared_ptr<UUIDAssociationId>(new UUIDAssociationId(temp));
		}
		else {
			std::stringstream err {};
			err << "Unsupported association ID type " << type;
			throw std::runtime_error(err.str());
		}
	}
	boost::shared_ptr<AssociationID> AssociationID::create(reader &stream) {
		unsigned char type;
		stream >> type;
		if(type==0) {
			auto ret=boost::shared_ptr<UUIDAssociationId>(new UUIDAssociationId());
			stream >> *ret;
			return ret;
		}
		else {
			std::stringstream err {};
			err << "Unsupported association ID type " << type;
			throw std::runtime_error(err.str());
		}


	}

	UUIDAssociationId::operator data::bytes() {
		if(_assocId.is_nil())
			return {};
		data::bytes out(_assocId.size()+1);
		out[0]=0;
		std::copy(_assocId.begin(), _assocId.end(),out.begin()+1);
		return out;
	}
	UUIDAssociationId::operator std::string() {
		return boost::uuids::to_string(_assocId);
	}
	UUIDAssociationId::UUIDAssociationId(data::bytes data) : AssociationID(data) {

		if(_assocId.size() != data.size())
		{
			return;
		}
		std::copy(data.begin(),data.end(),_assocId.begin());
	}
	UUIDAssociationId::UUIDAssociationId() {
		_assocId=boost::uuids::nil_uuid();
	};
	void UUIDAssociationId::generateRandom() {
		boost::uuids::basic_random_generator<boost::mt19937> gen {};
		_assocId=gen();
	}
	reader &UUIDAssociationId::read(reader &stream) {
		data::bytes input(_assocId.size());
		stream >> input;
		std::copy(input.begin(),input.end(),_assocId.begin());
		return stream;
	}
	writer &UUIDAssociationId::write(writer &stream) const {
		stream << (char)0;
		data::bytes input(_assocId.size());
		std::copy(_assocId.begin(), _assocId.end(),input.begin());
		stream << input;
		return stream;
	}
	UUIDAssociationId::operator boost::uuids::uuid() {
		return _assocId;
	}
}