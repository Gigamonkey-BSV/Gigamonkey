// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_ASSOCIATION_ID_HPP_
#define GIGAMONKEY_P2P_ASSOCIATION_ID_HPP_

#include <boost/shared_ptr.hpp>
#include <boost/uuid/uuid.hpp>
#include "data/cross.hpp"
#include "gigamonkey/types.hpp"
namespace Gigamonkey::Bitcoin::P2P {
	class AssociationID {
	  public:
		explicit AssociationID(data::bytes data) {};
		AssociationID()= default;
		virtual explicit operator data::bytes() = 0;
		virtual explicit operator std::string() = 0;
		static boost::shared_ptr<AssociationID> create(data::bytes data);
		static boost::shared_ptr<AssociationID> create(reader &stream);
		virtual reader &read(reader& stream) = 0;
		virtual writer &write(writer & stream) const =0;
		/**
		 * Reads an address from a stream
		 * @param stream Stream to read from
		 * @param address Address to read into
		 * @return stream
		 */
		friend reader &operator>>(reader &stream, AssociationID &address) {
			return address.read(stream);
		}

		/**
		 * Writes an AssociationID to stream
		 * @param stream Stream to write to
		 * @param address AssociationID to write
		 * @return Stream
		 */
		friend writer &operator<<(writer &stream, const AssociationID &address){
			return address.write(stream);
		}
	};

	class UUIDAssociationId : public AssociationID {
	  public:
		explicit UUIDAssociationId(data::bytes data);
		UUIDAssociationId();
		void generateRandom();
		explicit operator data::bytes() override;
		explicit operator std::string() override;
		reader &read(reader &stream) override;
		writer &write(writer &stream) const override;

	  private:
		boost::uuids::uuid _assocId{};
	};
}
#endif //GIGAMONKEY_P2P_ASSOCIATION_ID_HPP_
