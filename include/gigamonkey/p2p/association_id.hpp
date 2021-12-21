// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_ASSOCIATION_ID_HPP_
#define GIGAMONKEY_P2P_ASSOCIATION_ID_HPP_

#include <boost/shared_ptr.hpp>
#include <boost/uuid/uuid.hpp>
#include "data/cross.hpp"
namespace Gigamonkey::Bitcoin::P2P {
	class AssociationID {
	  public:
		explicit AssociationID(data::bytes data) {};
		AssociationID()= default;
		virtual explicit operator data::bytes() = 0;
		virtual explicit operator std::string() = 0;
		static boost::shared_ptr<AssociationID> create(data::bytes data);
	};

	class UUIDAssociationId : public AssociationID {
	  public:
		explicit UUIDAssociationId(data::bytes data);
		UUIDAssociationId();
		void generateRandom();
		explicit operator data::bytes() override;
		explicit operator std::string() override;

	  private:
		boost::uuids::uuid _assocId{};
	};
}
#endif //GIGAMONKEY_P2P_ASSOCIATION_ID_HPP_
