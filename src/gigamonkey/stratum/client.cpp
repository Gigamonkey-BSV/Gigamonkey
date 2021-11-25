// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/client.hpp>

namespace Gigamonkey::Stratum {
    
    mining::configure_request::parameters client::requested_configuration() const {
        mining::configure_request::parameters p;
        if (VersionRollingRequest) p = p.add(*VersionRollingRequest);
        if (MinimumDifficultyRequest) p = p.add(*MinimumDifficultyRequest);
        if (SubscribeExtranonceRequest) p = p.add(*SubscribeExtranonceRequest);
        if (InfoRequest) p = p.add(*InfoRequest);
        return p;
    }
    
}
