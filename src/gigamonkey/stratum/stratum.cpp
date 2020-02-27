#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum {
    
    void to_json(json& j, const notify& p) {
        throw data::method::unimplemented{"to_json notify"}; // TODO
    }

    void from_json(const json& j, notify& p) {
        throw data::method::unimplemented{"from_json notify"}; // TODO
    }
    
    void to_json(json& j, const share& p) {
        throw data::method::unimplemented{"to_json share"}; // TODO
    }
    
    void from_json(const json& j, share& p) {
        throw data::method::unimplemented{"from_json share"}; // TODO
    }
    
}


