#include <gigamonkey/stratum/mining_notify.hpp>

namespace Gigamonkey::Stratum::mining {
    
    notify::operator notification() const {
        throw data::method::unimplemented{""};
    }
    
    void to_json(json& j, const notify& p) {
        if (!p.valid()) {
            j = {};
            return; 
        }
        
        to_json(j, notification(p));
    }
    
    notify::notify(const notification& n) {/*
        if (!n.valid()) return;
        
        if (n.Method != mining_notify) return;
        
        if (n.Params.size() < 9) return;
        
        if (!(n.Params[0].is_number_unsigned())) return;
        
        if (!(n.Params[1].is_string())) return;
        encoding::hex::string previous{n.Params[1].get<string>()};
        if (!previous.valid()) return;
        bytes previous_bytes = bytes_view(previous);
        
        // the two parts of the coinbase. 
        if (!(n.Params[2].is_string())) return; 
        encoding::hex::string coinbase_1{n.Params[2].get<string>()};
        if (!coinbase_1.valid()) return;
        
        if (!(n.Params[3].is_string())) return;
        encoding::hex::string coinbase_2{n.Params[3].get<string>()};
        if (!coinbase_2.valid()) return;
        
        // merkle path
        if (!(n.Params[4].is_array())) return;
        cross<std::string> merkle(n.Params[4].size(), "");
        int i = 0;
        for (auto it = n.Params[4].begin(); it != n.Params[4].end(); it ++) {
            if (!it->is_string()) return;
            merkle[i] = it->get<string>();
            if (merkle[i].size() != 64) return;
        }
        
        if (!(n.Params[5].is_string())) return;
        
        
        if (!(n.Params[6].is_string())) return;
        
        
        if (!(n.Params[7].is_string())) return;  
        
        
        if (!(n.Params[8].is_boolean())) return; 
        
        ID = n.Params[0].get<uint32>();
        std::copy(previous_bytes.begin(), previous_bytes.end(), Digest.begin()); */
        
        throw data::method::unimplemented{""};
    }

    void from_json(const json& j, notify& p) {
        p = {};
        notification x;
        from_json(j, x);
        p = notify(x);
    }
    
    void to_json(json& j, const submit& p) {
        j = {};
    }
    
    submit::submit(const request& n) {
        if (!n.valid()) return;
        
        if (n.Method != mining_submit) return;
        
        throw data::method::unimplemented{""};
    }
    
    void from_json(const json& j, submit& p) {
        p = {};
        request x;
        from_json(j, x);
        p = submit(x);
    }
}
