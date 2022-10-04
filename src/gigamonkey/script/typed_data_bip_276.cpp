#include <gigamonkey/script/typed_data_bip_276.hpp>
#include <gigamonkey/address.hpp>

namespace Gigamonkey {
    
    string typed_data::write(type t, byte version, network n, const bytes& b) {
        std::stringstream ss;
        
        switch (t) {
            case bitcoin_script: {
                ss << "bitcoin-script";
            } break;
            
            default: throw "invalid data type";
        }
        
        bytes data = bytes::write(b.size() + 2, version, byte(n), b);
        
        ss << ':' << encoding::hex::write(data, encoding::hex::lower);
        
        auto checksum = Bitcoin::checksum(bytes::from_string(ss.str()));
        
        ss << encoding::hex::write(checksum, encoding::hex::lower);
        
        return ss.str();
    }
    
    typed_data typed_data::read(string_view z) {
        // 8 characters of checksum, 15 of "bitcoin-script:", 2 of version and 2 of network.
        if (z.size() <= 27) return {};
        
        if (!ctre::match<pattern>(z)) return {};
        
        bytes last_4_bytes = *encoding::hex::read(z.substr(z.size() - 8));
        
        uint32_little expected_checksum;
        std::copy(last_4_bytes.begin(), last_4_bytes.end(), expected_checksum.begin());
        uint32_little real_checksum = Bitcoin::checksum(bytes::from_string(z.substr(0, z.size() - 8)));
        
        // does the checksum match? 
        if (expected_checksum != real_checksum) return {};
        
        bytes payload = *encoding::hex::read(z.substr(15, z.size() - 23));
        
        if (payload[0] != 1 || payload[1] > 2) return {};
        
        return {bitcoin_script, 1, network(payload[1]), bytes{bytes_view{payload.data() + 2, payload.size() - 2}}};
        
    }
    
}
