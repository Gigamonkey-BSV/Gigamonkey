#include <gigamonkey/script/typed_data_bip_276.hpp>
#include <gigamonkey/p2p/checksum.hpp>

namespace Gigamonkey {
    
    string typed_data::write (type t, byte version, network n, const bytes &b) {
        std::stringstream ss;
        
        switch (t) {
            case bitcoin_script: {
                ss << "bitcoin-script";
            } break;
            
            default: throw "invalid data type";
        }
        
        bytes data = write_bytes (b.size () + 2, version, byte (n), b);
        
        ss << ':' << encoding::hex::write (data, data::hex_case::lower);
        
        auto checksum = Bitcoin::checksum (bytes (string (ss.str ())));
        
        ss << encoding::hex::write (checksum, data::hex_case::lower);
        
        return ss.str ();
    }
    
    typed_data typed_data::read (string_view z) {
        // 8 characters of checksum, 15 of "bitcoin-script:", 2 of version and 2 of network.
        if (z.size () <= 27) return {};
        
        if (!ctre::match<pattern> (z)) return {};
        
        bytes last_4_bytes = *encoding::hex::read (z.substr (z.size () - 8));
        
        Bitcoin::check expected_checksum;
        std::copy (last_4_bytes.begin (), last_4_bytes.end (), expected_checksum.begin ());
        Bitcoin::check real_checksum = Bitcoin::checksum (bytes (string (z.substr (0, z.size () - 8))));
        
        // does the checksum match? 
        if (expected_checksum != real_checksum) return {};
        
        bytes payload = *encoding::hex::read (z.substr (15, z.size () - 23));
        
        if (payload[0] != 1 || payload[1] > 2) return {};
        
        return {bitcoin_script, 1, network (payload[1]), bytes {bytes_view {payload.data () + 2, payload.size () - 2}}};
        
    }
    
}
