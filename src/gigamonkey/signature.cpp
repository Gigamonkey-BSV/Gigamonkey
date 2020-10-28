
#include <gigamonkey/signature.hpp>
#include <sv/key.h>
#include <sv/pubkey.h>
#include <sv/script/interpreter.h>
#include <sv/streams.h>

namespace Gigamonkey::Bitcoin {
    
    signature sign(const digest256& d, const secp256k1::secret& s) {
        signature x;
        sv::CKey z{};
        z.Set(s.Value.begin(), s.Value.end(), true);
        sv::uint256 hash{};
        std::copy(d.Value.begin(), d.Value.end(), hash.begin());
        z.Sign(hash, static_cast<std::vector<uint8_t> &>(x.Data));
        return x; 
    }
    
    bool verify(const signature& x, const digest256& d, const pubkey& p) {
        sv::uint256 hash{};
        std::copy(d.Value.begin(), d.Value.end(), hash.begin());
        return sv::CPubKey{p.Value.begin(), p.Value.end()}.Verify(hash, static_cast<const std::vector<uint8_t> &>(x.Data));
    }
    
    digest256 signature_hash(const input_index &v, sighash::directive d) {
        sv::CScript script(v.Output.Script.begin(),v.Output.Script.end());
        sv::CDataStream stream{static_cast<const std::vector<uint8_t>&>(v.Transaction), sv::SER_NETWORK, sv::PROTOCOL_VERSION};
        sv::CTransaction tx{sv::deserialize, stream};
        sv::SigHashType hashType(d);
        sv::Amount amount((long)v.Output.Value);
        sv::uint256 tmp = sv::SignatureHash(script, tx, v.Index, hashType, amount);
        digest<32> output;
        std::copy(output.begin(),tmp.begin(),tmp.end());
        return output;
    }

}
