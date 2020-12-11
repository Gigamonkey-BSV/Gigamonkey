
#include <gigamonkey/signature.hpp>

#include <sv/key.h>
#include <sv/pubkey.h>
#include <sv/script/interpreter.h>
#include <sv/streams.h>

namespace Gigamonkey::Bitcoin {
    
    signature sign(const digest256& d, const secp256k1::secret& s) {
        signature x;
        bsv::CKey z{};
        z.Set(s.Value.begin(), s.Value.end(), true);
        bsv::uint256 hash{};
        std::copy(d.Value.begin(), d.Value.end(), hash.begin());
        z.Sign(hash, static_cast<std::vector<uint8_t> &>(x.Data));
        return x; 
    }
    
    bool verify(const signature& x, const digest256& d, const pubkey& p) {
        bsv::uint256 hash{};
        std::copy(d.Value.begin(), d.Value.end(), hash.begin());
        return bsv::CPubKey{p.Value.begin(), p.Value.end()}.Verify(hash, static_cast<const std::vector<uint8_t> &>(x.Data));
    }
    
    digest256 signature_hash_original(const input_index &v, sighash::directive d) {
        bsv::CScript script(v.Output.Script.begin(),v.Output.Script.end());
        bsv::CDataStream stream{static_cast<const std::vector<uint8_t>&>(v.Transaction), bsv::SER_NETWORK, bsv::PROTOCOL_VERSION};
        bsv::CTransaction tx{bsv::deserialize, stream};
        bsv::SigHashType hashType(d);
        bsv::Amount amount((long)v.Output.Value);
        bsv::uint256 tmp = bsv::SignatureHash(script, tx, v.Index, hashType, amount, nullptr, false);
        digest<32> output;
        std::copy(output.begin(), tmp.begin(), tmp.end());
        return output;
    }
    
    digest256 signature_hash_forkid(const input_index &v, sighash::directive d) {
        bsv::CScript script(v.Output.Script.begin(),v.Output.Script.end());
        bsv::CDataStream stream{static_cast<const std::vector<uint8_t>&>(v.Transaction), bsv::SER_NETWORK, bsv::PROTOCOL_VERSION};
        bsv::CTransaction tx{bsv::deserialize, stream};
        bsv::SigHashType hashType(d);
        bsv::Amount amount((long)v.Output.Value);
        bsv::uint256 tmp = bsv::SignatureHash(script, tx, v.Index, hashType, amount, nullptr, true);
        digest<32> output;
        std::copy(output.begin(), tmp.begin(), tmp.end());
        return output;
    }

}
