
#include <gigamonkey/signature.hpp>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>

namespace Gigamonkey::Bitcoin {
    
    signature sign(const digest<32>& d, const secp256k1::secret& s) {
        signature x;
        CKey z{};
        z.Set(s.Value.begin(), s.Value.end(), true);
        ::uint256 hash{};
        std::copy(d.Value.begin(), d.Value.end(), hash.begin());
        z.Sign(hash, static_cast<std::vector<uint8_t> &>(x.Data));
        return x; 
    }
    
    bool verify(const signature& x, const digest<32>& d, const pubkey& p) {
        ::uint256 hash{};
        std::copy(d.Value.begin(), d.Value.end(), hash.begin());
        return CPubKey{p.Value.begin(), p.Value.end()}.Verify(hash, static_cast<const std::vector<uint8_t> &>(x.Data));
    }

    digest<32> signature_hash(const input_index &v, sighash::directive d) {
        CScript script(v.Output.Script.begin(),v.Output.Script.end());
        CDataStream stream{static_cast<const std::vector<uint8_t>&>(v.Transaction), SER_NETWORK, PROTOCOL_VERSION};
        CTransaction tx{deserialize, stream};
        ::SigHashType hashType(d);
        Amount amount((long)v.Output.Value);
        ::uint256 tmp= SignatureHash(script, tx, v.Index, hashType, amount);
        digest<32> output;
        std::copy(output.begin(),tmp.begin(),tmp.end());
        return output;
    }

}
