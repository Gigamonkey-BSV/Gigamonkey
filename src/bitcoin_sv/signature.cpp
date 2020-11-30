
#include <gigamonkey/signature.hpp>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>

namespace Gigamonkey::Bitcoin {
    
    digest256 signature_hash(const input_index &v, sighash::directive d) {
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
