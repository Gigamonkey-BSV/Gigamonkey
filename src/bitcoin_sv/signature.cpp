
#include <gigamonkey/signature.hpp>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>

namespace Gigamonkey::Bitcoin {
    
    digest256 signature_hash(const input_index &v, sighash::directive d) {
        bytes_view x = output::script(v.output());
        CScript script(x.begin(), x.end());
        CDataStream stream{(const char*)(v.Transaction.data()), 
            (const char*)(v.Transaction.data() + v.Transaction.size()), SER_NETWORK, PROTOCOL_VERSION};
        CTransaction ctx{deserialize, stream};
        ::SigHashType hashType(d);
        Amount amount((int64)v.value());
        ::uint256 tmp= SignatureHash(script, ctx, v.Index, hashType, amount);
        digest<32> output;
        std::copy(output.begin(), tmp.begin(), tmp.end());
        return output;
    }

}
