
#include <gigamonkey/signature.hpp>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>

namespace Gigamonkey::Bitcoin {
    
    digest256 signature_hash(const bytes_view tx, index i, sighash::directive d) {
        
        CDataStream stream{(const char*)(tx.data()), 
            (const char*)(tx.data() + tx.size()), SER_NETWORK, PROTOCOL_VERSION};
        CTransaction ctx{deserialize, stream};
        
        bytes_view o = transaction::output(tx, i);
        bytes_view x = output::script(o);
        
        ::uint256 tmp= SignatureHash(CScript(x.begin(), x.end()), ctx, i, SigHashType(d), Amount((int64)output::value(o)));
        
        digest<32> output;
        std::copy(output.begin(), tmp.begin(), tmp.end());
        return output;
        
    }

}
