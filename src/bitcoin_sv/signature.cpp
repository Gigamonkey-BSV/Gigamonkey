// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/signature.hpp>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>

namespace Gigamonkey::Bitcoin {
            
    incomplete::transaction::transaction(int32_little v, list<input> i, list<output> o, uint32_little l) : 
        Version{v}, Inputs(i.size()), Outputs(o.size()), Locktime{l} {
        for (int n = 0; n < i.size(); n++) {
            Inputs[n] = i.first();
            i = i.rest();
        }
        
        for (int n = 0; n < o.size(); n++) {
            Outputs[n] = o.first();
            o = o.rest();
        }
    }
    
    bytes incomplete::transaction::write() const {
        list<output> outputs;
        for (const output& o : Outputs) outputs = outputs << o;
        list<Bitcoin::input> inputs;
        for (const input& in : Inputs) inputs = inputs << Bitcoin::input{in.Reference, {}, in.Sequence};
        return Bitcoin::transaction{Version, inputs, outputs, Locktime}.write();
    }
    
    incomplete::transaction incomplete::transaction::read(bytes_view b) {
        auto tx = Bitcoin::transaction::read(b);
        return incomplete::transaction{tx.Version, 
            data::for_each([](const Bitcoin::input& in) -> incomplete::input {
                    return {in.Reference, in.Sequence};
                }, tx.Inputs), 
            tx.Outputs, tx.Locktime};
    }
    
    digest256 signature::document::hash(sighash::directive d) const {
        
        bytes tx = Transaction.write();
        
        CDataStream stream{(const char*)(tx.data()), 
            (const char*)(tx.data() + tx.size()), SER_NETWORK, PROTOCOL_VERSION};
        
        CTransaction ctx{deserialize, stream};
        
        ::uint256 tmp = SignatureHash(
            CScript(Previous.Script.begin(), Previous.Script.end()), ctx, Index, SigHashType(d), 
            Amount((int64)Previous.Value));
        
        digest<32> out;
        std::copy(tmp.begin(), tmp.end(), out.begin());
        
        return out;
        
    }

}
