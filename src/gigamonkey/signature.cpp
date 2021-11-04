// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/signature.hpp>

namespace Gigamonkey::Bitcoin {
    
    script_error inline signature::verify(const signature& x, const secp256k1::pubkey& p, const document& doc, uint32 flags) {
        auto d = x.sighash();
        auto raw = x.raw();
        
        if (!sighash::valid(d)) return SCRIPT_ERR_SIG_HASHTYPE;
        if (sighash::has_fork_id(d) && !(flags & SCRIPT_ENABLE_SIGHASH_FORKID)) return SCRIPT_ERR_ILLEGAL_FORKID;
        if (!sighash::has_fork_id(d) && (flags & SCRIPT_ENABLE_SIGHASH_FORKID)) return SCRIPT_ERR_MUST_USE_FORKID;
        
        if (flags & SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE && !p.compressed()) return SCRIPT_ERR_NONCOMPRESSED_PUBKEY;
        else if (flags & SCRIPT_VERIFY_STRICTENC && !p.valid()) return SCRIPT_ERR_PUBKEYTYPE;
        
        if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) && !signature::DER(x)) 
            return SCRIPT_ERR_SIG_DER;
        
        if ((flags & SCRIPT_VERIFY_LOW_S) && !secp256k1::signature::normalized(raw)) return SCRIPT_ERR_SIG_HIGH_S;
        
        return p.verify(signature::hash(doc, d), raw) ? SCRIPT_ERR_OK : SCRIPT_ERR_CHECKSIGVERIFY;
    }
    
    Bitcoin::transaction incomplete::transaction::complete(list<bytes> scripts) const {
        if (scripts.size() != Inputs.size()) return {};
        list<Bitcoin::input> in;
        list<output> out;
        for (const input& i : Inputs) {
            in = in << i.complete(scripts.first());
            scripts = scripts.rest();
        }
        for (const output& o : Outputs) out = out << o;
        return Bitcoin::transaction{Version, in, out, Locktime};
    }
    
    incomplete::transaction::transaction(int32_little v, list<input> i, list<output> o, uint32_little l) : 
        Version{v}, Inputs(i.size()), Outputs(o.size()), Locktime{l} {
        for (int n = 0; n < Inputs.size(); n++) {
            Inputs[n] = i.first();
            i = i.rest();
        }
        
        for (int n = 0; n < Outputs.size(); n++) {
            Outputs[n] = o.first();
            o = o.rest();
        }
    }
    
    incomplete::transaction::operator bytes() const {
        list<output> outputs;
        for (const output& o : Outputs) outputs = outputs << o;
        list<Bitcoin::input> inputs;
        for (const input& in : Inputs) inputs = inputs << Bitcoin::input{in.Reference, {}, in.Sequence};
        return bytes(Bitcoin::transaction{Version, inputs, outputs, Locktime});
    }
    
    incomplete::transaction::transaction(bytes_view b) {
        auto tx = Bitcoin::transaction{b};
        *this = incomplete::transaction{tx.Version, 
            data::for_each([](const Bitcoin::input& in) -> incomplete::input {
                    return {in.Reference, in.Sequence};
                }, tx.Inputs), 
            tx.Outputs, tx.Locktime};
    }

}
