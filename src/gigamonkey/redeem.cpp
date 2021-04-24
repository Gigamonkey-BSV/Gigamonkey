#include <gigamonkey/redeem.hpp>

namespace Gigamonkey::Bitcoin::redemption {
    
    bytes redeem(incomplete x, bytes_view tx, index i, bool dummy_signature) {
        list<bytes> parts{};
        uint32 size = 0;
        while(!x.empty()) {
            bytes b = x.first().redeem(tx, i, dummy_signature);
            size += b.size();
            parts = parts << b;
        }
        bytes b(size);
        bytes_writer w{b.begin(), b.end()};
        write(w, parts);
        return b;
    }
    
    uint32 expected_size(incomplete x) {
        uint32 size = 0;
        
        while(!x.empty()) {
            size += x.first().expected_size();
            x = x.rest();
        }
        
        return size;
    };
    
}

namespace Gigamonkey::Bitcoin {
    
    ptr<bytes> redeem(list<data::entry<spendable, sighash::directive>> prev, list<output> out, uint32_little locktime) {
        
        satoshi spent = fold([](satoshi s, data::entry<spendable, sighash::directive> v) -> satoshi {
            return s + v.Key.Value;
        }, 0, prev);
        
        satoshi sent = fold([](satoshi s, output o) -> satoshi {
            return s + o.Value;
        }, 0, out);
        
        if (spent > sent) return {};
        
        bytes incomplete = transaction{data::for_each([](data::entry<spendable, sighash::directive> s) -> input {
            return input{s.Key.Outpoint, {}, s.Key.Sequence};
        }, prev), out, locktime}.write();
        
        uint32 ind{0};
        list<input> in;
        list<data::entry<spendable, sighash::directive>> p = prev;
        
        while (!p.empty()) {
            data::entry<spendable, sighash::directive> entry = p.first();
            in = in << input{entry.Key.Outpoint, 
                redemption::redeem(entry.Key.Redeemer->redeem(entry.Value), incomplete, ind++), 
                entry.Key.Sequence};
        }
        
        return std::make_shared<bytes>(transaction{in, out, locktime}.write());
    }
    
    bool ledger::vertex::valid() const {
        if (!double_entry::valid() || prevouts().valid()) return false; 
        list<prevout> p = prevouts();
        
        if (spent() > sent()) return false;
        
        // TODO run scripts
        throw "ledger::vertex::valid(): we need to run scripts.";
        return true;
    }
    
    uint32 ledger::vertex::sigops() const {
        throw method::unimplemented{"vertex::sigops"};
    }
    
}
