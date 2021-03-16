#include <gigamonkey/redeem.hpp>

namespace Gigamonkey::Bitcoin::redemption {
    
    bytes redeem(incomplete x, const input_index& tx, bool dummy_signature) {
        list<bytes> parts{};
        uint32 size = 0;
        while(!x.empty()) {
            bytes b = x.first().redeem(tx, dummy_signature);
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
    
    vertex redeem(list<data::entry<spendable, sighash::directive>> prev, list<output> out, uint32_little locktime) {
        satoshi spent = fold([](satoshi s, data::entry<spendable, sighash::directive> v) -> satoshi {
            return s + v.Key.Prevout.value();
        }, 0, prev);
        satoshi redeemed = fold([](satoshi s, output o) -> satoshi {
            return s + o.Value;
        }, 0, out);
        if (spent > redeemed) return {};
        bytes incomplete = transaction{data::for_each([](data::entry<spendable, sighash::directive> s) -> input {
            return input{s.Key.Prevout.input().Outpoint, {}, s.Key.Sequence};
        }, prev), out, locktime}.write();
        uint32 ind{0};
        list<input> in;
        list<prevout> prevouts;
        list<data::entry<spendable, sighash::directive>> p = prev;
        while (!p.empty()) {
            data::entry<spendable, sighash::directive> entry = p.first();
            in = in << input{entry.Key.Prevout.input().Outpoint, 
                redemption::redeem(entry.Key.Redeemer->redeem(entry.Value), 
                    input_index{incomplete, ind++}), 
                entry.Key.Sequence};
            prevouts = prevouts << entry.Key.Prevout;
        }
        return {prevouts, transaction{in, out, locktime}};
    }
    
    satoshi vertex::spent() const {
        return fold([](satoshi x, const prevout& p) -> satoshi {
            return x + p.value();
        }, satoshi{0}, Previous);
    }
    
    bool vertex::valid() const {
        if (!transaction().valid()) return false; 
        list<prevout> p = Previous;
        while(!p.empty()) {
            if(!p.first().valid()) return false;
            p = p.rest();
        }
        if (spent() > sent()) return false;
        // TODO run scripts
        return true;
    }
    
    uint32 vertex::sigops() const {
        throw method::unimplemented{"vertex::sigops"};
    }
    
}
