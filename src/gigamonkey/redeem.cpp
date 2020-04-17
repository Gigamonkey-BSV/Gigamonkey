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
    
    transaction redeem(list<data::entry<spendable, sighash::directive>> prev, list<output> out, int32_little locktime) {
        satoshi spent = fold([](satoshi s, data::entry<spendable, sighash::directive> v) -> satoshi {
            return s + v.Key.Prevout.Output.Value;
        }, 0, prev);
        satoshi redeemed = fold([](satoshi s, output o) -> satoshi {
            return s + o.Value;
        }, 0, out);
        if (spent > redeemed) return {};
        bytes incomplete = transaction{data::for_each([](data::entry<spendable, sighash::directive> s) -> input {
                    return input{s.Key.Prevout.Outpoint, {}, s.Key.Sequence};
                }, prev), out, locktime}.write();
        uint32 ind{0};
        return transaction{for_each([&incomplete, &ind](data::entry<spendable, sighash::directive> s) -> input {
            return input{s.Key.Prevout.Outpoint, 
                redemption::redeem(s.Key.Redeemer.redeem(s.Value), input_index{s.Key.Prevout.Output, incomplete, ind++}), 
                s.Key.Sequence};
        }, prev), out, locktime};
    }
    
}
