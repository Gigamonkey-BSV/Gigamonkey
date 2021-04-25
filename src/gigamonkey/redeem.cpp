#include <gigamonkey/redeem.hpp>
#include <gigamonkey/script/script.hpp>

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
    
    ledger::vertex redeem(list<data::entry<spendable, sighash::directive>> prev, list<output> out, uint32_little locktime) {
        
        satoshi spent = fold([](satoshi s, data::entry<spendable, sighash::directive> v) -> satoshi {
            return s + v.Key.value();
        }, 0, prev);
        
        satoshi sent = fold([](satoshi s, output o) -> satoshi {
            return s + o.Value;
        }, 0, out);
        
        if (spent > sent) return {};
        
        bytes incomplete = transaction{data::for_each([](data::entry<spendable, sighash::directive> s) -> input {
            return input{s.Key.reference(), {}, s.Key.Sequence};
        }, prev), out, locktime}.write();
        
        uint32 ind{0};
        list<input> in;
        data::map<outpoint, Bitcoin::output> prevouts;
        
        for (const data::entry<spendable, sighash::directive> order : prev) {
            in = in << input{order.Key.reference(), 
                redemption::redeem(order.Key.Redeemer->redeem(order.Value), incomplete, ind++), 
                order.Key.Sequence};
            prevouts = prevouts.insert(static_cast<ledger::prevout>(order.Key));
        }
        
        return {ledger::double_entry{std::make_shared<bytes>(transaction{in, out, locktime}.write()), {}, {}}, prevouts};
    }
    
    bool ledger::vertex::valid() const {
        if (!double_entry::valid() || incoming_edges().valid()) return false; 
        
        if (spent() > sent()) return false;
        
        uint32 index = 0;
        for (const edge& e: incoming_edges()) {
            if (!evaluate_script(e.Input.Script, e.Output.Script, ptr<bytes>::operator*(), index)) return false;
            index++;
        }
        return true;
    }
    
    uint32 ledger::vertex::sigops() const {
        throw method::unimplemented{"vertex::sigops"};
    }
    
}
