#include <gigamonkey/redeem.hpp>
#include <gigamonkey/script/script.hpp>
    
namespace Gigamonkey::Bitcoin {
    
    ledger::vertex redeem(list<spend_order> prev, list<output> out, uint32_little locktime) {
        // first check if we are trying to spend more than we can afford. 
        satoshi spent = fold([](satoshi s, spend_order v) -> satoshi {
            return s + v.first.value();
        }, 0, prev);
        
        satoshi sent = fold([](satoshi s, output o) -> satoshi {
            return s + o.Value;
        }, 0, out);
        
        if (spent < sent) return {};
        
        // generate the incomplete transaction for signatures. 
        incomplete::transaction incomplete{
            Bitcoin::transaction::LatestVersion, 
            data::for_each([](spend_order s) -> incomplete::input {
                return incomplete::input{s.first.reference(), s.second.Sequence};
            }, prev), out, locktime};
        
        uint32 ind{0};
        list<input> inputs;
        data::map<outpoint, Bitcoin::output> prevouts;
        
        for (const spend_order& s : prev) {
            input new_input = s.first(incomplete, ind, s.second.Directive);
            new_input.Sequence = s.second.Sequence;
            if (!new_input.valid()) return {};
            inputs = inputs << new_input;
            prevouts = prevouts.insert(s.first.Previous.Key, s.first.Previous.Value);
            ind++;
        }
        
        return {ledger::double_entry{std::make_shared<bytes>(transaction{inputs, out, locktime}.write()), {}, {}}, prevouts};
        
    }
    
    bool ledger::vertex::valid() const {
        if (!double_entry::valid()) return false;
        
        for (const struct input &in : inputs()) if (!Previous.contains(in.Reference)) return false;
        
        auto edges = incoming_edges();
        if (!edges.valid()) return false; 
        
        if (sent() > spent()) return false;
        
        uint32 index = 0;
        for (const edge& e: edges) {
            if (!interpreter::evaluate(e.Input.Script, 
                signature::document{e.Output, incomplete::transaction::read(ptr<bytes>::operator*()), index})) return false;
            index++;
        }
        
        return true;
    }
    
    uint32 ledger::vertex::sigops() const {
        throw method::unimplemented{"vertex::sigops"};
    }
    
}
