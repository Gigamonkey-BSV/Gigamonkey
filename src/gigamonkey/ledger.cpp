#include <gigamonkey/ledger.hpp>
#include <gigamonkey/script/machine.hpp>
    
namespace Gigamonkey {
    using namespace Bitcoin;
    
    bool ledger::vertex::valid () const {
        if (!Bitcoin::transaction::valid ()) return false;
        
        for (const struct input &in : this->Inputs) if (!Previous.contains (in.Reference)) return false;
        
        auto edges = incoming_edges ();
        if (!edges.valid ()) return false;
        
        if (this->sent () > spent ()) return false;
        
        uint32 index = 0;
        for (const edge& e: edges) {
            if (!evaluate (e.Input.Script, e.Output.Script,
                redemption_document {e.Output.Value, incomplete::transaction {*this}, index})) return false;
            index++;
        }
        
        return true;
    }
    
}
