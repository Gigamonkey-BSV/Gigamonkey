
#include <gigamonkey/pay/extended.hpp>
#include <gigamonkey/script/interpreter.hpp>

namespace Gigamonkey::extended {

    uint64 transaction::serialized_size () const {
        return 14u + Bitcoin::var_int::size (Inputs.size ()) + Bitcoin::var_int::size (Outputs.size ()) +
            data::fold ([] (uint64 size, const input &i) -> uint64 {
                return size + i.serialized_size ();
            }, 0u, Inputs) +
            data::fold ([] (uint64 size, const Bitcoin::output &i) -> uint64 {
                return size + i.serialized_size ();
            }, 0u, Outputs);
    }

    input::operator bytes () const {
        bytes b (serialized_size ());
        bytes_writer w {b.begin (), b.end ()};
        w << *this;
        return b;
    }

    transaction::operator bytes () const {
        bytes b (serialized_size ());
        bytes_writer w {b.begin (), b.end ()};
        w << *this;
        return b;
    }

    bool transaction::valid (uint32 flags) const {
        if (!(Inputs.size () > 0 && Outputs.size () > 0 && data::valid (Inputs) && data::valid (Outputs) && sent () <= spent ())) return false;

        Bitcoin::incomplete::transaction tx (Bitcoin::transaction (*this));

        uint32 index = 0;
        for (const input &in : Inputs) {
            if (!in.evaluate (tx, index, flags)) return false;
            index ++;
        }

        return true;
    }
}
