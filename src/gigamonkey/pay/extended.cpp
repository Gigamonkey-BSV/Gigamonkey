
#include <gigamonkey/pay/extended.hpp>

namespace Gigamonkey::extended {

    uint64 transaction::serialized_size () const {
        return 14u + Bitcoin::var_int::size (Inputs.size ()) + Bitcoin::var_int::size (Outputs.size ()) +
            data::fold ([] (uint64 size, const Bitcoin::input &i) -> uint64 {
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
}
