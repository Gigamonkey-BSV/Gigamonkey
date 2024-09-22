// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>
#include <gigamonkey/script.hpp>
#include <gigamonkey/work/ASICBoost.hpp>
#include <gigamonkey/script/opcodes.h>

namespace Gigamonkey {
    bool header_valid_work (slice<80> h) {
        return work::string::valid (h);
    }
    
    bool header_valid (const Bitcoin::header &h) {
        return h.Version >= 1 && h.MerkleRoot.valid () && h.Timestamp != Bitcoin::timestamp {};
    }
}

namespace Gigamonkey::Bitcoin {
    
    int32_little header::version (const slice<80> x) {
        int32_little version;
        slice<4> v = x.range<0, 4> ();
        std::copy (v.begin (), v.end (), version.data ());
        return version;
    }
    
    Bitcoin::timestamp header::timestamp (const slice<80> x) {
        Bitcoin::timestamp time;
        slice<4> v = x.range<68, 72> ();
        std::copy (v.begin (), v.end (), time.data ());
        return time;
    }
    
    work::compact header::target (const slice<80> x) {
        work::compact work;
        slice<4> v = x.range<72, 76> ();
        std::copy (v.begin (), v.end (), work.data ());
        return work;
    }
    
    uint32_little header::nonce (const slice<80> x) {
        uint32_little n;
        slice<4> v = x.range<76, 80> ();
        std::copy (v.begin (), v.end (), n.data ());
        return n;
    }
    
    bool header::valid (const slice<80> h) {
        return header_valid (Bitcoin::header {h}) && header_valid_work (h);
    }
        
    bool header::valid () const {
        return header_valid_work (write ()) && header_valid (*this);
    }
    
    bool input::valid () const {
        return decompile (Script) != program {};
    }
    
    bool output::valid () const {
        return Value < 2100000000000000 && decompile (Script) != program {};
    }
    
    uint64 transaction::serialized_size () const {
        return 8 + var_int::size (Inputs.size ()) + var_int::size (Outputs.size ()) +
            data::fold ([] (uint64 size, const Bitcoin::input &i) -> uint64 {
                return size + i.serialized_size ();
            }, 0u, Inputs) + 
            data::fold ([] (uint64 size, const Bitcoin::output &i) -> uint64 {
                return size + i.serialized_size ();
            }, 0u, Outputs);
    }
    
    uint64 block::serialized_size () const {
        return 80 + var_int::size (Transactions.size ()) +
        data::fold ([] (uint64 size, transaction x) -> uint64 {
            return size + x.serialized_size ();
        }, 0u, Transactions);
    }

    input::input (bytes_view b) : input {} {
        try {
            bytes_reader r {b.begin (), b.end ()};
            r >> *this;
        } catch (data::end_of_stream n) {
            *this = input {};
        }
    }
    
    transaction::transaction (bytes_view b) : transaction {} {
        try {
            bytes_reader r {b.begin (), b.end ()};
            r >> *this;
        } catch (data::end_of_stream n) {
            *this = transaction {};
        }
    }
        
    block::block (bytes_view b) : block {} {
        try {
            bytes_reader r {b.begin (), b.end()};
            r >> *this;
        } catch (data::end_of_stream n) {
            *this = block {};
        } catch (std::bad_alloc n) {
            *this = block {};
        }
    }

    input::operator bytes () const {
        bytes b (serialized_size ());
        bytes_writer w {b.begin (), b.end ()};
        w << *this;
        return b;
    }
    
    output::operator bytes () const {
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
    
    std::vector<bytes_view> block::transactions (bytes_view b) {
        bytes_reader r (b.data (), b.data () + b.size ());
        Bitcoin::header h;
        var_int num_txs; 
        r >> h >> num_txs;
        std::vector<bytes_view> x;
        x.resize (num_txs);
        auto prev = r.Begin;
        for (int i = 0; i < num_txs; i++) {
            transaction tx;
            r >> tx;
            auto next = r.Begin;
            x[i] = bytes_view {prev, static_cast<size_t> (next - prev)};
            prev = next;
        }
        return x;
    }
    
    template <typename reader>
    bool read_transaction_version (reader &r, int32_little &v) {
        r >> v;
        if (v == 1) return true;
        if ((v & work::ASICBoost::Mask) == 2) {
            v = 2;
            return true;
        }
        v = -1;
        return false;
    }
    
    template <typename reader>
    bool to_transaction_inputs (reader &r) {
        int32_little v;
        if (!read_transaction_version (r, v)) return false;
        return true;
    }

    void scan_input (bytes_reader &r, bytes_view &i) {
        const byte *begin = r.Begin;
        outpoint o;
        var_int script_size;
        r >> o >> script_size;
        r.skip (script_size + 4);
        i = bytes_view {begin, script_size + 40 + var_int::size (script_size)};
    }

    template <typename reader>
    bool to_transaction_outputs (reader &r) {
        if (!to_transaction_inputs (r)) return false;
        auto inputs = var_int::read (r);
        bytes_view in;
        for (uint64 i; i < inputs; i++) scan_input (r, in);
        return true;
    }
    
    void scan_output (bytes_reader &r, bytes_view &o) {
        satoshi value;
        const byte *begin = r.Begin;
        var_int script_size; 
        r >> value >> script_size;
        r.skip (script_size);
        o = bytes_view {begin, script_size + 8 + var_int::size (script_size)};
    }

    bytes_view transaction::input (bytes_view b, index i) {
        bytes_reader r {b.begin (), b.end ()};
        try {
            if (!to_transaction_inputs (r)) return {};
            var_int num_outputs;
            r >> num_outputs;
            if (num_outputs == 0 || num_outputs <= i) return {};
            bytes_view input;
            do {
                scan_input (r, input);
                if (input.size () == 0) return {};
                if (i == 0) return input;
                i--;
            } while (true);
        } catch (data::end_of_stream) {
            return {};
        }
    }
    
    bytes_view transaction::output (bytes_view b, index i) {
        bytes_reader r {b.begin (), b.end ()};
        try {
            if (!to_transaction_outputs (r)) return {};
            var_int num_outputs;
            r >> num_outputs;
            if (num_outputs == 0 || num_outputs <= i) return {};
            bytes_view output;
            do {
                scan_output (r, output);
                if (output.size () == 0) return {};
                if (i == 0) return output;
                i--;
            } while (true);
        } catch (data::end_of_stream) {
            return {};
        }
    }
    
    output::output (bytes_view b) {
        bytes_reader r {b.begin (), b.end ()};
        try {
            r >> Value >> var_string {Script};
        } catch (data::end_of_stream) {
            Value = -1;
            Script = {};
        }
    }
    
    satoshi output::value (bytes_view z) {
        bytes_reader r {z.begin (), z.end ()};
        satoshi Value;
        try {
            r >> Value;
        } catch (data::end_of_stream) {
            Value = -1;
        }
        return Value;
    }
    
    bytes_view output::script (bytes_view z) {
        bytes_reader r {z.begin (), z.end ()};
        satoshi Value;
        try {
            var_int script_size; 
            r >> Value >> script_size;
            return bytes_view {r.Begin, script_size};
        } catch (data::end_of_stream) {
            return {};
        }
    }
    
    byte_array<80> header::write () const {
        byte_array<80> x; 
        bytes_writer w {x.begin (), x.end ()};
        w << Version << Previous << MerkleRoot << Timestamp << Target << Nonce;
        return x;
    }

    uint64 transaction::sigops () const {
        uint64 sigops {0};
        for (const auto &in : Inputs) for (const byte &op : in.Script)
            if (op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY) sigops++;
            else if (op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY) sigops += 20;
        for (const auto &out : Outputs) for (const byte &op : out.Script)
            if (op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY) sigops++;
            else if (op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY) sigops += 20;
        return 0;
    }

}

