// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>
#include <gigamonkey/script/script.hpp>
#include <gigamonkey/work/ASICBoost.hpp>

namespace Gigamonkey {
    bool header_valid_work(slice<80> h) {
        return work::string::valid(h);
    }
    
    bool header_valid(const Bitcoin::header& h) {
        return h.Version >= 1 && h.MerkleRoot.valid() && h.Timestamp != Bitcoin::timestamp{};
    }
}

namespace Gigamonkey::Bitcoin {
    
    int32_little header::version(const slice<80> x) {
        int32_little version;
        slice<4> v = x.range<0, 4>();
        std::copy(v.begin(), v.end(), version.data());
        return version;
    }
    
    Bitcoin::timestamp header::timestamp(const slice<80> x) {
        Bitcoin::timestamp time;
        slice<4> v = x.range<68, 72>();
        std::copy(v.begin(), v.end(), time.data());
        return time;
    }
    
    work::compact header::target(const slice<80> x) {
        work::compact work;
        slice<4> v = x.range<72, 76>();
        std::copy(v.begin(), v.end(), work.data());
        return work;
    }
    
    uint32_little header::nonce(const slice<80> x) {
        uint32_little n;
        slice<4> v = x.range<76, 80>();
        std::copy(v.begin(), v.end(), n.data());
        return n;
    }
    
    bool header::valid(const slice<80> h) {
        return header_valid(Bitcoin::header{h}) && header_valid_work(h);
    }
    
    Gigamonkey::uint256 satoshi_uint256_to_uint256(::uint256 x) {
        Gigamonkey::uint256 y;
        std::copy(x.begin(), x.end(), y.begin());
        return y;
    }
    
    header::header(const CBlockHeader& b) : 
        Version{int32_little{b.nVersion}}, 
        Previous{satoshi_uint256_to_uint256(b.hashPrevBlock)}, 
        MerkleRoot{satoshi_uint256_to_uint256(b.hashMerkleRoot)}, 
        Timestamp{uint32_little{b.nTime}}, 
        Target{uint32_little{b.nBits}}, 
        Nonce{b.nNonce} {};
        
    header::operator CBlockHeader() const {
        CBlockHeader h;
        h.nVersion = Version;
        h.nTime = Timestamp.Value;
        h.nBits = Target;
        h.nNonce = Nonce;
        std::copy(Previous.Value.begin(), Previous.Value.end(), h.hashPrevBlock.begin());
        std::copy(MerkleRoot.Value.begin(), MerkleRoot.Value.end(), h.hashMerkleRoot.begin());
        return h;
    }
        
    bool header::valid() const {
        return header_valid_work(write()) && header_valid(*this);
    }
    
    bool input::valid() const {
        return interpreter::decompile(Script) != interpreter::program{};
    }
    
    bool output::valid() const {
        return Value < 2100000000000000 && interpreter::decompile(Script) != interpreter::program{};
    }
    
    size_t transaction::serialized_size() const {
        return 8 + var_int_size(Inputs.size()) + var_int_size(Inputs.size()) + 
            data::fold([](size_t size, const Bitcoin::input& i) -> size_t {
                return size + i.serialized_size();
            }, 0, Inputs) + 
            data::fold([](size_t size, const Bitcoin::output& i) -> size_t {
                return size + i.serialized_size();
            }, 0, Outputs);
    }
    
    size_t block::serialized_size() const {
        return 80 + var_int_size(Transactions.size()) + 
        data::fold([](size_t size, transaction x)->size_t{
            return size + x.serialized_size();
        }, 0, Transactions);
    }
    
    inline size_t input::serialized_size() const {
        return 40 + var_int_size(Script.size()) + Script.size();
    }
    
    inline size_t output::serialized_size() const {
        return 8 + var_int_size(Script.size()) + Script.size();
    }
    
    transaction::transaction(bytes_view b) : transaction{} {
        try {
            reader r{b.begin(), b.end()};
            read(r, *this);
        } catch (data::end_of_stream n) {
            *this = transaction{};
        }
    }
        
    block::block(bytes_view b) : block{} {
        try {
            reader r{b.begin(), b.end()};
            read(r, *this);
        } catch (data::end_of_stream n) {
            *this = block{};
        } catch (std::bad_alloc n) {
            *this = block{};
        }
    }
    
    transaction::operator bytes() const {
        bytes b(serialized_size());
        writer w{b.begin(), b.end()};
        w << *this;
        return b;
    }
    
    std::vector<bytes_view> block::transactions(bytes_view b) {
        bytes_reader r(b.data(), b.data() + b.size());
        Bitcoin::header h;
        r >> h;
        uint64 num_txs = read_var_int(r);
        std::vector<bytes_view> x;
        x.resize(num_txs);
        auto prev = r.Reader.Begin;
        for (int i = 0; i < num_txs; i++) {
            transaction tx;
            r >> tx;
            auto next = r.Reader.Begin;
            x[i] = bytes_view{prev, static_cast<size_t>(next - prev)};
            prev = next;
        }
        return x;
    }
    
    template <typename reader>
    bool read_transaction_version(reader &r, int32_little& v) {
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
    bool transaction_outputs(reader &r) {
        int32_little v;
        if (!read_transaction_version(r, v)) return false;
        return true;
    }
    
    void scan_output(reader &r, bytes_view& o) {
        satoshi value;
        const byte* begin = r.Reader.Begin;
        r >> value;
        uint64 script_size = read_var_int(r);
        r.skip(script_size);
        o = bytes_view{begin, script_size + 8 + var_int_size(script_size)};
    }
    
    bytes_view transaction::output(bytes_view b, index i) {
        reader r{b.begin(), b.end()};
        try {
            if (!transaction_outputs(r)) return {};
            uint64 num_outputs = read_var_int(r);
            if (num_outputs == 0 || num_outputs <= i) return {};
            bytes_view output;
            do {
                scan_output(r, output);
                if (output.size() == 0) return {};
                if (i == 0) return output;
                i--;
            } while(true);
        } catch (data::end_of_stream) {
            return {};
        }
    }
    
    output::output(bytes_view b) {
        reader r{b.begin(), b.end()};
        try {
            r >> Value;
            read_bytes(r, Script);
        } catch (data::end_of_stream) {
            Value = -1;
            Script = {};
        }
    }
    
    satoshi output::value(bytes_view z) {
        reader r{z.begin(), z.end()};
        satoshi Value;
        try {
            r >> Value;
        } catch (data::end_of_stream) {
            Value = -1;
        }
        return Value;
    }
    
    bytes_view output::script(bytes_view z) {
        reader r{z.begin(), z.end()};
        satoshi Value;
        try {
            r >> Value;
            uint64 script_size = read_var_int(r);
            return bytes_view{r.Reader.Begin, script_size};
        } catch (data::end_of_stream) {
            return {};
        }
    }
    
    uint<80> header::write() const {
        uint<80> x; // inefficient: unnecessary copy. 
        bytes b(80);
        writer{b.begin(), b.end()} << Version << Previous << MerkleRoot << Timestamp << Target << Nonce;
        std::copy(b.begin(), b.end(), x.data());
        return x;
    }
    
    bool transaction::valid() const {
        if (Inputs.size() == 0 || Outputs.size() == 0) return false;
        for (const Bitcoin::input& i : Inputs) if (!i.valid()) return false; 
        for (const Bitcoin::output& o : Outputs) if (!o.valid()) return false; 
        return true;
    }
    
}

