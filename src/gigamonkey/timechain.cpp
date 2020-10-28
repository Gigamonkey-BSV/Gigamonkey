// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>
#include <gigamonkey/script/script.hpp>

namespace Gigamonkey {
    bool header_valid_work(slice<80> h) {
        return work::string::valid(h);
    }
    
    bool header_valid(const Bitcoin::header& h) {
        return h.Version >= 1 && h.MerkleRoot.valid() && h.Timestamp != Bitcoin::timestamp{};
    }
}

namespace Gigamonkey::Bitcoin {
    
    bytes_writer writer::write_var_int(bytes_writer r, uint64 x) {
        if (x <= 0xfc) return r << static_cast<byte>(x);
        else if (x <= 0xffff) return r << byte(0xfd) << uint16_little{static_cast<uint16>(x)};
        else if (x <= 0xffffffff) return r << byte(0xfe) << uint32_little{static_cast<uint32>(x)};
        else return r << byte(0xff) << uint64_little{x};
    }
    
    bytes_reader reader::read_var_int(bytes_reader r, uint64& x) {
        byte b;
        r = r >> b;
        if (b <= 0xfc) {
            x = b;
        } else if (b == 0xfd) {
            uint16_little n;
            r = r >> n;
            x = uint16(n);
        } else if (b == 0xfe) {
            uint32_little n;
            r = r >> n;
            x = uint32(n);
        } else {
            uint64_little n;
            r = r >> n;
            x = uint64(n);
        } 
        return r;
    }
    
    size_t writer::var_int_size(uint64 x) {
        if (x <= 0xfc) return 1;
        if (x <= 0xffff) return 3;
        if (x <= 0xffffffff) return 5;
        return 9;
    }
    
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
        return header_valid(Bitcoin::header::read(h)) && header_valid_work(h);
    }
    
    Gigamonkey::uint256 satoshi_uint256_to_uint256(sv::uint256 x) {
        Gigamonkey::uint256 y;
        std::copy(x.begin(), x.end(), y.begin());
        return y;
    }
    
    header::header(const sv::CBlockHeader& b) : 
        Version{int32_little{b.nVersion}}, 
        Previous{satoshi_uint256_to_uint256(b.hashPrevBlock)}, 
        MerkleRoot{satoshi_uint256_to_uint256(b.hashMerkleRoot)}, 
        Timestamp{uint32_little{b.nTime}}, 
        Target{uint32_little{b.nBits}}, 
        Nonce{b.nNonce} {};
        
    header::operator sv::CBlockHeader() const {
        sv::CBlockHeader h;
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
        return decompile(Script) != program{};
    }
    
    bool output::valid() const {
        return Value < 2100000000000000 && decompile(Script) != program{};
    }
    
    size_t transaction::serialized_size() const {
        return 8 + writer::var_int_size(Inputs.size()) + writer::var_int_size(Inputs.size()) + 
            data::fold([](size_t size, const Bitcoin::input& i)->size_t{
                return size + i.serialized_size();
            }, 0, Inputs) + 
            data::fold([](size_t size, const Bitcoin::output& i)->size_t{
                return size + i.serialized_size();
            }, 0, Outputs);
    }
    
    size_t block::serialized_size() const {
        return 80 + writer::var_int_size(Transactions.size()) + 
        data::fold([](size_t size, transaction x)->size_t{
            return size + x.serialized_size();
        }, 0, Transactions);
    }
    
    inline size_t input::serialized_size() const {
        return 40 + writer::var_int_size(Script.size()) + Script.size();
    }
    
    inline size_t output::serialized_size() const {
        return 8 + writer::var_int_size(Script.size()) + Script.size();
    }
    
    transaction transaction::read(bytes_view b) {
        transaction t;
        bytes_reader(b.data(), b.data() + b.size()) >> t;
        return t;
    }
    
    bytes transaction::write() const {
        bytes b(serialized_size());
        writer w{b};
        w = w << *this;
        return b;
    }
    
    std::vector<bytes_view> block::transactions(bytes_view b) {
        bytes_reader r(b.data(), b.data() + b.size());
        Bitcoin::header h;
        r = (reader{r} >> h).Reader;
        uint64 num_txs;
        r = reader::read_var_int(r, num_txs);
        std::vector<bytes_view> x;
        x.resize(num_txs);
        auto prev = r.Reader.Begin;
        for (int i = 0; i < num_txs; i++) {
            transaction tx;
            r = (reader{r} >> tx).Reader;
            auto next = r.Reader.Begin;
            x[i] = bytes_view{prev, static_cast<size_t>(next - prev)};
            prev = next;
        }
        return x;
    }
    
}

