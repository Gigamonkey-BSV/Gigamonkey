// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/job.hpp>

namespace Gigamonkey::Stratum::mining {

    void from_json(const json& j, notify& p) {
        p = {};
        notification x;
        from_json(j, x);
        p = notify(x);
    }
    
    void to_json(json& j, const notify& p) {
        j = {};
        if (!data::valid(p)) return; 
        to_json(j, notification(p));
    }
    
    void from_json(const json& j, submit_request& p) {
        p = {};
        request x;
        from_json(j, x);
        p = submit_request(x);
    }
    
    void to_json(json& j, const submit_request& p) {
        j = {};
        if (!p.valid()) return; 
        to_json(j, request(p));
    }
    
    inline encoding::hex::fixed<4> write(job_id x) {
        return encoding::hex::write(uint32_big{x}, encoding::hex::lower);
    }
    
    bool read(const json& j, job_id& x) {
        if (!j.is_string()) return false;
        string str(j);
        if (str.size() != 8) return false;
        encoding::hex::view hex{str};
        if (!hex.valid()) return false;
        bytes_view b = bytes_view(hex);
        uint32_big n;
        std::copy(b.begin(), b.end(), n.begin());
        x = uint32(n);
        return true;
    }
    
    inline encoding::hex::fixed<32> write(const uint256& x) {
        return encoding::hex::write(x, encoding::hex::lower);
    }
    
    bool read(const json& j, uint256& x) {
        if (!j.is_string()) return false;
        string str(j);
        if (str.size() != 64) return false;
        encoding::hex::view hex{str};
        if (!hex.valid()) return false;
        bytes_view b = bytes_view(hex);
        std::copy(b.begin(), b.end(), x.begin());
        return true;
    }
    
    inline encoding::hex::string write(const bytes& b) {
        return encoding::hex::write(b, encoding::hex::lower);
    }
    
    bool read(const json& j, bytes& x) {
        if (!j.is_string()) return false;
        string str(j);
        encoding::hex::view hex{str};
        if (!hex.valid()) return false;
        x = bytes_view(hex);
        return true;
    }
    
    params write(const Merkle::digests& x) {
        params p;
        Merkle::digests n;
        p.resize(x.size());
        for (auto it = p.rbegin(); it != p.rend(); ++it) { 
            *it = write(n.first().Value);
            n = n.rest();
        }
        return p;
    }
    
    inline bool read(const json& j, Merkle::digests& x) {
        if (!j.is_array()) return false;
        x = {};
        for (json d : j) {
            uint256 o;
            if (!read(d, o)) return false;
            x = x << digest256{o};
        }
        return true;
    }
    
    inline encoding::hex::fixed<4> write(const int32_little& x) {
        return encoding::hex::write(bytes_view(x), endian::little, encoding::hex::lower);
    }
    
    bool read(const json& j, int32_little& x) {
        if (!j.is_string()) return false;
        string str(j);
        if (str.size() != 8) return false;
        encoding::hex::view hex{str};
        if (!hex.valid()) return false;
        bytes_view b = bytes_view(hex);
        int32_big n;
        std::copy(b.begin(), b.end(), n.begin());
        x = int32_little(n);
        return true;
    }
    
    inline encoding::hex::fixed<4> write(const work::compact& x) {
        return encoding::hex::write(uint32_big{static_cast<uint32_little>(x)}, encoding::hex::lower);
    }
    
    bool read(const json& j, work::compact& x) {
        if (!j.is_string()) return false;
        string str(j);
        if (str.size() != 8) return false;
        encoding::hex::view hex{str};
        if (!hex.valid()) return false;
        bytes_view b = bytes_view(hex);
        uint32_big n;
        std::copy(b.begin(), b.end(), n.begin());
        x = work::compact(uint32_little(n));
        return true;
    }
    
    inline encoding::hex::fixed<4> write(const Bitcoin::timestamp& x) {
        return encoding::hex::write(uint32_big{x.Value}, encoding::hex::lower);
    }
    
    bool read(const json& j, Bitcoin::timestamp& x) {
        if (!j.is_string()) return false;
        string str(j);
        if (str.size() != 8) return false;
        encoding::hex::view hex{str};
        if (!hex.valid()) return false;
        bytes_view b = bytes_view(hex);
        uint32_big n;
        std::copy(b.begin(), b.end(), n.begin());
        x = Bitcoin::timestamp(uint32_little(n));
        return true;
    }
    
    inline encoding::hex::fixed<8> write(const uint64_little& x) {
        return encoding::hex::write(x, encoding::hex::lower);
    }
    
    inline bool read(const json& j, uint64_little& x) {
        if (!j.is_string()) return false;
        string str(j);
        if (str.size() != 16) return false;
        encoding::hex::view hex{str};
        bytes_view b = bytes_view(hex);
        std::copy(b.begin(), b.end(), x.begin());
        return true;
    }
    
    inline encoding::hex::fixed<4> write(const nonce& x) {
        return encoding::hex::write(uint32_big{x}, encoding::hex::lower);
    }
    
    bool read(const json& j, nonce& x) {
        if (!j.is_string()) return false;
        string str(j);
        if (str.size() != 8) return false;
        encoding::hex::view hex{str};
        bytes_view b = bytes_view(hex);
        uint32_big n;
        std::copy(b.begin(), b.end(), n.begin());
        x = uint32_little(n);
        return true;
    }
    
    notify::operator notification() const {
        if (!valid()) return {};
        return notification(mining_notify, 
            params{write(ID), write(Digest), write(GenerationTx1), write(GenerationTx2), 
                write(Path), write(Version), write(Target), write(Now), Clean});
    }
    
    notify::notify(const notification& n) : notify{} {
        if (!n.valid() || n.Method != mining_notify || n.Params.size() != 9 || !n.Params[8].is_boolean() ||
            !read(n.Params[0], ID) || 
            !read(n.Params[1], Digest) || 
            !read(n.Params[2], GenerationTx1) || 
            !read(n.Params[3], GenerationTx2) || 
            !read(n.Params[4], Path) || 
            !read(n.Params[5], Version) || 
            !read(n.Params[6], Target) || 
            !read(n.Params[7], Now)) return;
        Clean = bool(n.Params[8]);
    }
    
    submit_request::operator request() const {
        if (!valid()) return {};
        return request(ID, mining_submit, 
            params{Share.Name, write(Share.JobID), write(Share.Solution.ExtraNonce), 
                write(Share.Solution.Timestamp), write(Share.Solution.Nonce)});
    }
    
    submit_request::submit_request(const request& n) : submit_request{} {
        if (!n.valid() || n.Method != mining_submit || n.Params.size() != 5 || !n.Params[0].is_string() ||
            !read(n.Params[1], Share.JobID) || 
            !read(n.Params[2], Share.Solution.ExtraNonce) || 
            !read(n.Params[3], Share.Solution.Timestamp) || 
            !read(n.Params[4], Share.Solution.Nonce)) return;
        ID = n.ID;
        Share.Name = string(n.Params[0]);
    }
}
