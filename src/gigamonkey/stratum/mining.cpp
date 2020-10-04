// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/job.hpp>

namespace Gigamonkey::Stratum::mining {
    
    namespace {
        
        inline encoding::hex::fixed<4> write_job_id(const job_id& x) {
            return encoding::hex::write(uint32_big{x}, encoding::hex::lower);
        }
        
        bool read_job_id(const json& j, job_id& x) {
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
        
        parameters write(const Merkle::digests& x) {
            parameters p;
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
        
        inline encoding::hex::fixed<8> write(const uint64_big& x) {
            return encoding::hex::write(x, encoding::hex::lower);
        }
        
        inline bool read(const json& j, uint64_big& x) {
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
        
    }
    
    parameters notify::serialize(const parameters& p) {
        return Stratum::parameters{write_job_id(p.ID), write(p.Digest), write(p.GenerationTx1), write(p.GenerationTx2), 
                write(p.Path), write(p.Version), write(p.Target), write(p.Now), p.Clean};
    }
    
    notify::parameters notify::deserialize(const Stratum::parameters& n) {
        parameters p;
        
        if (n.size() != 9 || !n[8].is_boolean() ||
            !read_job_id(n[0], p.ID) || 
            !read(n[1], p.Digest) || 
            !read(n[2], p.GenerationTx1) || 
            !read(n[3], p.GenerationTx2) || 
            !read(n[4], p.Path) || 
            !read(n[5], p.Version) || 
            !read(n[6], p.Target) || 
            !read(n[7], p.Now)) return {};
        
        p.Clean = bool(n[8]);
        
        return p;
    }
        
    parameters submit_request::serialize(const share& Share) {
        return parameters{Share.Name, write_job_id(Share.JobID), write(Share.Solution.ExtraNonce2), 
                write(Share.Solution.Timestamp), write(Share.Solution.Nonce)};
    }
    
    share submit_request::deserialize(const parameters& n) {
        share Share{};
        
        if (n.size() != 5 || !n[0].is_string() ||
            !read_job_id(n[1], Share.JobID) || 
            !read(n[2], Share.Solution.ExtraNonce2) || 
            !read(n[3], Share.Solution.Timestamp) || 
            !read(n[4], Share.Solution.Nonce)) return {};
        
        Share.Name = string(n[0]);
        
        return Share;
    }
    
}
