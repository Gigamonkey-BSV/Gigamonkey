// Copyright (c) 2020-21 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/job.hpp>

namespace Gigamonkey::Stratum::mining {
    
    namespace {
        
        bool read_job_id (const JSON &j, job_id &x) {
            if (!j.is_string ()) return false;
            x = string (j);
            return true;
        }
        
        encoding::hex::fixed<32> inline write (const uint256 &x) {
            uint256 z = x;
            for (int i = 0; i < 32; i+=4) std::reverse (z.begin () + i, z.begin () + i + 3);
            return encoding::hex::write (z, data::hex_case::lower);
        }
        
        bool read (const JSON &j, uint256 &x) {
            if (!j.is_string ()) return false;
            string str (j);
            if (str.size () != 64) return false;
            maybe<bytes> b = encoding::hex::read (str);
            if (!bool (b)) return false;
            for (int i = 0; i < 8; i++) for (int j = 0; j < 4; j++) x[4 * i + j] = *(b->begin () + 4 * (i + 1) - j - 1);
            return true;
        }
        
        encoding::hex::string inline write (const bytes &b) {
            return encoding::hex::write (b, data::hex_case::lower);
        }
        
        bool read (const JSON &j, bytes &x) {
            if (!j.is_string ()) return false;
            string str (j);
            maybe<bytes> b = encoding::hex::read (str);
            if (!bool (b)) return false;
            x = *b;
            return true;
        }
        
        parameters write (const Merkle::digests &x) {
            parameters p;
            Merkle::digests n;
            p.resize (x.size ());
            for (auto it = p.rbegin (); it != p.rend (); ++it) {
                *it = write (*first (n));
                n = rest (n);
            }
            return p;
        }
        
        bool inline read (const JSON &j, Merkle::digests &x) {
            if (!j.is_array ()) return false;
            x = {};
            for (JSON d : j) {
                uint256 o;
                if (!read (d, o)) return false;
                x >>= digest256 {o};
            }
            return true;
        }
        
        encoding::hex::fixed<4> inline write (const int32_little &x) {
            return encoding::hex::write (x, data::hex_case::lower);
        }
        
        bool read (const JSON &j, int32_little &x) {
            if (!j.is_string ()) return false;
            string str (j);
            if (str.size () != 8) return false;
            maybe<bytes> b = encoding::hex::read (str);
            if (!bool (b)) return false;
            int32_big n;
            std::copy (b->begin (), b->end (), n.begin ());
            x = int32_little (n);
            return true;
        }
        
        encoding::hex::fixed<4> inline write (const work::compact &x) {
            return encoding::hex::write (uint32_big {static_cast<uint32_little> (x)}, data::hex_case::lower);
        }
        
        bool read (const JSON &j, work::compact &x) {
            if (!j.is_string ()) return false;
            string str (j);
            if (str.size () != 8) return false;
            maybe<bytes> b = encoding::hex::read (str);
            if (!bool (b)) return false;
            uint32_big n;
            std::copy (b->begin (), b->end (), n.begin ());
            x = work::compact (uint32_little (n));
            return true;
        }
        
        encoding::hex::fixed<4> inline write (const Bitcoin::timestamp &x) {
            return encoding::hex::write (uint32_big {x.Value}, data::hex_case::lower);
        }
        
        bool read (const JSON &j, Bitcoin::timestamp &x) {
            if (!j.is_string ()) return false;
            string str (j);
            if (str.size () != 8) return false;
            maybe<bytes> b = encoding::hex::read (str);
            if (!bool (b)) return false;
            uint32_big n;
            std::copy (b->begin (), b->end (), n.begin ());
            x = Bitcoin::timestamp (uint32_little (n));
            return true;
        }

        encoding::hex::fixed<8> inline write (const uint64_big &x) {
            return encoding::hex::write (x, data::hex_case::lower);
        }
        
        bool inline read (const JSON &j, uint64_big &x) {
            if (!j.is_string ()) return false;
            string str (j);
            if (str.size () != 16) return false;
            maybe<bytes> b = encoding::hex::read (str);
            std::copy (b->begin (), b->end (), x.begin ());
            return true;
        }
        
        encoding::hex::fixed<4> inline write (const Bitcoin::nonce &x) {
            return encoding::hex::write (uint32_big {x}, data::hex_case::lower);
        }
        
        bool read (const JSON &j, Bitcoin::nonce &x) {
            if (!j.is_string ()) return false;
            string str (j);
            if (str.size () != 8) return false;
            maybe<bytes> b = encoding::hex::read (str);
            uint32_big n;
            std::copy (b->begin (), b->end (), n.begin ());
            x = uint32_little (n);
            return true;
        }
        
    }
    
    parameters notify::serialize (const parameters &p) {
        return Stratum::parameters {p.JobID, write (p.Digest), write (p.GenerationTx1), write (p.GenerationTx2),
            write (p.Path), write (p.Version), write (p.Target), write (p.Now), p.Clean};
    }
    
    notify::parameters notify::deserialize (const Stratum::parameters &n) {
        
        parameters p;
        
        if (n.size() != 9 || !n[8].is_boolean () ||
            !read_job_id (n[0], p.JobID) ||
            !read (n[1], p.Digest) ||
            !read (n[2], p.GenerationTx1) ||
            !read (n[3], p.GenerationTx2) ||
            !read (n[4], p.Path) ||
            !read (n[5], p.Version) ||
            !read (n[6], p.Target) ||
            !read (n[7], p.Now)) return {};
        
        p.Clean = bool (n[8]);
        
        return p;
    }
        
    parameters submit_request::serialize (const share &Share) {
        if (Share.Share.Bits) return parameters {Share.Name, Share.JobID, write (Share.Share.ExtraNonce2),
            write (Share.Share.Timestamp), write (Share.Share.Nonce), write (*Share.Share.Bits)};
        
        return parameters {Share.Name, Share.JobID, write (Share.Share.ExtraNonce2),
            write (Share.Share.Timestamp), write (Share.Share.Nonce)};
    }
    
    share submit_request::deserialize (const parameters &n) {
        share Share {};
        
        if (!(n.size () == 5 || n.size () == 6) || !n[0].is_string () ||
            !read_job_id (n[1], Share.JobID) ||
            !read (n[2], Share.Share.ExtraNonce2) ||
            !read (n[3], Share.Share.Timestamp) ||
            !read (n[4], Share.Share.Nonce)) return {};
        
        if (n.size () == 6) {
            Share.Share.Bits = 0;
            if (!read (n[5], *Share.Share.Bits)) return {};
        }
        
        Share.Name = string (n[0]);
        
        return Share;
    }
    
}
