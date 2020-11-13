// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_SUBMIT
#define GIGAMONKEY_STRATUM_MINING_SUBMIT

#include <gigamonkey/stratum/boolean_response.hpp>
#include <gigamonkey/stratum/session_id.hpp>

namespace Gigamonkey::Stratum::mining {
    
    // A Stratum share; also a representation of the 'submit' method.
    struct submit_request;
    
    using submit_response = boolean_response;
    
    bool operator==(const submit_request&, const submit_request&);
    bool operator!=(const submit_request&, const submit_request&);
    
    void to_json(json& j, const submit_request& p); 
    void from_json(const json& j, submit_request& p); 
    
    std::ostream& operator<<(std::ostream&, const submit_request&);
    
}

namespace Gigamonkey::Stratum {
    
    // A Stratum share; also a representation of the 'submit' method.
    struct share {
        worker_name Name;
        job_id JobID;
        work::solution Solution; 
        
        share();
        share(worker_name name, job_id jid, const work::solution& x);
        share(worker_name name, job_id jid, uint64_little en2, Bitcoin::timestamp t, nonce n);
        
        bool valid() const;
    };
    
    bool operator==(const share& a, const share& b);
    bool operator!=(const share& a, const share& b);
    
}

namespace Gigamonkey::Stratum::mining {
    
    // A Stratum share; also a representation of the 'submit' method.
    struct submit_request {
        request_id ID;
        share Share;
        
        submit_request();
        submit_request(request_id id, const share& x);
        
        bool valid() const;
        
        explicit operator request() const;
        explicit submit_request(const request&);
    };
    
}

namespace Gigamonkey::Stratum {
    
    inline bool operator==(const share& a, const share& b) {
        return a.Name == b.Name && 
            a.JobID == b.JobID && a.Solution == b.Solution;
    }
    
    inline bool operator!=(const share& a, const share& b) {
        return !(a == b);
    }
    
    inline share::share() : Name{}, JobID{}, Solution{} {}
    
    inline share::share(worker_name name, job_id jid, const work::solution& x) : 
        Name{name}, JobID{jid}, Solution{x} {}
    
    inline share::share(worker_name name, job_id jid, uint64_little en2, Bitcoin::timestamp t, nonce n) : 
        Name{name}, JobID{jid}, Solution{t, n, en2} {}
    
    inline bool share::valid() const {
        return Name != std::string{};
    }
    
}

namespace Gigamonkey::Stratum::mining {
    
    inline bool operator==(const submit_request& a, const submit_request& b) {
        return a.ID == b.ID && a.Share == b.Share;
    }
    
    inline bool operator!=(const submit_request& a, const submit_request& b) {
        return !(a == b);
    }
    
    inline std::ostream& operator<<(std::ostream& o, const submit_request& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
    
    inline submit_request::submit_request() : ID{}, Share{} {}
    
    inline submit_request::submit_request(request_id id, const share& x) : ID{id}, Share{x} {}
    
    inline bool submit_request::valid() const {
        return Share.valid();
    }
    
}

#endif
