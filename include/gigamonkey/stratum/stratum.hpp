#ifndef GIGAMONKEY_STRATUM_STRATUM
#define GIGAMONKEY_STRATUM_STRATUM

#include <nlohmann/json.hpp>

#include <gigamonkey/work/proof.hpp>

namespace Gigamonkey {
    using json = nlohmann::json;
}

namespace Gigamonkey::Stratum {
    using request_id = uint64;
    
    // List of stratum methods (incomplete)
    enum method {
        unset,
        mining_authorize, 
        mining_configure, 
        mining_subscribe, 
        mining_notify, 
        mining_set_target, 
        mining_submit, 
        client_get_version,
        client_reconnect
    };
    
    std::string method_to_string(method m);
    
    method method_from_string(std::string st);
    
    // Stratum error codes (incomplete)
    enum error_code {
        none
    };
    
    std::string error_message_from_code(error_code);
    
    struct request;
    struct response;
    struct notification;
    
    void to_json(json& j, const request& p); 
    void from_json(const json& j, request& p); 
    
    void to_json(json& j, const response& p); 
    void from_json(const json& j, response& p); 
    
    void to_json(json& j, const notification& p); 
    void from_json(const json& j, notification& p); 
    
    struct request {
        
        request_id ID;
        
        method Method;
        
        std::vector<json> Params;
        
        request() : ID{0}, Method{unset}, Params{} {}
        request(request_id id, method m, const std::vector<json>& p) : ID{id}, Method{m}, Params{p} {}
        
        bool valid() const {
            return Method != unset;
        }
        
        bool operator==(const request& r) const {
            return ID == r.ID && Method == r.Method && Params == r.Params;
        }
        
        bool operator!=(const request& r) const {
            return !operator==(r);
        }
        
    };
    
    struct notification {
        
        method Method;
        
        std::vector<json> Params;
        
        notification() : Method{unset}, Params{} {}
        notification(method m, const std::vector<json>& p) : Method{m}, Params{p} {}
        
        bool valid() const {
            return Method != unset;
        }
        
        bool operator==(const notification& r) const {
            return Method == r.Method && Params == r.Params;
        }
        
        bool operator!=(const notification& r) const {
            return !operator==(r);
        }
    };
    
    struct response {
        
        request_id ID;
        
        json Result;
        
        error_code ErrorCode;
        
        std::string ErrorMessage;
        
        response() : ID{0}, Result{}, ErrorCode{none}{}
        response(request_id id, json p) : ID{id}, Result{p}, ErrorCode{none}, ErrorMessage{} {}
        response(request_id id, json p, error_code c) : 
            ID{id}, Result{p}, ErrorCode{c}, ErrorMessage{error_message_from_code(c)} {}
        
        bool operator==(const response& r) const {
            return ID == r.ID && Result == r.Result && ErrorCode == r.ErrorCode;
        }
        
        bool operator!=(const response& r) const {
            return !operator==(r);
        }
        
    private:
        response(request_id id, json p, error_code c, std::string error_message) : 
            ID{id}, Result{p}, ErrorCode{c}, ErrorMessage{error_message} {}
            
        friend void from_json(const json& j, response& p);
    };
    
    using job_id = uint32;
    
    // Representation of a Stratum notify message. 
    struct notify { 
        job_id ID; 
        // would be hash of prev block for Bitcoin, contents for Boost. 
        uint256 Digest; 
        
        // Stratum separates the coinbase into two parts. Between these two parts
        // the nonces contributed from both parties (miner and mining pool) are inserted.
        bytes GenerationTx1;
        bytes GenerationTx2;
        
        // The path is always index zero, so we don't need to store an index. 
        list<digest256> Path;
        
        work::target Target;
        timestamp Now;
        
        bool Clean;
        
        notify() : ID{}, Digest{}, GenerationTx1{}, GenerationTx2{}, Path{}, Target{}, Now{}, Clean{} {}
        notify(job_id id, uint256 d, bytes tx1, bytes tx2, list<digest256> p, work::target t, timestamp n, bool c) : 
            ID{id}, Digest{d}, GenerationTx1{tx1}, GenerationTx2{tx2}, Path{p}, Target{t}, Now{n}, Clean{c} {};
        
        explicit notify(const notification&);
            
        bool valid() const {
            return Now.valid() && Target.valid();
        }
        
        bool operator==(const notify& n) const {
            return ID == n.ID && Digest == n.Digest && 
                GenerationTx1 == n.GenerationTx1 && 
                GenerationTx2 == n.GenerationTx2 && 
                Path == n.Path && Target == n.Target && 
                Now == n.Now && Clean == n.Clean;
        }
        
        bool operator!=(const notify& n) const {
            return !operator==(n);
        }
        
        explicit operator notification() const;
    };
    
    using worker_name = std::string;
    
    // A Stratum share; also a representation of the 'submit' method.
    struct share {
        request_id ID;
        worker_name Name;
        job_id JobID;
        uint64_little ExtraNonce2;
        timestamp nTime;
        nonce nOnce;
        
        share() : ID{}, Name{}, JobID{}, ExtraNonce2{}, nTime{}, nOnce{} {}
        share(request_id id, worker_name name, job_id jid, uint64_little n2, timestamp time, nonce n)
            : ID{id}, Name{name}, JobID{jid}, ExtraNonce2{n2}, nTime{time}, nOnce{n} {}
        
        explicit share(const request& n);
        
        bool valid() const {
            return Name != std::string{};
        }
        
        bool operator==(const share& n) const {
            return ID == n.ID && Name == n.Name && 
                JobID == n.JobID && 
                ExtraNonce2 == n.ExtraNonce2 && 
                nTime == n.nTime && nOnce == n.nOnce;
        }
        
        bool operator!=(const share& n) const {
            return !operator==(n);
        }
        
        explicit operator request() const;
    };
    
    void to_json(json& j, const notify& p); 
    void from_json(const json& j, notify& p); 
    
    void to_json(json& j, const share& p); 
    void from_json(const json& j, share& p); 
    
    struct worker {
        worker_name Name;
        uint32_little ExtraNonce1;
        constexpr static uint32_t ExtraNonce2_size{8};
        
        worker() : Name{}, ExtraNonce1{} {}
        
        // for Boost
        worker(worker_name n, uint32_little n1) : Name{n}, ExtraNonce1{n1} {}
        
        bool operator==(const worker& w) const {
            return Name == w.Name && ExtraNonce1 == w.ExtraNonce1;
        }
        
        bool operator!=(const worker& w) const {
            return !operator==(w);
        }
    };
    
    struct job {  
        
        int32_little Version;
        
        worker Worker;
        
        notify Notify;
        
        job() : Version{}, Worker{}, Notify{} {}
        job(int32_little v, const worker& w, notify n) : 
            Version{v}, Worker{w}, Notify{n} {}
        job(job_id i, const work::puzzle& puzzle, const worker& w, timestamp now, bool clean) : 
            Version{puzzle.Category}, Worker{w}, 
            Notify{i, puzzle.Digest, puzzle.Header, puzzle.Body, puzzle.Path.Hashes, puzzle.Target, now, clean} {}
        
        bool valid() const {
            return Notify.valid();
        }
        
        bool operator==(const job& j) const {
            return Version == j.Version && Worker == j.Worker && Notify == j.Notify;
        }
        
        bool operator!=(const job& j) const {
            return !operator==(j);
        }
        
        work::puzzle puzzle() const {
            if (!valid()) return work::puzzle{};
            return work::puzzle{
                Version, 
                Notify.Digest, 
                Notify.Target, 
                Merkle::path{Notify.Path, 0}, 
                Notify.GenerationTx1, 
                Worker.ExtraNonce1,
                Notify.GenerationTx2};
        }
    };
    
    struct solved {
        job Job;
        share Share;
        
        solved(const job& j, const share&sh) : Job{j}, Share{sh} {}
        
        solved(job_id i, const worker_name& name, const work::proof& p, bool clean) : 
            Job{i, p.Puzzle, worker{name, p.Puzzle.ExtraNonce}, p.Solution.Timestamp, clean}, Share{} {}
        
        work::proof proof() const {
            return work::proof{
                Job.puzzle(), 
                work::solution{
                    Share.nTime, 
                    Share.nOnce, 
                    Share.ExtraNonce2}};
        }
        
        bool valid() const {
            return proof().valid();
        }
    
    };
    
}

#endif 

