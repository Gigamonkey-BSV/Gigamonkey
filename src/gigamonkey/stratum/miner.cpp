// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/miner.hpp>

namespace Gigamonkey::Stratum {
    
    miner::job miner::make_job(const difficulty &d,
        const mining::set_extranonce::parameters &p,
        const mining::notify::parameters &n,
        const extensions::version_mask *mask) {
        
        job j{n.JobID, work::job{
            work::puzzle{n.Version, n.Digest, n.Target, Merkle::path{0, n.Path}, n.GenerationTx1, n.GenerationTx2}, p.ExtraNonce1}, 
            p.ExtraNonce2Size, uint256(work::difficulty(d)), false};
        
        if (mask != nullptr) {
            j.VersionMaskEnabled = true;
            j.WorkJob.Puzzle.Mask = *mask;
        };
        
        return j;
    }
    
    byte miner::random_byte() {
        static bool first = true;
        static std::default_random_engine gen;
        static std::uniform_int_distribution<byte> u(0, 255);
        
        if (first) {
            std::random_device rd;
            gen.seed(rd());
            first = false;
        } 
        
        return u(gen);
    }
    
    uint32_little miner::random_uint32_little() {
        std::lock_guard<mutex> lock(GenerateRandomNumber);
        uint32_little z;
        for (auto i = z.begin(); i != z.end(); i++) *i = random_byte();
        return z;
    }
    
    bytes miner::random_bytes(size_t size) {
        std::lock_guard<mutex> lock(GenerateRandomNumber);
        bytes b(size);
        for (byte &x : b) x = random_byte();
        return b;
    }
    
    void miner::start() {
        for (int i = 0; i < Threads; i++) Mining[i] = new std::thread{
            [this](string name) {
                ReadNewJobs.lock_shared();
                job Job = *miner::Job;
                ReadNewJobs.unlock_shared();
                
                nonce n = random_uint32_little();
                bytes n2 = random_bytes(Job.ExtraNonce2Size);
                
                work::share Share{Bitcoin::timestamp::now(), n, n2};
                if (Job.VersionMaskEnabled) Share.Bits = 0xffffffff;
                
                while (true) {
                    if (work::proof{Job.WorkJob, Share}.string().hash() < Job.Target) 
                        this->submit(share{name, Job.ID, Share});
                    
                    n++;
                    
                    if ((n & 0x000fffff) == 0 && ReadNewJobs.try_lock_shared()) {
                        if (miner::Job == nullptr) return;
                        Job = *miner::Job;
                        ReadNewJobs.unlock_shared();
                        Share.Timestamp = Bitcoin::timestamp::now();
                        if (n2.size() != Job.ExtraNonce2Size) n2 = random_bytes(Job.ExtraNonce2Size);
                    }
                    
                    if (n == 0) for (byte &b : n2) if (++b) break;
                }
            }, string{"Gigamonkey"} + std::to_string(i + 1)};
        
        WhenMiningStarts.set_value();
    }
    
    void miner::make_puzzle() {
        if (!ready_to_mine() && !Finished) return;
        if (Job != nullptr) *Job = make_job(*Difficulty, *ExtraNonce, *Notify, VersionMask);
        else {
            Job = new job{make_job(*Difficulty, *ExtraNonce, *Notify, VersionMask)};
            start();
        }
    }
    
    void miner::notify(const mining::notify::parameters &n) {
        std::cout << "notification received: " << n << std::endl;
        std::lock_guard<std::shared_mutex> lock(ReadNewJobs);
        if (Notify == nullptr) Notify = new mining::notify::parameters{n};
        else *Notify = n;
        make_puzzle();
    }
    
    void miner::set_difficulty(const difficulty &d) {
        std::cout << "difficulty received: " << d << std::endl;
        std::lock_guard<std::shared_mutex> lock(ReadNewJobs);
        if (Difficulty == nullptr) Difficulty = new difficulty{d};
        else *Difficulty = d;
        make_puzzle();
    }
    
    void miner::set_extranonce(const mining::set_extranonce::parameters &p) {
        std::cout << "extra nonce received: " << p << std::endl;
        std::lock_guard<std::shared_mutex> lock(ReadNewJobs);
        if (ExtraNonce == nullptr) ExtraNonce = new mining::set_extranonce::parameters{p};
        else *ExtraNonce = p;
        make_puzzle();
    }
    
    void miner::set_version_mask(const extensions::version_mask &m) {
        std::cout << "version mask received: " << m << std::endl;
        std::lock_guard<std::shared_mutex> lock(ReadNewJobs);
        if (VersionMask == nullptr) VersionMask = new extensions::version_mask{m};
        else *VersionMask = m;
        make_puzzle();
    }
    
    miner::miner(tcp::socket &socket, uint32 threads) : 
        client_session{socket}, Threads{threads}, Mining{new std::thread*[threads]}, 
        WhenMiningStarts{}, WaitToStartMining{WhenMiningStarts.get_future()}, Finished{false} {
        for (int i = 0; i < Threads; i++) Mining[i] == nullptr;
    }
    
    void miner::run(
        const std::optional<extensions::requests> cp, 
        const mining::authorize_request::parameters& ap, 
        const mining::subscribe_request::parameters& sp) {
        try {
            if (!this->initialize(cp, ap, sp)) shutdown();
            
            WaitToStartMining.get();
            
            std::cout << "Begin mining!" << std::endl;
            
            for (int i = 0; i < Threads; i++) Mining[i]->join();
        } catch (...) {
            std::cout << "some kind of error happened" << std::endl;
            shutdown();
        }
    }
    
    void miner::shutdown() {
        std::lock_guard<std::shared_mutex> lock(ReadNewJobs);
        
        Finished = true;
        delete Job;
    }
    
    miner::~miner() {
        shutdown();
        
        for (int i = 0; i < Threads; i++) {
            Mining[i]->join();
            delete Mining[i];
        }
        
        delete[] Mining;
        delete Notify;
        delete VersionMask;
        delete ExtraNonce;
        delete Difficulty;
    }

}
