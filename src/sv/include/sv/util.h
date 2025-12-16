// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment: argument handling, config file parsing,
 * thread wrappers, startup time
 */
#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <sv/compat.h>
#include <sv/utiltime.h>

#include <atomic>
#include <array>
#include <cstdint>
#include <exception>
#include <map>
#include <numeric>
#include <string>
#include <vector>

#include <boost/signals2/signal.hpp>
#include <boost/thread/exceptions.hpp>

// Application startup time (used for uptime calculation)
int64_t GetStartupTime ();

extern const char *const BITCOIN_CONF_FILENAME;
extern const char *const BITCOIN_PID_FILENAME;

void SetupEnvironment ();
bool SetupNetworking ();

void PrintExceptionContinue (const std::exception *pex, const char *pszThread);
void FileCommit (FILE *file);
bool TruncateFile (FILE *file, uint64_t length);
int RaiseFileDescriptorLimit (int nMinFD);
void AllocateFileRange (FILE *file, unsigned int offset, uint64_t length);

void ClearDatadirCache ();
void runCommand (const std::string &strCommand);

template <typename ITER>
std::string StringJoin (const std::string &separator, ITER begin, ITER end) {
    std::ostringstream result;

    if (begin != end) {
        result << *begin;
        begin++;

        while (begin != end) {
            result << separator << *begin;
            begin++;
        }
    }

    return result.str ();
}

template <typename CONTAINER>
std::string StringJoin (const std::string &separator, const CONTAINER &cont) {
    return StringJoin (separator, cont.cbegin (), cont.cend ());
}

inline bool IsSwitchChar (char c) {
#ifdef WIN32
    return c == '-' || c == '/';
#else
    return c == '-';
#endif
}

/**
 * Format a string to be used as group of options in help messages.
 *
 * @param message Group name (e.g. "RPC server options:")
 * @return the formatted string
 */
std::string HelpMessageGroup (const std::string &message);

/**
 * Format a string to be used as option description in help messages.
 *
 * @param option Option message (e.g. "-rpcuser=<user>")
 * @param message Option description (e.g. "Username for JSON-RPC connections")
 * @return the formatted string
 */
std::string HelpMessageOpt (const std::string &option, const std::string &message);

/**
 * Return the number of physical cores available on the current system.
 * @note This does not count virtual cores, such as those provided by
 * HyperThreading when boost is newer than 1.56.
 */
int GetNumCores ();

void RenameThread (const char *name);
std::string GetThreadName ();

std::string CopyrightHolders (const std::string &strPrefix);

/**
 * A reusable average function.
 * Pre-condition: [first, last) is non-empty.
 */
template<typename InputIterator>
auto Average (InputIterator first, InputIterator last) {
    auto rangeSize { std::distance (first, last) };
    if (rangeSize == 0)
        throw std::runtime_error ("0 elements for Average");

    using T = typename InputIterator::value_type;
    T sum = std::accumulate (first, last, T {});
    return sum / rangeSize;
}

#endif // BITCOIN_UTIL_H
