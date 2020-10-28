// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SV_SUPPORT_CLEANSE_H
#define SV_SUPPORT_CLEANSE_H

#include <cstdlib>

namespace sv {

void memory_cleanse(void *ptr, size_t len);

}

#endif // SV_SUPPORT_CLEANSE_H

