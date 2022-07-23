// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/p2p/var_int.hpp>

namespace Gigamonkey::Bitcoin {

	uint64 var_int::read(reader &r) {
		byte b;
		r >> b;
		if (b <= 0xfc) {
			return b;
		}

		if (b == 0xfd) {
			uint16_little n;
			r >> n;
			return uint16(n);
		}

		if (b == 0xfe) {
			uint32_little n;
			r >> n;
			return uint32(n);
		}

		uint64_little n;
		r >> n;
		return uint64(n);
	}

	writer &var_int::write(writer &w, uint64 x) {
		if (x <= 0xfc) return w << static_cast<byte>(x);
		else if (x <= 0xffff) return w << byte(0xfd) << uint16_little{static_cast<uint16>(x)};
		else if (x <= 0xffffffff) return w << byte(0xfe) << uint32_little{static_cast<uint32>(x)};
		else return w << byte(0xff) << uint64_little{x};
	}

	reader &var_string::read(reader &r, bytes &b) {
		b = {};
		uint64 size = var_int::read(r);
		b.resize(size);
		for (int i = 0; i < size; i++) r >> b[i];
		return r;
	}

}