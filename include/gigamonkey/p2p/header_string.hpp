// Copyright (c) 2022 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef GIGAMONKEY_INCLUDE_GIGAMONKEY_P2P_HEADER_STRING_HPP_
#define GIGAMONKEY_INCLUDE_GIGAMONKEY_P2P_HEADER_STRING_HPP_

#include <string_view>
namespace Gigamonkey::Bitcoin {
	template<std::size_t Size = 12>
	class string {
		char m_data[Size] = {0};
	  public:
		constexpr string() : m_data({}){}
		constexpr string(std::string_view str) {
			for(int i=0;i< str.size();i++) {
				m_data[i]=str[i];
			}
		}
		constexpr  char const* data() const { return m_data;}
		constexpr operator const char*() const { return data();}
		constexpr char const& operator[] (std::size_t i) const { return m_data[i];}
		constexpr const char* begin() const { return std::begin(m_data);}
		constexpr const char* end() const { return std::end(m_data);}
	};
}
#endif //GIGAMONKEY_INCLUDE_GIGAMONKEY_P2P_HEADER_STRING_HPP_
