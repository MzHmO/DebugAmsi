#pragma once

namespace mlcg {
	constexpr uint32_t modulus() {
		return 0x7FFFFFFF;
	}

	constexpr uint32_t fnv1a(const char* str, uint32_t h = 0x811C9DC5U) {
		return (*str == 0) ? h : fnv1a(str + 1, (h ^ static_cast<uint32_t>(*str)) * 0x1000193U);
	}

	template<size_t N>
	constexpr uint32_t seed(const char(&entropy)[N], const uint32_t iv = 0) {
		return fnv1a(entropy) ^ iv;
	}

	constexpr uint32_t prng(const uint32_t input) {
		return (input * 0xBC8FU) % modulus();
	}
}

template<typename T, size_t N>
struct encrypted {
	uint32_t seed;
	T data[N];
};

template<typename T, size_t N>
constexpr auto crypt(const T(&input)[N], const uint32_t seed = 0) {
	encrypted<T, N> blob{};
	blob.seed = seed;
	for (uint32_t index{ 0 }, stream{ seed }; index < N; index++) {
		blob.data[index] = input[index] ^ stream;
		stream = mlcg::prng(stream);
	}
	return blob;
}


#define ec(STRING) ([&] {                                                       \
    constexpr auto _{ crypt(STRING, mlcg::seed(__TIMESTAMP__, __COUNTER__ )) }; \
    return std::string{ crypt(_.data, _.seed).data };                           \
}())

#define ew(STRING) ([&] {                                                       \
    constexpr auto _{ crypt(STRING, mlcg::seed(__TIMESTAMP__, __COUNTER__ )) }; \
    return std::wstring{ crypt(_.data, _.seed).data };                          \
}())
