#pragma once
#include <Windows.h>
#include <iostream>
#include <locale>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <bitset>
#include <vector>

#include "StrHide.hpp"

#ifdef _DEBUG
#define DEBUG
#endif


class amsi_exception : public std::runtime_error
{
public:
	amsi_exception(const std::wstring& err, DWORD error_code = 0)
		:std::runtime_error(""),
		error_text_(err), error_code_(0)
	{}

	const std::wstring& get_error() const
	{
		return error_text_;
	}

	const std::wstring get_winapi_error() const
	{
		return error_text_ + get_winapi_error_description();
	}

	const std::wstring get_winapi_error_description() const {
		std::wstring errorDescription;
		LPWSTR buffer = nullptr;

		if (FormatMessageW(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			error_code_,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			reinterpret_cast<LPWSTR>(&buffer),
			0,
			nullptr)) {
			errorDescription = buffer;
			LocalFree(buffer);
		}
		else {
			errorDescription = L"Unknown Error";
		}

		return errorDescription;
	}

private:
	std::wstring error_text_;
	DWORD error_code_;
};

class handle_helper
{
public:
	handle_helper(HANDLE h)
		:h_(h)
	{}

	handle_helper(handle_helper& other)
		:h_(other.h_)
	{
		other.h_ = INVALID_HANDLE_VALUE;
	}

	handle_helper()
		:h_(INVALID_HANDLE_VALUE)
	{}

	handle_helper& operator=(handle_helper& other)
	{
		close();
		h_ = other.h_;
		other.h_ = INVALID_HANDLE_VALUE;
		return *this;
	}

	handle_helper& operator=(HANDLE h)
	{
		close();
		h_ = h;
		return *this;
	}

	HANDLE& get() { return h_; }

	~handle_helper()
	{
		close();
	}

	void close()
	{
		if (h_ != INVALID_HANDLE_VALUE)
		{
			CloseHandle(h_);
			h_ = INVALID_HANDLE_VALUE;
		}
	}

	void reset() { h_ = INVALID_HANDLE_VALUE; }

private:
	HANDLE h_;
};
