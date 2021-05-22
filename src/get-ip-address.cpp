#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iphlpapi.h>
#include <intrin.h>

#include <array>

#include <cstring>
#include <cctype>

#define GMX_EXPORT extern "C" __declspec(dllexport)

//////////////////////////////////////////////////////////////////////////

namespace gmx
{
	//////////////////////////////////////////////////////////////////////////

	static char s_LastError[256] = {};

	//////////////////////////////////////////////////////////////////////////

	void SetLastErrorString(const char* error)
	{
		strcpy(s_LastError, error);
	}

	//////////////////////////////////////////////////////////////////////////

	char* GetLastErrorString()
	{
		return s_LastError;
	}

	//////////////////////////////////////////////////////////////////////////

	PIP_ADAPTER_INFO GetAdapter()
	{
		ULONG buffer_size  = sizeof(IP_ADAPTER_INFO);;
		PIP_ADAPTER_INFO adapter_info
			= (IP_ADAPTER_INFO*) malloc(sizeof(IP_ADAPTER_INFO));
		
		if (!adapter_info)
		{
			SetLastErrorString("Failed to allocate initial IP_ADAPTER_INFO.");
			return NULL;
		}

		if (GetAdaptersInfo(adapter_info, &buffer_size) == ERROR_BUFFER_OVERFLOW)
		{
			free(adapter_info);
			adapter_info = (IP_ADAPTER_INFO*)malloc(buffer_size);
			
			if (!adapter_info)
			{
				SetLastErrorString("Failed to allocate secondary IP_ADAPTER_INFO.");
				return NULL;
			}
		}

		if (GetAdaptersInfo(adapter_info, &buffer_size) == NO_ERROR)
		{
			return adapter_info;
		}

		if (adapter_info)
		{
			free(adapter_info);
		}

		SetLastErrorString("Generic failure getting IP_ADAPTER_INFO.");

		return NULL;
	}

	//////////////////////////////////////////////////////////////////////////

	using IpAddress = std::array<int, 4>;

	//////////////////////////////////////////////////////////////////////////

	static IpAddress ParseIP(const char* str)
	{
		IpAddress ret {};
		int pos = 0;
		
		while (*str)
		{
			if (*str == '.')
			{
				pos++;
			}
			else if (isdigit(*str))
			{
				ret[pos] = ret[pos] * 10 + (*str - '0');
			}

			str++;
		}

		return ret;
	}

	//////////////////////////////////////////////////////////////////////////

	char* GetLocalIPAddress()
	{
		PIP_ADAPTER_INFO adapter = gmx::GetAdapter();

		if (!adapter)
		{
			return GetLastErrorString();
		}

		static char output_string[4096] = {};

		while (adapter)
		{
			const char* type = nullptr;

			switch (adapter->Type)
			{
			case MIB_IF_TYPE_ETHERNET:
				type = "wired";
				break;
			
			case IF_TYPE_IEEE80211:
				type = "wifi";
				break;
			}

			IP_ADDR_STRING* ip_address = &adapter->IpAddressList;

			while (ip_address)
			{
				IpAddress ip        = ParseIP(ip_address->IpAddress.String);
				IpAddress mask      = ParseIP(ip_address->IpMask.String);
				int       mask_bits = 0;

				for (int i = 0; i < 4; i++)
				{
					mask_bits += __popcnt(mask[i]);
					mask[i] &= ip[i];
				}

				if (*output_string != '\0')
				{
					strcat(output_string, ";");
				}

				strcat(output_string, type);
				strcat(output_string, ",");
				strncat(output_string, ip_address->IpAddress.String, 16);
				strcat(output_string, ",");

				for (size_t i = 0; i < mask.size(); ++i)
				{
					const int mask_component = mask[i];

					char str[16] = {};
					_itoa(mask_component, str, 10);

					strcat(output_string, str);

					const char* terminator = (i < mask.size() - 1) ? "." : "/";
					strcat(output_string, terminator);
				}

				char str[16] = {};
				_itoa(mask_bits, str, 10);

				strcat(output_string, str);

				ip_address = ip_address->Next;
			}

			adapter = adapter->Next;
		}

		free(adapter);

		return output_string;
	}

	//////////////////////////////////////////////////////////////////////////
}

//////////////////////////////////////////////////////////////////////////

GMX_EXPORT char* __cdecl gmx_get_local_ip_address()
{
	SetUnhandledExceptionFilter(UnhandledExceptionFilter);
	int* a = nullptr;
	*a = 10;
	return gmx::GetLocalIPAddress();
}

//////////////////////////////////////////////////////////////////////////

