#pragma once
#include "libsock.h"


namespace libsock
{

#if defined( OS_WINDOWS )
typedef SOCKET _Socket_handle;
constexpr _Socket_handle _Invalid_socket = INVALID_SOCKET;

#elif defined( OS_LINUX )
typedef int _Socket_handle;
constexpr _Socket_handle _Invalid_socket = -1;

#endif

bool _initialize_platform();
bool _cleanup_platform();

int _get_platform_address_family( address_family family );
int _get_platform_socket_type( socket_type type );
int _get_platform_protocol( protocol proto );

}
