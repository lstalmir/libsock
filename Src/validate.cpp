#if defined( _WIN32 ) || defined( WIN32 ) || defined( _WIN64 )
// WA for WINAPI 8.1 in conformance mode
struct IUnknown;
#endif

#include "libsock.h"
using namespace libsock;

#include <string>
using namespace std;


int main()
    {
    libsock_scope sockscope;

    socket_address_info hints = {};
    hints.family = socket_address_family::inet;
    hints.socktype = socket_type::stream;
    hints.protocol = tcp_socket_protocol();
    hints.flags = socket_address_flags::passive;

    socket_address_info addrinfo =
        get_socket_address_info( "27015", hints );

    libsock::socket localhost_sock( addrinfo );
    localhost_sock.bind( *addrinfo.addr );
    localhost_sock.listen();

    return 0;
    }
