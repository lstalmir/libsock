
// WA for WINAPI 8.1 in conformance mode
struct IUnknown;

#include "libsock.h"
using namespace libsock;

#include <string>
using namespace std;


int main()
    {
    volatile libsock_scope sockscope;

    libsock::socket localhost_sock(
        address_family::inet,
        socket_type::stream,
        protocol::tcp );

    return 0;
    }
