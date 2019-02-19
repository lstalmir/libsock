#if defined( _WIN32 ) || defined( WIN32 ) || defined( _WIN64 )
// WA for WINAPI 8.1 in conformance mode
struct IUnknown;
#endif

#include "libsock.h"
using namespace libsock;

#include <string>
#include <thread>
using namespace std;


char g_recv_buffer[128];
int g_recv_byte_count;

thread g_client_thread;

void sock_thread_proc()
_TRY_BEGIN
    {
    libsock_scope sockscope;

    socket_address_info hints(
        socket_address_family::inet,
        socket_type::stream,
        tcp_socket_protocol() );

    socket_address_info addrinfo =
        get_socket_address_info( "", "27015", hints );

    libsock::socket sock( addrinfo );
    sock.connect( *addrinfo.addr );

    g_recv_byte_count = sock.recv( g_recv_buffer, sizeof( g_recv_buffer ) );

    sock.shutdown();
    }
_CATCH( socket_exception ex )
    {
    perror( ex.what() );
    }
_CATCH_ALL
_CATCH_END;
// END sock_thread_proc


int main()
_TRY_BEGIN
    {
    libsock_scope sockscope;

    socket_address_info hints(
        socket_address_family::inet,
        socket_type::stream,
        tcp_socket_protocol(),
        socket_address_flags::passive );

    socket_address_info addrinfo =
        get_socket_address_info( "", "27015", hints );

    libsock::socket localhost_sock( addrinfo );
    localhost_sock.bind( *addrinfo.addr );
    localhost_sock.listen();

    g_client_thread = thread( sock_thread_proc );

    libsock::socket client_sock = localhost_sock.accept();
    client_sock << "Hello";

    if( !g_client_thread.joinable() )
        return -1;

    g_client_thread.join();

    if( g_recv_byte_count != 6 )
        return -2;

    if( strcmp( "Hello", g_recv_buffer ) != 0 )
        return -3;

    return 0;
    }
_CATCH( socket_exception ex )
    {
    perror( ex.what() );
    return ex.code().value();
    }
_CATCH_ALL
    {
    return -4;
    }
_CATCH_END;
// END main
