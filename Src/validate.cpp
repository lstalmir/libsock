#if defined( _WIN32 ) || defined( WIN32 ) || defined( _WIN64 )
// WA for WINAPI 8.1 in conformance mode
struct IUnknown;
#endif

#include "libsock.h"
using namespace libsock;

#include <string>
#include <thread>
using namespace std;

#ifndef _TRY_BEGIN
#define _TRY_BEGIN try {
#define _CATCH(X) } catch( X ) {
#define _CATCH_ALL } catch(...) {
#define _CATCH_END }
#endif


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
    libsock::socketstream sock_stream( sock, 0 );

    sock.connect( *addrinfo.addr );

    std::string text;
    sock_stream >> text;

    memcpy( g_recv_buffer, text.c_str(), text.length() + 1 );
    g_recv_byte_count += text.size() + 1;

    short number = 0;
    sock_stream >> number;

    memcpy( g_recv_buffer + g_recv_byte_count - 1, &number, sizeof( number ) );
    g_recv_byte_count += sizeof( number );

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
    libsock::socketstream stream( client_sock, 0 );

    stream << string( "Hello" );
    stream << (short)0x30;

    if( !g_client_thread.joinable() )
        return -1;

    g_client_thread.join();

    if( g_recv_byte_count != 8 )
        return -2;

    if( strcmp( "Hello0", g_recv_buffer ) != 0 )
        return -3;

    return 0;
    }
_CATCH( socket_exception ex )
    {
    perror( ex.what() );
    if( g_client_thread.joinable() )
        g_client_thread.join();
    return ex.code().value();
    }
_CATCH_ALL
    {
    if( g_client_thread.joinable() )
        g_client_thread.join();
    return -4;
    }
_CATCH_END;
// END main
