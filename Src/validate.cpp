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
thread g_raw_client_thread;

void sock_thread_proc() noexcept
    {
    try
        {
        libsock_scope sockscope;

        socket_address_info hints(
            socket_address_family::inet,
            socket_type::stream,
            tcp_socket_protocol() );

        socket_address_info addrinfo =
            get_socket_address_info( "", "27015", hints );

        libsock::socket sock( addrinfo );
        libsock::socketstream sock_stream( sock, socketstream::text );

        sock.connect( *addrinfo.addr );

        sock_stream >> g_recv_buffer;
        g_recv_byte_count += (int)strlen( g_recv_buffer ) + 1;

        short number = 0;
        sock_stream >> std::hex >> number;

        memcpy( g_recv_buffer + g_recv_byte_count - 1, &number, sizeof( number ) );
        g_recv_byte_count += sizeof( number );

        sock.shutdown();
        }
    catch( socket_exception ex )
        {
        perror( ex.what() );
        }
    catch( ... )
        {}
    }
// END sock_thread_proc

void raw_sock_thread_proc() noexcept
    {
    try
        {
        libsock_scope sockscope;

        socket_address_info hints(
            socket_address_family::inet,
            socket_type::raw,
            raw_socket_protocol() );

        socket_address_info addrinfo =
            get_socket_address_info( "", "27015", hints );

        libsock::socket sock( addrinfo );

        sock.set_opt( socket_opt_ip::header_included, true );
        }
    catch( socket_exception ex )
        {
        perror( ex.what() );
        }
    catch( ... )
        {}
    }
// END raw_sock_thread_proc


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
    localhost_sock.bind();
    localhost_sock.listen();

    // TEST 1
    g_client_thread = thread( sock_thread_proc );
    libsock::socket client_sock = localhost_sock.accept();
    libsock::socketstream stream( client_sock, socketstream::text );
    stream << string( "Hello" );
    stream << std::hex << (short)0x30;
    if( !g_client_thread.joinable() )
        return -1;
    g_client_thread.join();
    if( g_recv_byte_count != 8 )
        return -2;
    if( strcmp( "Hello0", g_recv_buffer ) != 0 )
        return -3;

    // TEST 2
    g_raw_client_thread = thread( raw_sock_thread_proc );
    // TODO: reenable after implementation of raw sockets support
    //client_sock = localhost_sock.accept();
    if( !g_raw_client_thread.joinable() )
        return -4;
    g_raw_client_thread.join();

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
