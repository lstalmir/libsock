#ifndef __libsock_h_
#define __libsock_h_
#ifndef RC_INVOKED
#include <memory>
#include <system_error>

#ifndef _CONSTEXPRIF
#if defined( __cpp_if_constexpr ) && __cpp_if_constexpr <= __cplusplus
#define _CONSTEXPRIF constexpr
#else
#define _CONSTEXPRIF
#endif
#endif

#ifndef _NODISCARD
#define _NODISCARD
#endif

#if defined( _WIN32 ) || defined( _WIN64 ) || defined( WIN32 )
#define OS_WINDOWS

#include <sdkddkver.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <WS2bth.h>
#include <WS2atm.h>
#include <AF_Irda.h>

#elif defined( __linux__ )
#define OS_LINUX

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#else
#error Unknown target OS

#endif

#define _LIBSOCK ::libsock::

#define _LIBSOCK_CHECK_ARG_NOT_NULL( ARG ) \
    if( (ARG) == nullptr ) \
        throw std::invalid_argument( #ARG " cannot be NULL" );

#define _LIBSOCK_CHECK_ARG_NOT_EQ( ARG, VAL ) \
    if( (ARG) == (VAL) ) \
        throw std::invalid_argument( #ARG " cannot be " #VAL ); 


namespace libsock
{

template<typename _Ty, typename _Ty2>
inline _Ty _Reinterpret_optional_or_default( const _Ty2* _Optional, _Ty _Default )
    {   // extract value from optional value via reinterpret_cast
    return ((_Optional != nullptr) ? *reinterpret_cast<const _Ty*>(_Optional) : _Default);
    }

template<typename _Ty, typename _Ty2>
inline _Ty _Static_optional_or_default( const _Ty2* _Optional, _Ty _Default )
    {   // extract value from optional value via static_cast
    return ((_Optional != nullptr) ? static_cast<_Ty>(*_Optional) : _Default);
    }


#if defined( OS_WINDOWS )
typedef SOCKET _Socket_handle;
typedef int _Sock_size_t;
typedef int _Sockcomm_data_size_t;
typedef char _Sockcomm_data_t;
typedef char _Sockopt_data_t;
constexpr _Socket_handle _Invalid_socket = INVALID_SOCKET;

#elif defined( OS_LINUX )
typedef int _Socket_handle;
typedef socklen_t _Sock_size_t;
typedef size_t _Sockcomm_data_size_t;
typedef void _Sockcomm_data_t;
typedef void _Sockopt_data_t;
constexpr _Socket_handle _Invalid_socket = -1;

#else
#error _Socket_handle not defined for this OS
#endif

namespace __impl
{
#if defined( OS_WINDOWS ) \
 || defined( OS_LINUX )
using ::socket;
using ::shutdown;
using ::connect;
using ::accept;
using ::bind;
using ::listen;
using ::setsockopt;
using ::getsockopt;
using ::send;
using ::sendto;
using ::recv;
using ::recvfrom;
using ::getprotobyname;

#if defined( OS_WINDOWS )
using ::closesocket;
#elif defined( OS_LINUX )
inline int closesocket( _Socket_handle _Socket ) noexcept
    {   // closesocket alias for linux
    return ::close( _Socket );
    }
#endif

#else
#error Socket functions not defined for this OS
#endif

inline int geterror( int _Retval ) noexcept
    {   // gets last error reported by the sockets API
#if defined( OS_WINDOWS )
    (_Retval); // Unreferenced in this OS
    return WSAGetLastError();
#elif defined( OS_LINUX )
    (_Retval); // Unreferenced in this OS
    return errno;
#else
    return _Retval;
#endif
    }
}


_NODISCARD inline bool _Has_flags( int _Combined, int _Flags ) noexcept
    {   // check if combined flags contain specified values
    return (((_Combined) & (_Flags)) == (_Flags));
    }



// CLASS _Socket_error_category
class _Socket_error_category
    : public _STD error_category
    {
public:
    _NODISCARD inline virtual const char* name() const noexcept override
        {
        return "libsock error";
        }

    _NODISCARD inline virtual std::string message( int _Errval ) const override
        {
        _STD string msg = "Unable to retrieve error message";
#   if defined( OS_WINDOWS )
        // Windows OSes provide FormatMessage function, which translates error messages
        // into human-readable forms.
        char* msg_buffer = nullptr;
        ::FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            _Errval,
            MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
            (char*)(&msg_buffer), 0,
            nullptr );
        if( msg_buffer != nullptr )
            { // Copy obtained message to the output string and free the memory.
            msg.assign( msg_buffer );
            ::LocalFree( msg_buffer );
            }
#   elif defined( OS_LINUX )
        // Linux OSes provide strerror function, which translatess errno messages into
        // human-readable forms.
        msg.assign( ::strerror( _Errval ) );
#   else
#   error _Socket_error_category::message: Messages not implemented for this OS
#   endif
        return msg;
        }
    };


// CLASS socket_exception
class socket_exception
    : public _STD system_error
    {
typedef _STD system_error _MyBase;

public:
    inline socket_exception( int _Errval )
        : _MyBase( _Errval, _Socket_error_category{} )
        {   // construct basic socket exception
        }

    inline socket_exception( int _Errval, const char* _Message )
        : _MyBase( _Errval, _Socket_error_category{}, _Message )
        {   // construct basic socket exception with own message
        }
    };


// CLASS libsock_scope
class libsock_scope
    {
public:
    inline libsock_scope()
        {   // initialize socket library
#   if defined( OS_WINDOWS )
        WSADATA wsaData;
        if( WSAStartup( MAKEWORD( 2, 0 ), &wsaData ) != ERROR_SUCCESS )
            throw socket_exception( ::WSAGetLastError() );
        (wsaData); // avoid 'not referenced' warnings
#   endif
        }

    inline ~libsock_scope() noexcept
        {   // deinitialize socket library
#   if defined( OS_WINDOWS )
        ::WSACleanup();
#   endif
        }
    };


// ENUM CLASS address_family
enum class address_family
    {
    unknown             = -1,               // Unknown
    unspec              = AF_UNSPEC,        // Unspecified
    local               = AF_UNIX,          // Local to host (pipes, portals)
    decnet              = AF_DECnet,        // DECnet
    inet                = AF_INET,          // Internet IP protocol version 4 (IPv4)
    inet6               = AF_INET6,         // Internet IP protocol version 6 (IPv6)
    irda                = AF_IRDA,          // IrDA
#if defined( OS_WINDOWS )
    atm                 = AF_ATM,           // Native ATM services
    bluetooth           = AF_BTH,           // Bluetooth RFCOMM/L2CAP protocols
#elif defined( OS_LINUX )
    atm                 = AF_ATMSVC,        // Native ATM services
    bluetooth           = AF_BLUETOOTH,     // Bluetooth RFCOMM/L2CAP protocols
#endif
    };


// ENUM CLASS socket_type
enum class socket_type
    {
    unknown             = -1,               //
    stream              = SOCK_STREAM,      // Reliable stream socket
    datagram            = SOCK_DGRAM,       // Unreliable datagram socket
    rdm                 = SOCK_RDM,         // Reliable datagram socket
    seqpacket           = SOCK_SEQPACKET,   // Pseudo-stream datagram socket
    raw                 = SOCK_RAW          // Raw socket
    };


// RAW socket protocol initializer
enum _Raw_proto { _Raw };


// CLASS protocol
class protocol
    {
public:
    inline protocol( const char* _Name )
        : _MyId( -1 )
        {   // construct protocol wrapper from IANA name
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Name );
        protoent _Proto_ent = _Get_protocol_from_name( _Name );
        _MyId = static_cast<int>(_Proto_ent.p_proto);
        }

    inline protocol( _STD _Uninitialized ) noexcept
        : _MyId( -1 )
        {   // construct uninitialized (unknown) protocol wrapper
        }

    inline protocol( _Raw_proto ) noexcept
        : _MyId( 0 )
        {   // construct raw (no) protocol wrapper
        }

    _NODISCARD inline int get_id() const
        {   // get protocol id
        return _MyId;
        }

    _NODISCARD inline explicit operator int() const
        {   // cast protocol into INT value
        return get_id();
        }

protected:
    int _MyId;

    _NODISCARD inline protoent _Get_protocol_from_name( const char* _Name ) const
        {   // get protoent structure from IANA name
        protoent* _Proto_ent = __impl::getprotobyname( _Name );
        if( _Proto_ent == nullptr )
            { // protocol not found
            throw socket_exception( -1, "Unsupported protocol" );
            }
        return (*_Proto_ent);
        }
    };


_NODISCARD inline protocol unknown_protocol() { return protocol( _STD _Noinit ); }
_NODISCARD inline protocol raw_protocol() { return protocol( _Raw ); }
_NODISCARD inline protocol icmp_protocol() { return protocol( "icmp" ); }
_NODISCARD inline protocol igmp_protocol() { return protocol( "igmp" ); }
_NODISCARD inline protocol tcp_protocol() { return protocol( "tcp" ); }
_NODISCARD inline protocol udp_protocol() { return protocol( "udp" ); }


// ENUM CLASS socket_opt_ip
enum class socket_opt_ip
    {
    unknown             = -1,
    join_group          = IP_ADD_MEMBERSHIP,
    leave_group         = IP_DROP_MEMBERSHIP,
    join_source_group   = IP_ADD_SOURCE_MEMBERSHIP,
    leave_source_group  = IP_DROP_SOURCE_MEMBERSHIP,
    block_source        = IP_BLOCK_SOURCE,
    unblock_source      = IP_UNBLOCK_SOURCE,
    header_included     = IP_HDRINCL,
    multicast_interface = IP_MULTICAST_IF,
    multicast_loop      = IP_MULTICAST_LOOP,
    multicast_ttl       = IP_MULTICAST_TTL,
    ttl                 = IP_TTL,
    type_of_service     = IP_TOS,
    unicast_interface   = IP_UNICAST_IF,
    packet_info         = IP_PKTINFO,
#if defined( OS_WINDOWS )
    dont_fragment       = IP_DONTFRAGMENT,
#if defined IP_MTU
    mtu                 = IP_MTU,
    mtu_discover        = IP_MTU_DISCOVER,
#endif
#elif defined( OS_LINUX )
    dont_fragment       = 0x7f000001, // use special value to fallback to MTU_DISCOVER
    mtu                 = IP_MTU,
    mtu_discover        = IP_MTU_DISCOVER,
#else
#error dont_fragment not defined
#endif
    };


template<typename _SockOptT>
struct _Socket_opt_level;

template<>
struct _Socket_opt_level<socket_opt_ip>
    { 
    static constexpr int value = IPPROTO_IP;
    static constexpr int value_v6 = IPPROTO_IPV6;
    };


// CLASS socket
class socket
    {
public: // shutdown flag bits
    static constexpr int in = 1;
    static constexpr int out = 2;

private:
    static constexpr int _inout = socket::in | socket::out;

public:
    inline socket( address_family _Family, socket_type _Type, protocol _Protocol )
        : _MyHandle( _Invalid_socket )
        , _MyAddr_family( _Family )
        , _MyType( _Type )
        , _MyProtocol( _Protocol )
        {   // construct socket object
        this->_MyHandle = _Throw_if_failed( __impl::socket(
            static_cast<int>(_Family),
            static_cast<int>(_Type),
            static_cast<int>(_Protocol) ) );
        }

    inline virtual ~socket() noexcept
        {   // destroy socket object
        __impl::closesocket( this->_MyHandle );
        this->_MyHandle = _Invalid_socket;
        this->_MyAddr_family = address_family::unknown;
        this->_MyType = socket_type::unknown;
        this->_MyProtocol = unknown_protocol();
        }

    template<typename _SockOptT>
    inline void set_opt( _SockOptT _Opt, const void* _Optval, size_t _Optlen )
        {   // set socket option value
        _Set_socket_opt( static_cast<int>(_Opt), _Socket_opt_level<_SockOptT>::value,
            _Optval, _Optlen );
        }

    template<typename _SockOptT>
    inline void get_opt( _SockOptT _Opt, void* _Optval, size_t* _Optlen ) const
        {   // get socket option value
        _Get_socket_opt( static_cast<int>(_Opt), _Socket_opt_level<_SockOptT>::value,
            _Optval, _Optlen );
        }

    inline virtual int send( const void* _Data, size_t _ByteSize, int _Flags = 0 )
        {   // send message to the remote host
        if( _ByteSize == 0 ) return 0;
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Data );
        return _Throw_if_failed( (int)__impl::send( this->_MyHandle,
            reinterpret_cast<const _Sockcomm_data_t*>(_Data),
            static_cast<_Sockcomm_data_size_t>(_ByteSize),
            _Flags ) );
        }

    inline virtual int recv( void* _Data, size_t _ByteSize, int _Flags = 0 )
        {   // receive message from the remote host
        if( _ByteSize == 0 ) return 0;
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Data );
        return _Throw_if_failed( (int)__impl::recv( this->_MyHandle,
            reinterpret_cast<_Sockcomm_data_t*>(_Data),
            static_cast<_Sockcomm_data_size_t>(_ByteSize),
            _Flags ) );
        }

    template<typename _SockAddrTy>
    inline void bind( const _SockAddrTy* _Addr, size_t _Addrlen )
        {   // bind socket to the network interface
        _Throw_if_failed( __impl::bind( this->_MyHandle,
            reinterpret_cast<const sockaddr*>(_Addr),
            static_cast<_Sock_size_t>(_Addrlen) ) );
        }

    inline void listen( size_t _QueueLength = SOMAXCONN )
        {   // start listening for incoming connections
        _Throw_if_failed( __impl::listen( this->_MyHandle,
            static_cast<int>(_QueueLength) ) );
        }

    template<typename _SockAddrTy>
    inline void connect( const _SockAddrTy* _Addr, size_t _Addrlen )
        {   // connect to the remote host
        _Throw_if_failed( __impl::connect( this->_MyHandle,
            reinterpret_cast<const sockaddr*>(_Addr),
            static_cast<_Sock_size_t>(_Addrlen) ) );
        }

    _NODISCARD inline socket accept()
        {   // accept incoming connection from the client
        return accept<sockaddr>( nullptr, nullptr );
        }

    template<typename _SockAddrTy>
    _NODISCARD inline socket accept( _SockAddrTy* _Addr, size_t* _Addrlen )
        {   // accept incoming connection from the client
        // Length of _Addrlen value may differ, change it to platform-dependent
        // for the call and then cast it to size_t.
        _Sock_size_t addrlen = _Static_optional_or_default<_Sock_size_t>( _Addrlen, 0 );
        _Socket_handle _Accepted_handle = _Throw_if_failed( __impl::accept( this->_MyHandle,
            reinterpret_cast<sockaddr*>(_Addr),
            reinterpret_cast<_Sock_size_t*>((_Addrlen) ? &addrlen : nullptr) ) );
        if( _Addrlen != nullptr )
            { // Pass retrieved addrlen to the actual output parameter
            (*_Addrlen) = static_cast<size_t>(addrlen);
            }
        return socket( static_cast<_Socket_handle>(_Accepted_handle) );
        }

    inline void shutdown( int _Flags = socket::_inout )
        {   // close socket connection in specified direction
        int how = 0;
        if( _Has_flags( _Flags, socket::_inout ) )
            how = socket::_Shut_inout;
        else if( _Has_flags( _Flags, socket::in ) )
            how = socket::_Shut_in;
        else if( _Has_flags( _Flags, socket::out ) )
            how = socket::_Shut_out;
        _Throw_if_failed( __impl::shutdown( this->_MyHandle, how ) );
        }

public:
    template<typename _Ty>
    inline socket& operator<<( const _Ty& _Data )
        {   // send message through socket stream
        if( !_Is_stream_socket() )
            { // the socket is not stream-like
            throw std::exception( "Cannot use stream operations on non-stream socket" );
            }
        if( send( &_Data, sizeof( _Ty ) ) != static_cast<int>(sizeof( _Ty )) )
            { // send failed without raising errors?
            _Throw_if_failed( -1 );
            }
        return (*this);
        }

    template<typename _Ty>
    inline socket& operator>>( _Ty& _Data )
        {   // receive message through socket stream
        if( !_Is_stream_socket() )
            { // the socket is not stream-like
            throw std::exception( "Cannot use stream operations on non-stream socket" );
            }
        if( recv( &_Data, sizeof( _Ty ) ) != static_cast<int>(sizeof( _Ty )) )
            { // recv failed without raising errors?
            _Throw_if_failed( -1 );
            }
        return (*this);
        }

public:
    _NODISCARD inline _Socket_handle get_native_handle() const noexcept
        {   // retrieve native socket handle
        return this->_MyHandle;
        }

    _NODISCARD inline address_family get_address_family() const noexcept
        {   // get socket address family
        return this->_MyAddr_family;
        }

    _NODISCARD inline socket_type get_socket_type() const noexcept
        {   // get socket type
        return this->_MyType;
        }

    _NODISCARD inline protocol get_protocol() const noexcept
        {   // get socket protocol
        return this->_MyProtocol;
        }

protected:
    _Socket_handle _MyHandle;
    address_family _MyAddr_family;
    socket_type _MyType;
    protocol _MyProtocol;

    inline socket( _Socket_handle _Handle = _Invalid_socket ) noexcept
        : _MyHandle( _Handle )
        , _MyAddr_family( address_family::unknown )
        , _MyType( socket_type::unknown )
        , _MyProtocol( unknown_protocol() )
        {   // construct socket object from existing handle
        }

    _NODISCARD inline bool _Is_stream_socket() const noexcept
        {   // checks if the socket is reliable, stream one
        return (this->_MyType == socket_type::stream)
            || (this->_MyType == socket_type::seqpacket);
        }

    template<typename _Ty>
    inline _Ty& _Throw_if_failed( _Ty&& _Retval ) const
        {   // throw exception if _Retval indicates error
        if( reinterpret_cast<const int&>(_Retval) < 0 )
            { // assume that all negative return values indicate error
            throw socket_exception( __impl::geterror(
                static_cast<int>(_Retval) ) );
            }
        return _Retval;
        }

private:
    inline virtual void _Set_socket_opt( int _Opt, int _Opt_level, const void* _Optval, size_t _Optlen )
        {   // set socket option value
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optval );
        _LIBSOCK_CHECK_ARG_NOT_EQ( _Optlen, 0 );
        _Adjust_socket_opt_level( _Opt_level );
        _Throw_if_failed( __impl::setsockopt( this->_MyHandle,
            _Opt_level, _Opt,
            reinterpret_cast<const _Sockopt_data_t*>(_Optval),
            static_cast<_Sock_size_t>(_Optlen) ) );
        }

    inline virtual void _Get_socket_opt( int _Opt, int _Opt_level, void* _Optval, size_t* _Optlen ) const
        {   // get socket option value
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optval );
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optlen );
        _LIBSOCK_CHECK_ARG_NOT_EQ( *_Optlen, 0 );
        _Adjust_socket_opt_level( _Opt_level );
        _Sock_size_t optlen = _Static_optional_or_default<_Sock_size_t>( _Optlen, 0 );
        _Throw_if_failed( __impl::getsockopt( this->_MyHandle,
            _Opt_level, _Opt,
            reinterpret_cast<_Sockopt_data_t*>(_Optval),
            reinterpret_cast<_Sock_size_t*>(_Optlen ? &optlen : nullptr) ) );
        if( _Optlen != nullptr )
            (*_Optlen) = static_cast<size_t>(optlen);
        }

    inline virtual void _Adjust_socket_opt_level( int& _Opt_level ) const noexcept
        {   // adjust socket option level to socket's address family
        if( _Opt_level == _Socket_opt_level<socket_opt_ip>::value && _MyAddr_family == address_family::inet6 )
            { // _Socket_opt_level for IP has additional value for IPv6
            _Opt_level = _Socket_opt_level<socket_opt_ip>::value_v6;
            }
        }

private: // platform-dependent shutdown values
#if defined( OS_WINDOWS )
    static constexpr int _Shut_in = SD_RECEIVE;
    static constexpr int _Shut_out = SD_SEND;
    static constexpr int _Shut_inout = SD_BOTH;
#elif defined( OS_LINUX )
    static constexpr int _Shut_in = SHUT_RD;
    static constexpr int _Shut_out = SHUT_WR;
    static constexpr int _Shut_inout = SHUT_RDWR;
#else
#error Shutdown flags not defined
#endif
    };


template<>
inline void socket::get_opt( socket_opt_ip _Opt, void* _Optval, size_t* _Optlen ) const
    {   // get socket ip option value
#if defined( OS_LINUX )
    if( _Opt == socket_opt_ip::dont_fragment )
        {   // Linux OSes get/set DF flag via mtu MTU_DISCOVER settings
        if( (!_Optlen) || (*_Optlen) != sizeof( long ) )
            throw std::invalid_argument( "dont_fragment option requires LONG argument" );
        long value = 0;
        _Get_socket_opt( static_cast<int>(socket_opt_ip::mtu_discover), _Socket_opt_level<socket_opt_ip>::value,
            &value, _Optlen );
        if( _Optval != nullptr )
            *reinterpret_cast<long*>(_Optval) = (value == IP_PMTUDISC_DONT) ? 0 : 1;
        }
#endif// OS_LINUX
    return _Get_socket_opt( static_cast<int>(_Opt), _Socket_opt_level<socket_opt_ip>::value,
        _Optval, _Optlen );
    }


template<>
inline void socket::set_opt( socket_opt_ip _Opt, const void* _Optval, size_t _Optlen )
    {   // set socket ip option value
#if defined( OS_LINUX )
    if( _Opt == socket_opt_ip::dont_fragment )
        {   // Linux OSes get/set DF flag via mtu MTU_DISCOVER settings
        if( _Optlen != sizeof( long ) )
            throw std::invalid_argument( "dont_fragment option requires LONG argument" );
        long value = _Reinterpret_optional_or_default( _Optval, 0 );
        value = (value != 0) ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
        return _Set_socket_opt( static_cast<int>(socket_opt_ip::mtu_discover), _Socket_opt_level<socket_opt_ip>::value,
            &value, sizeof( value ) );
        }
#endif// OS_LINUX
    return _Set_socket_opt( static_cast<int>(_Opt), _Socket_opt_level<socket_opt_ip>::value,
        _Optval, _Optlen );
    }

}// libsock

#endif// RC_INVOKED
#endif// __libsock_h_
