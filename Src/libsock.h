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

#if __has_include(<sdkddkver.h>)
#include <sdkddkver.h>
#endif

#ifdef _WIN32_WINNT
#define OS_WINDOWS

#include <WinSock2.h>

#if __has_include(<WS2tcpip.h>)
#define WINDOWS_IP
#include <WS2tcpip.h>
#endif

#if __has_include(<WSNwLink.h>)
#define WINDOWS_IPX
#include <WSNwLink.h>
#endif

#if __has_include(<AF_Irda.h>)
#define WINDOWS_IRDA
#include <AF_Irda.h>
#endif

#if __has_include(<atalkwsh.h>)
#define WINDOWS_APPLETALK
#include <atalkwsh.h>
#endif

#if defined( _WIN32_WINNT_NT4 ) && ( _WIN32_WINNT >=_WIN32_WINNT_NT4 )
#define WINNT_4_0
#define OS_WINDOWS_NT

#if defined( _WIN32_WINNT_WIN2K ) && ( _WIN32_WINNT >= _WIN32_WINNT_WIN2K )
#define WINNT_5_0
#define OS_WINDOWS_2000

#if defined( _WIN32_WINNT_WINXP ) && ( _WIN32_WINNT >= _WIN32_WINNT_WINXP )
#define WINNT_5_1
#define OS_WINDOWS_XP
#define OS_WINDOWS_SERVER_2003

#if defined( _WIN32_WINNT_WS03 ) && ( _WIN32_WINNT >= _WIN32_WINNT_WS03 )
#define WINNT_5_2
#define OS_WINDOWS_XP_SP2
#define OS_WINDOWS_SERVER_2003_SP1

#if defined( _WIN32_WINNT_VISTA ) && ( _WIN32_WINNT >= _WIN32_WINNT_VISTA )
#define WINNT_6_0
#define OS_WINDOWS_VISTA
#define OS_WINDOWS_SERVER_2008

#if defined( _WIN32_WINNT_WIN7 ) && ( _WIN32_WINNT >= _WIN32_WINNT_WIN7 )
#define WINNT_6_1
#define OS_WINDOWS_7
#define OS_WINDOWS_SERVER_2008_R2

#if defined( _WIN32_WINNT_WIN8 ) && ( _WIN32_WINNT >= _WIN32_WINNT_WIN8 )
#define WINNT_6_2
#define OS_WINDOWS_8
#define OS_WINDOWS_SERVER_2012

#if defined( _WIN32_WINNT_WINBLUE ) && ( _WIN32_WINNT >= _WIN32_WINNT_WINBLUE )
#define WINNT_6_3
#define OS_WINDOWS_8_1
#define OS_WINDOWS_SERVER_2012_R2

#if defined( _WIN32_WINNT_WIN10 ) && ( _WIN32_WINNT >= _WIN32_WINNT_WIN10 )
#define WINNT_10_0
#define OS_WINDOWS_10
#define OS_WINDOWS_SERVER_2016

//          WINNT_10_0, WINDOWS 10
#endif  //  WINNT_6_3, WINDOWS 8.1
#endif  //  WINNT_6_2, WINDOWS 8
#endif  //  WINNT_6_1, WINDOWS 7
#endif  //  WINNT_6_0, WINDOWS VISTA
#endif  //  WINNT_5_2, WINDOWS XP SP2
#endif  //  WINNT_5_1, WINDOWS XP
#endif  //  WINNT_5_0, WINDOWS 2000
#endif  //  WINNT_4_0, WINDOWS NT
#endif  //  WINDOWS
#endif

#elif defined( __linux__ )
#define OS_LINUX

#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

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
#else
    return _Retval;
#endif
    }
}


// CLASS _Socket_error_category
class _Socket_error_category
    : public std::error_category
    {
public:
    _NODISCARD inline virtual const char* name() const noexcept override
        {
        return "libsock error";
        }

    _NODISCARD inline virtual std::string message( int _Errval ) const override
        {
        std::string msg = "Unable to retrieve error message";

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

#   else
#   error _Socket_error_category::message: Messages not implemented for this OS
#   endif
        return msg;
        }
    };


// CLASS socket_exception
class socket_exception
    : public std::system_error
    {
typedef std::system_error _MyBase;

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
    inet                = AF_INET,          // Internet IP protocol version 4 (IPv4)
    inet6               = AF_INET6,         // Internet IP protocol version 6 (IPv6)
    decnet              = AF_DECnet,        // DECnet
    irda                = AF_IRDA,          // IrDA
#if defined( OS_WINDOWS )
    implink             = AF_IMPLINK,       // ARPANET IMP address
    pup                 = AF_PUP,           // PUP protocols
    chaos               = AF_CHAOS,         // MIT CHAOS protocols
    ns                  = AF_NS,            // XEROX NS protocols
    ipx                 = AF_IPX,           // Novell IPX protocols
    iso                 = AF_ISO,           // ISO protocols
    osi                 = AF_OSI,           // OSI protocols
    ecma                = AF_ECMA,          // European Computer Manufacturers
    datakit             = AF_DATAKIT,       // DATAKIT protocols
    sna                 = AF_SNA,           // IBM SNA
    dli                 = AF_DLI,           // Direct data link interface
    lat                 = AF_LAT,           // LAT
    hylink              = AF_HYLINK,        // NSC Hyperchannel
    appletalk           = AF_APPLETALK,     // AppleTalk
    netbios             = AF_NETBIOS,       // NetBIOS-style address
    voiceview           = AF_VOICEVIEW,     // VoiceView
    firefox             = AF_FIREFOX,       // FireFox protocols
    banyan              = AF_BAN,           // Banyan
    cluster             = AF_CLUSTER,       // Microsoft Wolfpack
    ieee1284_4          = AF_12844,         // IEEE 1284.4 WG AF
    netdes              = AF_NETDES,        // Network Designers OSI & gateway
    x25                 = AF_CCITT,         // Reserved for X.25 project
    ax25                = AF_CCITT,         // Amateur Radio AX.25
    rose                = AF_CCITT,         // Amateur Radio X.25 PLP
    atm                 = AF_ATM,           // Native ATM services
#ifdef OS_WINDOWS_XP
    tcnprocess          = AF_TCNPROCESS,    // 
    tcnmessage          = AF_TCNMESSAGE,    //
    iclfxbm             = AF_ICLFXBM,       //
#ifdef OS_WINDOWS_VISTA
    bluetooth           = AF_BTH,           // Bluetooth RFCOMM/L2CAP protocols
#ifdef OS_WINDOWS_7
    link                = AF_LINK,          //
#ifdef OS_WINDOWS_10
    hyperv              = AF_HYPERV,        //
#endif // OS_WINDOWS_10
#endif // OS_WINDOWS_7
#endif // OS_WINDOWS_VISTA
#endif // OS_WINDOWS_XP
#elif defined( OS_LINUX )
    x25                 = AF_X25,           // Reserved for X.25 project
    ax25                = AF_AX25,          // Amateur Radio AX.25
    rose                = AF_ROSE,          // Amateur Radio X.25 PLP
    atm                 = AF_ATMSVC,        // Native ATM services
    atmpvc              = AF_ATMPVC,        // ATM PVCs
    ieee802154          = AF_IEEE802154,    // IEEE 802154 sockets
    infiniband          = AF_IB,            // Native InfiniBand address
    isdn                = AF_ISDN,          // mISDN sockets
    //xdp                 = AF_XDP,           // XDP sockets
    nfc                 = AF_NFC,           // NFC sockets
    bluetooth           = AF_BLUETOOTH,     // Bluetooth RFCOMM/L2CAP protocols
    bridge              = AF_BRIDGE,        // Multiprotocol bridge
    netlink             = AF_NETLINK,       // 
    netrom              = AF_NETROM,        // Amateur Radio NET/ROM
    netbeui             = AF_NETBEUI,       // Reserved for 802.2LLC project
    security            = AF_SECURITY,      // Security callback pseudo address family
    key                 = AF_KEY,           // Key management API
    packet              = AF_PACKET,        // Packet family
    ash                 = AF_ASH,           // ASH
    econet              = AF_ECONET,        // Acorn Econet
    rds                 = AF_RDS,           // RDS sockets
    pppox               = AF_PPPOX,         // PPPoX sockets
    wanpipe             = AF_WANPIPE,       // Wanpipe API Sockets
    llc                 = AF_LLC,           // Linux LLC
    mpls                = AF_MPLS,          // MPLS
    can                 = AF_CAN,           // Controller Area Network
    tipc                = AF_TIPC,          // TIPC sockets
    iucv                = AF_IUCV,          // IUCV sockets
    rxrpc               = AF_RXRPC,         // RxRPC sockets
    phonet              = AF_PHONET,        // Phonet sockets
    caif                = AF_CAIF,          // CAIF sockets
    algorithm           = AF_ALG,           // Algorithm sockets
    vsock               = AF_VSOCK,         // vSockets
    kcm                 = AF_KCM,           // Kernel Connection Multiplexor
    //qipcrtr             = AF_QIPCRTR,       // Qualcomm IPC Router
    //smc                 = AF_SMC            //
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


#define _PROTO( _FN ) \
    _FN( unspec ) \
    _FN( icmp ) \
    _FN( igmp ) \
    _FN( ggp ) \
    _FN( st ) \
    _FN( tcp ) \
    _FN( cbt ) \
    _FN( egp ) \
    _FN( igp ) \
    _FN( pup ) \
    _FN( udp ) \
    _FN( idp ) \
    _FN( rdp ) \
    _FN( auth )
    
#define _PROTO_ENUM_ELEMENT_DECL( proto ) proto,

// ENUM CLASS protocol
enum class protocol
    {
    unknown = -1,
    _PROTO( _PROTO_ENUM_ELEMENT_DECL )
    };

#define _PROTO_NAME_DECL( proto ) #proto,
static constexpr const char* _Protocol_name[] =
    {
    _PROTO( _PROTO_NAME_DECL )
    };

#undef _PROTO
#undef _PROTO_ENUM_ELEMENT_DECL
#undef _PROTO_NAME_DECL


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
    { static constexpr int value = IPPROTO_IP; };


//#define _Invoke_socket_func( FUNC, ... ) (FUNC(this->_MyHandle,__VA_ARGS__))


// CLASS socket
class socket
    {
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
            _Get_platform_protocol_id( _Protocol ) ) );
        }

    inline virtual ~socket() noexcept
        {   // destroy socket object
        __impl::closesocket( this->_MyHandle );
        this->_MyHandle = _Invalid_socket;
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
        , _MyProtocol( protocol::unknown )
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
    inline static int _Get_platform_protocol_id( protocol _Protocol )
        {   // get protocol number from system database
        size_t protocol_offset = static_cast<size_t>(_Protocol);
        if( protocol_offset >= std::extent<decltype(_Protocol_name)>::value )
            { // protocol argument invalid (out of range)
            throw socket_exception( -1, "Invalid protocol" );
            }
        protoent* proto = ::getprotobyname( _Protocol_name[protocol_offset] );
        if( proto == nullptr )
            { // protocol is not supported
            throw socket_exception( -1, "Unsupported protocol" );
            }
        return static_cast<int>(proto->p_proto);
        }

    inline virtual void _Set_socket_opt( int _Opt, int _Opt_level, const void* _Optval, size_t _Optlen )
        {   // set socket option value
        _LIBSOCK_CHECK_ARG_NOT_NULL( _Optval );
        _LIBSOCK_CHECK_ARG_NOT_EQ( _Optlen, 0 );
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
        _Sock_size_t optlen = _Static_optional_or_default<_Sock_size_t>( _Optlen, 0 );
        _Throw_if_failed( __impl::getsockopt( this->_MyHandle,
            _Opt_level, _Opt,
            reinterpret_cast<_Sockopt_data_t*>(_Optval),
            reinterpret_cast<_Sock_size_t*>(_Optlen ? &optlen : nullptr) ) );
        if( _Optlen != nullptr )
            (*_Optlen) = static_cast<size_t>(optlen);
        }

    };

template<>
inline void socket::get_opt( socket_opt_ip _Opt, void* _Optval, size_t* _Optlen ) const
    {   // get socket ip option value
#if defined( OS_LINUX )
    if( _Opt == socket_opt_ip::dont_fragment )
        {
        _Opt = socket_opt_ip::mtu_discover;
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
        {   // Linux OSes set DF flag via mtu MTU_DISCOVER settings
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
