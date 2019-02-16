#pragma once
#include <memory>
#include <system_error>

#if defined( _WIN32 ) || defined( _WIN64 ) || defined( WIN32 )

#if __has_include(<sdkddkver.h>)
#include <sdkddkver.h>
#endif

#ifdef _WIN32_WINNT
#define OS_WINDOWS

#include <WinSock2.h>

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

#elif defined( __POSIX__ )
#define OS_LINUX

#include <sys/socket.h>

#else
#error Unknown target OS

#endif


namespace libsock
{

#if defined( OS_WINDOWS )
typedef SOCKET _Socket_handle;
constexpr _Socket_handle _Invalid_socket = INVALID_SOCKET;

#elif defined( OS_LINUX )
typedef int _Socket_handle;
constexpr _Socket_handle _Invalid_socket = -1;

#endif


class _Socket_error_category
    : public std::error_category
{
public:
    ////////////////////////////////////////////////////////////////////////////////////
    /// @function _Socket_error_category::name
    /// @brief Returns name of the category object.
    /// @returns
    inline virtual const char* name() const noexcept override
    { return "libsock error"; }

    ////////////////////////////////////////////////////////////////////////////////////
    /// @function _Socket_error_category::message
    /// @brief Gets message for the specified error code.
    /// @param _Errval [in] Error code.
    /// @returns Error description message.
    inline virtual std::string message( int _Errval ) const override
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
            LocalFree( msg_buffer );
        }

#   elif defined( OS_LINUX )

#   else
#   error _Socket_error_category::message: Messages not implemented for this OS
#   endif
        return msg;
    }
};


/// @class socket_exception
/// @brief Socket exception class wraps all errors which may be raised by calls to
///     socket functions.
class socket_exception
    : public std::system_error
{
    typedef std::system_error _Base;

public:
    ////////////////////////////////////////////////////////////////////////////////////
    /// @function socket_exception::socket_exception
    /// @brief Constructs instance of basic socket exception with provided error code.
    /// @param _Errval [in] Error code to report.
    inline socket_exception( int _Errval )
        : _Base( _Errval, _Socket_error_category{} )
    {
    }
};


/// @class libsock_scope
/// @brief Some implementations (e.g.: Windows) require additional initialization and
///     cleanup when using sockets. Due to this, the library requires user to create
///     and hold reference to instance of this class to make sure all resources are
///     initialized.
class libsock_scope
{
public:
    ////////////////////////////////////////////////////////////////////////////////////
    /// @function libsock_scope::libsock_scope
    /// @brief Initializes the library. All calls to other socket functions are invalid
    ///     if the library has not been initialized.
    /// @throws socket_exception If initialization of the library fails.
    inline libsock_scope()
    {
#   if defined( OS_WINDOWS )
        // The structure will be initialized with OS caps for the sockets.
        // For now, we don't need them.
        WSADATA wsaData;

        if( WSAStartup( MAKEWORD( 2, 0 ), &wsaData ) != ERROR_SUCCESS )
            throw socket_exception( WSAGetLastError() );

        // Make sure no compiler reports warning on unused variable. This is to avoid
        // compilation errors when using 'treat warnings as errors' flags.
        (wsaData);

#   endif// WINDOWS
    }

    ////////////////////////////////////////////////////////////////////////////////////
    /// @function libsock_scope::~libsock_scope
    /// @brief Releases the library resources.
    inline ~libsock_scope() noexcept
    {
#   if defined( OS_WINDOWS )
        WSACleanup();
#   endif
    }
};


enum class address_family
{
    unknown = -1,   // Unknown
    unspec,         // Unspecified
    local,          // Local to host (pipes, portals)
    inet,           // Internet IP protocol version 4 (IPv4)
    implink,        // ARPANET IMP address
    pup,            // PUP protocols
    chaos,          // MIT CHAOS protocols
    ns,             // XEROX NS protocols
    ipx,            // Novell IPX protocols
    iso,            // ISO protocols
    osi,            // OSI protocols
    ecma,           // European Computer Manufacturers
    datakit,        // DATAKIT protocols
    sna,            // IBM SNA
    decnet,         // DECnet
    dli,            // Direct data link interface
    lat,            // LAT
    hylink,         // NSC Hyperchannel
    appletalk,      // AppleTalk
    netbios,        // NetBIOS-style address
    voiceview,      // VoiceView
    firefox,        // FireFox protocols
    banyan,         // Banyan
    atm,            // Native ATM services
    atmpvc,         // ATM PVCs
    inet6,          // Internet IP protocol version 6 (IPv6)
    cluster,        // Microsoft Wolfpack
    ieee1284_4,     // IEEE 1284.4 WG AF
    ieee802154,     // IEEE 802154 sockets
    irda,           // IrDA
    netdes,         // Network Designers OSI & gateway
    tcnprocess,     // 
    tcnmessage,     //
    iclfxbm,        //
    bluetooth,      // Bluetooth RFCOMM/L2CAP protocols
    link,           //
    hyperv,         //
    infiniband,     // Native InfiniBand address
    isdn,           // mISDN sockets
    xdp,            // XDP sockets
    nfc,            // NFC sockets
    bridge,         // Multiprotocol bridge
    x25,            // Reserved for X.25 project
    ax25,           // Amateur Radio AX.25
    rose,           // Amateur Radio X.25 PLP
    netlink,        // 
    netrom,         // Amateur Radio NET/ROM
    netbeui,        // Reserved for 802.2LLC project
    security,       // Security callback pseudo address family
    key,            // Key management API
    packet,         // Packet family
    ash,            // Ash
    econet,         // Acorn Econet
    rds,            // RDS sockets
    pppox,          // PPPoX sockets
    wanpipe,        // Wanpipe API Sockets
    llc,            // Linux LLC
    mpls,           // MPLS
    can,            // Controller Area Network
    tipc,           // TIPC sockets
    iucv,           // IUCV sockets
    rxrpc,          // RxRPC sockets
    phonet,         // Phonet sockets
    caif,           // CAIF sockets
    algorithm,      // Algorithm sockets
    vsock,          // vSockets
    kcm,            // Kernel Connection Multiplexor
    qipcrtr,        // Qualcomm IPC Router
    smc             //
};

//////////////////////////////////////////////////////////////////////////////
/// @function _get_platform_address_family
/// @brief Translates common address family, used by the libsock library, 
///     into system-dependent socket address family. Not all library families
///     have implementation in all systems.
/// @param _Family [in] Libsock library socket address family.
/// @returns Corresponding OS-dependent socket address family on success, 
///     -1 otherwise.
inline int _Get_platform_address_family( address_family _Family )
{
    typedef address_family af;
    switch( _Family )
    {
    default:                return -1;
    case af::unspec:        return AF_UNSPEC;
    case af::local:         return AF_UNIX;
    case af::inet:          return AF_INET;
    case af::inet6:         return AF_INET6;

    case af::implink:       return AF_IMPLINK;
    case af::pup:           return AF_PUP;
    case af::chaos:         return AF_CHAOS;
    case af::ns:            return AF_NS;
    case af::iso:           return AF_ISO;
    case af::osi:           return AF_OSI;
    case af::ecma:          return AF_ECMA;
    case af::datakit:       return AF_DATAKIT;
    case af::sna:           return AF_SNA;
    case af::decnet:        return AF_DECnet;
    case af::dli:           return AF_DLI;
    case af::lat:           return AF_LAT;
    case af::hylink:        return AF_HYLINK;
    case af::appletalk:     return AF_APPLETALK;
    case af::voiceview:     return AF_VOICEVIEW;
    case af::firefox:       return AF_FIREFOX;
    case af::banyan:        return AF_BAN;
    case af::atm:           return AF_ATM;
    case af::cluster:       return AF_CLUSTER;
    case af::irda:          return AF_IRDA;
    case af::netdes:        return AF_NETDES;

#if defined( OS_WINDOWS )
    case af::netbios:       return AF_NETBIOS;
    case af::rose:          return AF_CCITT;
    case af::x25:           return AF_CCITT;
    case af::ax25:          return AF_CCITT;
    case af::ieee1284_4:    return AF_12844;

#ifdef OS_WINDOWS_XP
    case af::tcnprocess:    return AF_TCNPROCESS;
    case af::tcnmessage:    return AF_TCNMESSAGE;
    case af::iclfxbm:       return AF_ICLFXBM;

#ifdef OS_WINDOWS_VISTA
    case af::bluetooth:     return AF_BTH;

#ifdef OS_WINDOWS_7
    case af::link:          return AF_LINK;

#ifdef OS_WINDOWS_10
    case af::hyperv:        return AF_HYPERV;

#endif// OS_WINDOWS_10
#endif// OS_WINDOWS_7
#endif// OS_WINDOWS_VISTA
#endif// OS_WINDOWS_XP

#elif defined( OS_LINUX )
    case af::rose:          return AF_ROSE;
    case af::x25:           return AF_X25;
    case af::ax25:          return AF_AX25;
    case af::bluetooth:     return AF_BLUETOOTH;

#else
#error Address families are not defined for this OS
#endif
    }
}


enum class socket_type
{
    unknown = -1,   //
    stream,         //
    datagram,       //
    raw,            //
    rdm,            //
    seqpacket       //
};

//////////////////////////////////////////////////////////////////////////////
/// @function _get_platform_socket_type
/// @brief Translates common socket type, used by the libsock library, into 
///     system-dependent socket type. Not all library types have 
///     implementation in all systems.
/// @param _Type [in] Libsock library socket type.
/// @returns Corresponding OS-dependent socket type on success, -1 otherwise.
inline int _Get_platform_socket_type( socket_type _Type )
{
    typedef socket_type sock;
    switch( _Type )
    {
    default:                return -1;
    case sock::stream:      return SOCK_STREAM;
    case sock::datagram:    return SOCK_DGRAM;
    case sock::raw:         return SOCK_RAW;
    case sock::seqpacket:   return SOCK_SEQPACKET;
#if defined( OS_WINDOWS )
    case sock::rdm:         return SOCK_RDM;
#endif
    }
}

enum class protocol
{
    unknown = -1,   //
    hopopts,        //
    icmp,           //
    igmp,           //
    ggp,            //
    ipv4,           //
    st,             //
    tcp,            //
    cbt,            //
    egp,            //
    igp,            //
    pup,            //
    udp,            //
    idp,            //
    rdp,            //
    ipv6,           //
    routing,        //
    fragment,       //
    esp,            //
    ah,             //
    icmpv6,         //
    none,           //
    dstopts,        //
    nd,             //
    iclfxbm,        //
    pim,            //
    pgm,            //
    l2tp,           //
    sctp,           //
    raw             //
};

//////////////////////////////////////////////////////////////////////////////
/// @function _get_platform_protocol
/// @brief Translates common protocol, used by the libsock library, into 
///     system-dependent protocol. Not all library protocol have
///     implementation in all systems.
/// @param _Protocol [in] Libsock library protocol.
/// @returns Corresponding OS-dependent protocol on success, -1 otherwise.
inline int _Get_platform_protocol( protocol _Protocol )
{
    typedef protocol proto;
    switch( _Protocol )
    {
    default:                return -1;
    case proto::icmp:       return IPPROTO_ICMP;
    case proto::igmp:       return IPPROTO_IGMP;
    case proto::ggp:        return IPPROTO_GGP;
    case proto::tcp:        return IPPROTO_TCP;
    case proto::pup:        return IPPROTO_PUP;
    case proto::udp:        return IPPROTO_UDP;
    case proto::idp:        return IPPROTO_IDP;
    case proto::nd:         return IPPROTO_ND;
    case proto::raw:        return IPPROTO_RAW;

#ifdef OS_WINDOWS_XP
    case proto::hopopts:    return IPPROTO_HOPOPTS;
    case proto::ipv4:       return IPPROTO_IPV4;
    case proto::ipv6:       return IPPROTO_IPV6;
    case proto::routing:    return IPPROTO_ROUTING;
    case proto::fragment:   return IPPROTO_FRAGMENT;
    case proto::esp:        return IPPROTO_ESP;
    case proto::ah:         return IPPROTO_AH;
    case proto::icmpv6:     return IPPROTO_ICMPV6;
    case proto::none:       return IPPROTO_NONE;
    case proto::dstopts:    return IPPROTO_DSTOPTS;
    case proto::iclfxbm:    return IPPROTO_ICLFXBM;

#ifdef OS_WINDOWS_VISTA
    case proto::st:         return IPPROTO_ST;
    case proto::cbt:        return IPPROTO_CBT;
    case proto::egp:        return IPPROTO_EGP;
    case proto::igp:        return IPPROTO_IGP;
    case proto::rdp:        return IPPROTO_RDP;
    case proto::pim:        return IPPROTO_PIM;
    case proto::pgm:        return IPPROTO_PGM;
    case proto::l2tp:       return IPPROTO_L2TP;
    case proto::sctp:       return IPPROTO_SCTP;

#endif
#endif
    }
}


class socket
{
public:
    ////////////////////////////////////////////////////////////////////////////////////
    /// @function socket::socket
    /// @brief Constructs new socket instance.
    /// @param _Family [in] Socket address family.
    /// @param _Type [in] Socket type.
    /// @param _Protocol [in] Communication protocol.
    /// @throws socket_exception If creation of the system socket object fails.
    inline socket( address_family _Family, socket_type _Type, protocol _Protocol )
        : _Handle( _Invalid_socket )
    {
        _Handle = ::socket(
            _Get_platform_address_family( _Family ),
            _Get_platform_socket_type( _Type ),
            _Get_platform_protocol( _Protocol ) );
        _Throw_if_failed( (int)(_Handle) );
    }

    ////////////////////////////////////////////////////////////////////////////////////
    inline virtual ~socket() noexcept
    { close(); }

    ////////////////////////////////////////////////////////////////////////////////////
    /// @function socket::get_native_handle
    /// @brief 
    inline _Socket_handle get_native_handle() const
    { return _Handle; }

    ////////////////////////////////////////////////////////////////////////////////////
    int bind();

    ////////////////////////////////////////////////////////////////////////////////////
    int listen( int _QueueLength = SOMAXCONN )
    {
        if( _QueueLength )
        {

        }
        return _Invoke_socket_func( ::listen, _QueueLength );
    }

    ////////////////////////////////////////////////////////////////////////////////////
    int connect();

    ////////////////////////////////////////////////////////////////////////////////////
    int accept();

    ////////////////////////////////////////////////////////////////////////////////////
    /// @function socket::send
    /// @brief Sends data to the remote host.
    /// @param _Data [in] Address of the memory block to send. It may be NULL only if
    ///     _ByteSize is 0.
    /// @param _ByteSize [in] Size of the memory block to send. If 0, no data is sent.
    /// @param _Flags [in] Optional operation flags.
    /// @returns Number of bytes sent.
    /// @throws std::invalid_argument If _Data pointer is NULL and _ByteSize is not 0.
    inline virtual int send( const void* _Data, size_t _ByteSize, int _Flags = 0 )
    {
        if( _ByteSize == 0 ) return 0;
        if( _Data == nullptr )
            throw std::invalid_argument( "Source data pointer cannot be NULL" );

        return _Invoke_socket_func( ::send, reinterpret_cast<const char*>(_Data),
            static_cast<int>(_ByteSize), _Flags );
    }

    ////////////////////////////////////////////////////////////////////////////////////
    /// @function socket::recv
    /// @brief Receive data from the remote host.
    /// @param _Data [out] Address of the destination memory block. The received data
    ///     will be stored in the block. It must be already allocated by the caller.
    /// @param _ByteSize [in] Size of the provided memory block. If 0, no data is
    ///     received.
    /// @param _Flags [in] Optional operation flags.
    /// @returns Number of bytes read.
    /// @throws std::invalid_argument If _Data pointer is NULL and _ByteSize is not 0.
    /// @throws socket_exception If any error occurs while receiving the data.
    inline virtual int recv( void* _Data, size_t _ByteSize, int _Flags = 0 )
    {
        if( _ByteSize == 0 ) return 0;
        if( _Data == nullptr )
            throw std::invalid_argument( "Destination data pointer cannot be NULL" );

        return _Invoke_socket_func( ::recv, reinterpret_cast<char*>(_Data),
            static_cast<int>(_ByteSize), _Flags );
    }

    ////////////////////////////////////////////////////////////////////////////////////
    /// @function socket::close
    /// @brief Release the socket handle.
    /// @returns 0 if the socket has been released successfully. If the socket was
    ///     invalid prior calling close(), 0 is returned.
    /// @throws socket_exception If any error occurs while releasing the socket.
    inline virtual void close() noexcept
    {
        if( _Handle != _Invalid_socket )
        {
            _Invoke_socket_func_nothrow( ::closesocket );
            _Handle = _Invalid_socket;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////
    int set_opt();

    ////////////////////////////////////////////////////////////////////////////////////
    int get_opt();

protected:
    _Socket_handle _Handle;

    ////////////////////////////////////////////////////////////////////////////////////
    /// @function socket::_Invoke_socket_func
    /// @brief Invokes socket function and throws C++ exception if the operation fails.
    ///     See _Invoke_socket_func_nothrow for exception-safe version of the function.
    /// @param _Func [in] Function to execute.
    /// @param _Args... [in] Optional parameters to pass to the function.
    /// @returns Return code of the original socket function.
    /// @throws socket_exception If the original socket function fails.
    template<typename _Fx, typename... _Ax>
    inline int _Invoke_socket_func( _Fx&& _Func, _Ax... _Args )
    {
         int result = _Func( _Handle, _Args... );
         _Throw_if_failed( result );
         return result;
    }

    ////////////////////////////////////////////////////////////////////////////////////
    /// @function socket::_Invoke_socket_func_nothrow
    /// @brief Invokes socket function and guarantees that no C++ exceptions will be
    ///     raised if the operation fails.
    /// @param _Func [in] Function to execute.
    /// @param _Args... [in] Optional parameters to pass to the function.
    /// @returns Return code of the original socket function.
    template<typename _Fx, typename... _Ax>
    inline int _Invoke_socket_func_nothrow( _Fx&& _Func, _Ax... _Args ) noexcept
    {
        return _Func( _Handle, _Args... );
    }

    ////////////////////////////////////////////////////////////////////////////////////
    /// @function socket::_Throw_if_failed
    /// @brief Raises a socket_exception if the provided return value indicates error.
    /// @param _Retval [in] Return value obtained from call to native socket function.
    /// @throws socket_exception If return value indicates an error.
    inline void _Throw_if_failed( int _Retval )
    {
        if( _Retval < 0 )
        { // We assume that all negative return values indicate error
#       if defined( OS_WINDOWS )
            // Windows OSes provide error data with this function
            _Retval = WSAGetLastError();
#       endif
            throw socket_exception( _Retval );
        }
    }

};

}
