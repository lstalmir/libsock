#include "pch.h"
#include "framework.h"

#ifdef OS_WINDOWS
#include "platform.h"

namespace libsock
{

/////////////////////////////////////////////////////////////////////////////
/// @function _initialize_platform
/// @brief Initializes WSA library. All calls to other socket functions are
///     invalid if the library has not been initialized.
/// @returns True if initialization was successful. Otherwise, if error
///     occured, false is returned.
bool _initialize_platform()
{
    WSADATA wsaData{};

    if( WSAStartup( MAKEWORD( 2, 0 ), &wsaData ) != ERROR_SUCCESS )
    {

        return false;
    }

    // Unreferenced
    (wsaData);

    return true;
}

//////////////////////////////////////////////////////////////////////////////
/// @function _cleanup_platform
/// @brief Releases WSA library resources.
/// @returns True if the library has been successfully released. If it was
///     not initialized prior calling this function, true is returned anyway.
///     Otherwise, if error occurred, false is returned.
bool _cleanup_platform()
{
    if( WSACleanup() != 0 )
    {

        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////////////
/// @function _get_platform_address_family
/// @brief Translates common address family, used by the libsock library, 
///     into system-dependent socket address family. Not all library families
///     have implementation in all systems.
/// @param _Family [in] Libsock library socket address family.
/// @returns Corresponding OS-dependent socket address family on success, 
///     -1 otherwise.
int _get_platform_address_family( address_family _Family )
{
    typedef address_family af;
    switch( _Family )
    {
    default:                return -1;
    case af::unspec:        return AF_UNSPEC;
    case af::local:         return AF_UNIX;
    case af::inet:          return AF_INET;
    case af::implink:       return AF_IMPLINK;
    case af::pup:           return AF_PUP;
    case af::chaos:         return AF_CHAOS;
    case af::ns:            return AF_NS;
    case af::iso:           return AF_ISO;
    case af::osi:           return AF_OSI;
    case af::ecma:          return AF_ECMA;
    case af::datakit:       return AF_DATAKIT;
    case af::rose:          return AF_CCITT;
    case af::x25:           return AF_CCITT;
    case af::ax25:          return AF_CCITT;
    case af::sna:           return AF_SNA;
    case af::decnet:        return AF_DECnet;
    case af::dli:           return AF_DLI;
    case af::lat:           return AF_LAT;
    case af::hylink:        return AF_HYLINK;
    case af::appletalk:     return AF_APPLETALK;
    case af::netbios:       return AF_NETBIOS;
    case af::voiceview:     return AF_VOICEVIEW;
    case af::firefox:       return AF_FIREFOX;
    case af::banyan:        return AF_BAN;
    case af::atm:           return AF_ATM;
    case af::inet6:         return AF_INET6;
    case af::cluster:       return AF_CLUSTER;
    case af::ieee1284_4:    return AF_12844;
    case af::irda:          return AF_IRDA;
    case af::netdes:        return AF_NETDES;

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

#endif
#endif
#endif
#endif
    }
}

//////////////////////////////////////////////////////////////////////////////
/// @function _get_platform_socket_type
/// @brief Translates common socket type, used by the libsock library, into 
///     system-dependent socket type. Not all library types have 
///     implementation in all systems.
/// @param _Type [in] Libsock library socket type.
/// @returns Corresponding OS-dependent socket type on success, -1 otherwise.
int _get_platform_socket_type( socket_type _Type )
{
    typedef socket_type sock;
    switch( _Type )
    {
    default:                return -1;
    case sock::stream:      return SOCK_STREAM;
    case sock::datagram:    return SOCK_DGRAM;
    case sock::raw:         return SOCK_RAW;
    case sock::rdm:         return SOCK_RDM;
    case sock::seqpacket:   return SOCK_SEQPACKET;
    }
}

//////////////////////////////////////////////////////////////////////////////
/// @function _get_platform_protocol
/// @brief Translates common protocol, used by the libsock library, into 
///     system-dependent protocol. Not all library protocol have
///     implementation in all systems.
/// @param _Protocol [in] Libsock library protocol.
/// @returns Corresponding OS-dependent protocol on success, -1 otherwise.
int _get_platform_protocol( protocol _Proto )
{
    typedef protocol proto;
    switch( _Proto )
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

}

#endif // OS_WINDOWS
