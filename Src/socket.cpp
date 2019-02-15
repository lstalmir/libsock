#include "pch.h"
#include "framework.h"

#include "libsock.h"
#include "platform.h"


namespace libsock
{

class socket::impl
{
public:
    _Socket_handle _Handle;

    inline impl( address_family family, socket_type type, protocol proto )
        : _Handle( _Invalid_socket )
    { // Initialize new socket.
        _Handle = ::socket(
            _get_platform_address_family( family ),
            _get_platform_socket_type( type ),
            _get_platform_protocol( proto ) );

        if( _Handle == _Invalid_socket )
            throw socket_exception( -1 /* todo */ );
    }

    inline ~impl() noexcept
    { // Release socket resources.
        if( _Handle != _Invalid_socket )
            ::closesocket( _Handle );
    }
};


socket::socket( address_family family, socket_type type, protocol proto )
    : _Impl( new impl( family, type, proto ) )
{}


int socket::bind()
{
    //int result = ::bind( _Impl->_Handle, );
    return -1;
}

}
