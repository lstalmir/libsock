#include "pch.h"
#include "framework.h"

#include "libsock.h"
#include "platform.h"


namespace libsock
{

class _Socket_category
    : public std::error_category
{
    inline virtual const char* name() const noexcept override
    {
        return "libsock::socket_exception";
    }

    inline virtual std::string message( int _Errval ) const override
    {
        _Errval;
        return "";
    }
};


socket_exception::socket_exception( int _Errval )
    : system_error( _Errval, _Socket_category{} )
{}

}
