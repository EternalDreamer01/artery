#ifndef SIGNED_CAM_HPP
#define SIGNED_CAM_HPP

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Data.h>

namespace vanetza
{
namespace asn1
{

class SignedCam : public asn1c_per_wrapper<EtsiTs103097Data_t>
{
public:
    using wrapper = asn1c_per_wrapper<EtsiTs103097Data_t>;
    SignedCam() : wrapper(asn_DEF_EtsiTs103097Data) {};
};

} // namespace asn1
} // namespace vanetza

#endif /* SIGNED_CAM_HPP */