#ifndef STATICCERTIFICATELOADER_H
#define STATICCERTIFICATELOADER_H

#include <vanetza/security/certificate.hpp>
#include <vanetza/security/certificate_cache.hpp>



namespace artery {

class StaticCertificateLoader {

public:
    StaticCertificateLoader();
    vanetza::security::Certificate GetNewTicket();
    void LoadAuthorizationAuthority(std::string, vanetza::security::CertificateCache&);

private:
    void LoadTickets();
};

}



#endif