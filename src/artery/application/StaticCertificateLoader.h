#ifndef STATICCERTIFICATELOADER_H
#define STATICCERTIFICATELOADER_H

#include <vanetza/security/certificate.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/security/ecdsa256.hpp>


namespace artery {
using namespace vanetza::security;
struct SecurityEntity {
   Certificate certificate;
   ecdsa256::KeyPair keyPair;
};

class StaticCertificateLoader {

public:
    StaticCertificateLoader(TrustStore&, CertificateCache&);
    SecurityEntity RenewTickets();

private:
    void LoadTickets();
};

}



#endif