#ifndef STATICCERTIFICATELOADER_H
#define STATICCERTIFICATELOADER_H

#include <vanetza/security/certificate.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/trust_store.hpp>



namespace artery {

class StaticCertificateLoader {

public:
    StaticCertificateLoader(vanetza::security::TrustStore&, vanetza::security::CertificateCache&);
    vanetza::security::Certificate GetNewCertificate();

private:
    vanetza::security::CertificateCache& certCache;
    vanetza::security::TrustStore& trustStore;
    void LoadCertificates();
};

}



#endif