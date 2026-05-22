#ifndef SYBILCERTIFICATELOADER_H
#define SYBILCERTIFICATELOADER_H

#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/trust_store.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/v2/certificate_provider.hpp>



namespace artery {
using namespace vanetza::security;

class SybilCertificateProvider : public CertificateProvider {

public:
    SybilCertificateProvider();
    void LoadAuthorizationAuthority(std::string, vanetza::security::CertificateCache&);
    void RenewTickets();

    /**
     * Get own certificate to use for signing
     * \return own certificate
     */
    const Certificate& own_certificate() override;

    /**
     * Get own certificate chain in root CA → AA → AT order, excluding the AT and root certificate
     * \return own certificate chain
     */
    std::list<Certificate> own_chain() override;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    const ecdsa256::PrivateKey& own_private_key() override;

private:
    void LoadTickets();
    ecdsa256::KeyPair current_keypair;
    std::list<Certificate> current_chain;
    Certificate current_certificate;
    int usage = 0;
};

}



#endif