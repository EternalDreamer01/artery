#ifndef SYBILCERTIFICATELOADER_H
#define SYBILCERTIFICATELOADER_H

#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/trust_store.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/v2/certificate_provider.hpp>


namespace artery {

namespace vs = vanetza::security;
namespace vs2 = vanetza::security::v2;

class SybilCertificateProvider : public vs2::CertificateProvider {

public:
    SybilCertificateProvider();
    void LoadAuthorizationAuthority(std::string, vs2::CertificateCache&);
    void RenewTickets();

    /**
     * Get own certificate to use for signing
     * \return own certificate
     */
    const vs2::Certificate& own_certificate() override;

    /**
     * Get own certificate chain in root CA → AA → AT order, excluding the AT and root certificate
     * \return own certificate chain
     */
    std::list<vs2::Certificate> own_chain() override;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    const vs::ecdsa256::PrivateKey& own_private_key() override;

private:
    void LoadTickets();
    vs::ecdsa256::KeyPair current_keypair;
    std::list<vs2::Certificate> current_chain;
    vs2::Certificate current_certificate;
    int usage = 0;
};

}



#endif