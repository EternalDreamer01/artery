#include "artery/application/platelet/SybilCertificateProvider.h"

#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/v2/naive_certificate_provider.hpp>
#include <vanetza/security/v2/null_certificate_provider.hpp>
#include <vanetza/security/v2/null_certificate_validator.hpp>

#include <string>
#include <stack>
#include <boost/filesystem.hpp>
#include <vanetza/security/persistence.hpp>
#include <omnetpp.h>


namespace artery {

// namespace vs = vanetza::security;
// namespace vs2 = vanetza::security::v2;

static std::stack<std::string> unused_certificates;
static std::stack<std::string> used_certificates;
static bool certificateLoaded = false;


SybilCertificateProvider::SybilCertificateProvider()
{
}
void SybilCertificateProvider::LoadTickets() {

    boost::filesystem::path certificate_path("./certificate/");

    boost::filesystem::directory_iterator end_itr;
    for (boost::filesystem::directory_iterator itr(certificate_path); itr != end_itr; itr++) {
        if (boost::filesystem::is_regular_file(itr->path())) {
            std::string file_path = itr->path().string();
            if (file_path.substr(file_path.find_last_of("."), file_path.size()).compare(".cert") == 0) {
                unused_certificates.push(itr->path().string());
            }
        }    
    }
    certificateLoaded = true;
}

void SybilCertificateProvider::LoadAuthorizationAuthority(std::string aa_path, vs2::CertificateCache& cert_cache)
{
    cert_cache.insert(vs2::load_certificate_from_file(aa_path));
}


void SybilCertificateProvider::RenewTickets()
{
    if (certificateLoaded == false) {
        SybilCertificateProvider::LoadTickets();
    }

    if (unused_certificates.size() == 0) {
        throw omnetpp::cRuntimeError("All certificates has been used. Try generating more certificate before running the simulation again");
    }

    std::string certificate_path = unused_certificates.top();
    used_certificates.push(certificate_path);
    unused_certificates.pop();

    std::string key_path = certificate_path.substr(0, certificate_path.find_last_of(".")) + ".key";


    current_certificate = vs2::load_certificate_from_file(certificate_path);
    current_keypair = vs2::load_private_key_from_file(key_path);
}

const vs::ecdsa256::PrivateKey& SybilCertificateProvider::own_private_key() {
        if (usage == 0) {
        RenewTickets();
        usage = 5;
    }
    return current_keypair.private_key;
}
const vs2::Certificate& SybilCertificateProvider::own_certificate() {
    if (usage == 0) {
        RenewTickets();
        usage = 5;
    }
    usage -= 1;

    return current_certificate;
}
std::list<vs2::Certificate> SybilCertificateProvider::own_chain() {
    std::list<vs2::Certificate> chain;
    return chain;
}
}

