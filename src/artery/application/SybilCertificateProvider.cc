#include "artery/application/SybilCertificateProvider.h"

#include<string>
#include<stack>
#include <boost/filesystem.hpp>
#include <vanetza/security/persistence.hpp>
#include <omnetpp.h>

namespace artery {

using namespace boost::filesystem;
using namespace vanetza::security;

static std::stack<std::string> unused_certificates;
static std::stack<std::string> used_certificates;
static bool certificateLoaded = false;


SybilCertificateProvider::SybilCertificateProvider()
{
}
void SybilCertificateProvider::LoadTickets() {

    path certificate_path("./certificate/");

    directory_iterator end_itr;
    for (directory_iterator itr(certificate_path); itr != end_itr; itr++) {
        if (is_regular_file(itr->path())) {
            std::string file_path = itr->path().string();
            if (file_path.substr(file_path.find_last_of("."), file_path.size()).compare(".cert") == 0) {
                unused_certificates.push(itr->path().string());
            }
        }    
    }
    certificateLoaded = true;
}

void SybilCertificateProvider::LoadAuthorizationAuthority(std::string aa_path, vanetza::security::CertificateCache& cert_cache)
{
    cert_cache.insert(vanetza::security::load_certificate_from_file(aa_path));
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


    current_certificate = load_certificate_from_file(certificate_path);
    current_keypair = load_private_key_from_file(key_path);
}

const ecdsa256::PrivateKey& SybilCertificateProvider::own_private_key() {
        if (usage == 0) {
        RenewTickets();
        usage = 5;
    }
    return current_keypair.private_key;
}
const Certificate& SybilCertificateProvider::own_certificate() {
    if (usage == 0) {
        RenewTickets();
        usage = 5;
    }
    usage -= 1;

    return current_certificate;
}
std::list<Certificate> SybilCertificateProvider::own_chain() {
    std::list<Certificate> chain;
    return chain;
}
}

