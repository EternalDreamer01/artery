#include "artery/application/StaticCertificateLoader.h"

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


StaticCertificateLoader::StaticCertificateLoader(TrustStore& trustStore, CertificateCache& certCache) : trustStore(trustStore), certCache(certCache)
{
}

void StaticCertificateLoader::LoadTickets() {

    path certificate_path("./certificates/");

    directory_iterator end_itr;
    for (directory_iterator itr(certificate_path); itr != end_itr; itr++) {
        if (is_regular_file(itr->path())) {
            unused_certificates.push(itr->path().string());
        }    
    }
    certCache.insert(load_certificate_from_file("./certificates/cert_bin/aa.cert"));
    trustStore.insert(load_certificate_from_file("./certificates/cert_bin/root.cert"));
    certificateLoaded = true;
}

SecurityEntity artery::StaticCertificateLoader::RenewTickets()
{
    if (certificateLoaded == false) {
        StaticCertificateLoader::LoadTickets();
        if (unused_certificates.size() == 0) {
            throw omnetpp::cRuntimeError("certificates folder must be populated");
        }
    }

    std::string certificate_path = unused_certificates.top();
    used_certificates.push(certificate_path);
    unused_certificates.pop();

    std::string key_path = certificate_path.substr(0, certificate_path.find_first_of(".")) + ".key";


    Certificate certificate = load_certificate_from_file(certificate_path);
    ecdsa256::KeyPair keyPair = load_private_key_from_file(key_path);

    return SecurityEntity { certificate, keyPair };
}

}
