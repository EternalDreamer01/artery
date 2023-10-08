#include "artery/application/StaticCertificateLoader.h"

#include<string>
#include<stack>
#include <boost/filesystem.hpp>
#include <vanetza/security/persistence.hpp>
#include <omnetpp.h>

namespace artery {

using namespace boost::filesystem;

static std::stack<std::string> unused_certificates;
static std::stack<std::string> used_certificates;
static bool certificateLoaded = false;


StaticCertificateLoader::StaticCertificateLoader(vanetza::security::TrustStore& trustStore, vanetza::security::CertificateCache& certCache) : trustStore(trustStore), certCache(certCache)
{
}

void StaticCertificateLoader::LoadCertificates() {

    path certificate_path("./certificates/");

    directory_iterator end_itr;
    for (directory_iterator itr(certificate_path); itr != end_itr; itr++) {
        if (is_regular_file(itr->path())) {
            unused_certificates.push(itr->path().string());
        }    
    }
    certCache.insert(vanetza::security::load_certificate_from_file("./certificates/cert_bin/aa.cert"));
    trustStore.insert(vanetza::security::load_certificate_from_file("./certificates/cert_bin/root.cert"));
    certificateLoaded = true;
}

vanetza::security::Certificate artery::StaticCertificateLoader::GetNewCertificate()
{
    if (certificateLoaded == false) {
        StaticCertificateLoader::LoadCertificates();
        if (unused_certificates.size() == 0) {
            throw omnetpp::cRuntimeError("certificates folder must be populated");
        }
    }

    std::string certificate_path = unused_certificates.top();
    used_certificates.push(certificate_path);
    unused_certificates.pop();

    return vanetza::security::load_certificate_from_file(certificate_path);
}

}
