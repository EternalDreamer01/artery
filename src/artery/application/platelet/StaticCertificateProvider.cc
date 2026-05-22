#include "StaticCertificateProvider.h"

#include <boost/filesystem.hpp>
#include <omnetpp.h>
#include <vanetza/security/persistence.hpp>

#include <stack>
#include <string>


namespace artery
{

using namespace boost::filesystem;
// using namespace vanetza::security;

static std::stack<std::string> unused_certificates;
static std::stack<std::string> used_certificates;
static bool certificateLoaded = false;


StaticCertificateProvider::StaticCertificateProvider()
{
}
void StaticCertificateProvider::LoadTickets()
{

    path certificate_path(boost::filesystem::current_path());

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

void StaticCertificateProvider::LoadAuthorizationAuthority(std::string aa_path, vs2::CertificateCache& cert_cache)
{
    cert_cache.insert(vs2::load_certificate_from_file(aa_path));
}


void StaticCertificateProvider::RenewTickets()
{
    if (certificateLoaded == false) {
        StaticCertificateProvider::LoadTickets();
        if (unused_certificates.size() == 0) {
            throw omnetpp::cRuntimeError("certificates folder must be populated");
        }
    }

    std::string certificate_path = unused_certificates.top();
    used_certificates.push(certificate_path);
    unused_certificates.pop();

    std::string key_path = certificate_path.substr(0, certificate_path.find_last_of(".")) + ".key";


    current_certificate = vs2::load_certificate_from_file(certificate_path);
    current_keypair = vs2::load_private_key_from_file(key_path);
}

const vs::ecdsa256::PrivateKey& StaticCertificateProvider::own_private_key()
{
    if (need_renew) {
        RenewTickets();
        need_renew = false;
    }
    return current_keypair.private_key;
}
const vs2::Certificate& StaticCertificateProvider::own_certificate()
{
    if (need_renew) {
        RenewTickets();
        need_renew = false;
    }
    return current_certificate;
}
std::list<vs2::Certificate> StaticCertificateProvider::own_chain()
{
    std::list<vs2::Certificate> chain;
    return chain;
}
}  // namespace artery
