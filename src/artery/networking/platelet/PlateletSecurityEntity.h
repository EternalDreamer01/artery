#ifndef CUSTOM_SECURITY_ENTITY_H
#define CUSTOM_SECURITY_ENTITY_H

#include <omnetpp/csimplemodule.h>
#include <vanetza/common/runtime.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/certificate_provider.hpp>
#include <vanetza/security/v2/certificate_validator.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <vanetza/security/verify_service.hpp>
#include <memory>
#include <string>

namespace artery {

namespace vs = vanetza::security;
namespace vs2 = vanetza::security::v2;

class PlateletSecurityEntity :
    public omnetpp::cSimpleModule,
    public vs::SecurityEntity
{
  protected:
    // OMNeT++ lifecycle
    int numInitStages() const override { return 3; }
    void initialize(int stage) override;
    void finish() override;

    // SecurityEntity overrides (v2)
    vs::EncapConfirm encapsulate_packet(vs::EncapRequest&& req) override;
    vs::DecapConfirm decapsulate_packet(vs::DecapRequest&& req) override;

  protected:
    // Factory helpers adapted to v2 API
    std::unique_ptr<vs::Backend>
      createBackend(const std::string &config) const;

    std::unique_ptr<vs2::CertificateProvider>
      createCertificateProvider(const std::string &config) const;

    std::unique_ptr<vs2::CertificateValidator>
      createCertificateValidator(const std::string &config) const;

    std::unique_ptr<vs::SignService>
      createSignService(const std::string &config) const;

    std::unique_ptr<vs2::VerifyService>
      createVerifyService(const std::string &config) const;

  private:
    // runtime / environment (v2)
    vanetza::Runtime *mRuntime{nullptr};
    vanetza::PositionProvider *mPositionProvider{nullptr};

    // security components (v2)
    std::unique_ptr<vs::Backend>               mBackend;
    std::unique_ptr<vs2::CertificateProvider>   mCertificateProvider;
    std::unique_ptr<vs2::CertificateValidator>  mCertificateValidator;
    std::unique_ptr<vs2::CertificateCache>      mCertificateCache;
    std::unique_ptr<vs2::SignHeaderPolicy>      mSignHeaderPolicy;

    // composite SecurityEntity (optional, if you embed/use another entity impl)
    std::unique_ptr<vs::SecurityEntity>        mEntity;
};

} // namespace artery

#endif // CUSTOM_SECURITY_ENTITY_H

