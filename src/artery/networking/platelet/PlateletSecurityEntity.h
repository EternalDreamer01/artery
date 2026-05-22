#ifndef CUSTOM_SECURITY_ENTITY_H
#define CUSTOM_SECURITY_ENTITY_H

#include <omnetpp/csimplemodule.h>
#include <vanetza/runtime.hpp>
#include <vanetza/position_provider.hpp>
#include <vanetza/security/v2/backend.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/certificate_provider.hpp>
#include <vanetza/security/v2/certificate_validator.hpp>
#include <vanetza/security/v2/security_entity.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <vanetza/security/v2/verify_service.hpp>
#include <memory>
#include <string>

namespace artery {

class PlateletSecurityEntity :
    public omnetpp::cSimpleModule,
    public vanetza::security::v2::SecurityEntity
{
  protected:
    // OMNeT++ lifecycle
    int numInitStages() const override { return 3; }
    void initialize(int stage) override;
    void finish() override;

    // SecurityEntity overrides (v2)
    vanetza::security::v2::EncapConfirm encapsulate_packet(vanetza::security::v2::EncapRequest&& req) override;
    vanetza::security::v2::DecapConfirm  decapsulate_packet(vanetza::security::v2::DecapRequest&& req) override;

  protected:
    // Factory helpers adapted to v2 API
    std::unique_ptr<vanetza::security::v2::Backend>
      createBackend(const std::string &config) const;

    std::unique_ptr<vanetza::security::v2::CertificateProvider>
      createCertificateProvider(const std::string &config) const;

    std::unique_ptr<vanetza::security::v2::CertificateValidator>
      createCertificateValidator(const std::string &config) const;

    std::unique_ptr<vanetza::security::v2::SignService>
      createSignService(const std::string &config) const;

    std::unique_ptr<vanetza::security::v2::VerifyService>
      createVerifyService(const std::string &config) const;

  private:
    // runtime / environment (v2)
    vanetza::Runtime *mRuntime{nullptr};
    vanetza::PositionProvider *mPositionProvider{nullptr};

    // security components (v2)
    std::unique_ptr<vanetza::security::v2::Backend>               mBackend;
    std::unique_ptr<vanetza::security::v2::CertificateProvider>   mCertificateProvider;
    std::unique_ptr<vanetza::security::v2::CertificateValidator>  mCertificateValidator;
    std::unique_ptr<vanetza::security::v2::CertificateCache>      mCertificateCache;
    std::unique_ptr<vanetza::security::v2::SignHeaderPolicy>      mSignHeaderPolicy;

    // composite SecurityEntity (optional, if you embed/use another entity impl)
    std::unique_ptr<vanetza::security::v2::SecurityEntity>        mEntity;
};

} // namespace artery

#endif // CUSTOM_SECURITY_ENTITY_H

