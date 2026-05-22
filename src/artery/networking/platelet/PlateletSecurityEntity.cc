#include "artery/networking/platelet/PlateletSecurityEntity.h"
#include "artery/networking/Runtime.h"
#include "artery/networking/SecurityEntity.h"
#include "artery/utility/PointerCheck.h"
#include <inet/common/ModuleAccess.h>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/v2/naive_certificate_provider.hpp>
#include <vanetza/security/v2/null_certificate_provider.hpp>
#include <vanetza/security/v2/null_certificate_validator.hpp>
#include <artery/application/platelet/StaticCertificateProvider.h>
#include "artery/application/platelet/SybilCertificateProvider.h"

namespace vs = vanetza::security;
namespace vs2 = vanetza::security::v2;

namespace artery {
    Define_Module(PlateletSecurityEntity); // <-- semicolon added

int PlateletSecurityEntity::numInitStages() const
{
    return 2;
}

void PlateletSecurityEntity::initialize(int stage)
{
    if (stage == 0) {
        mRuntime = inet::findModuleFromPar<Runtime>(par("runtimeModule"), this);
        mPositionProvider = inet::findModuleFromPar<vanetza::PositionProvider>(par("positionModule"), this);
    } else if (stage == 1){
        mBackend = vs::createBackend(par("CryptoBackend"));
        mCertificateProvider = createCertificateProvider(par("CertificateProvider"));
        mCertificateValidator = createCertificateValidator(par("CertificateValidator"));
        mCertificateCache.reset(new vs2::CertificateCache(*notNullPtr(mRuntime)));
        mSignHeaderPolicy.reset(new vs2::DefaultSignHeaderPolicy(*notNullPtr(mRuntime), *mPositionProvider));
        mEntity.reset(new vs::DelegatingSecurityEntity(createSignService(par("SignService")), createVerifyService(par("VerifyService"))));
    }
}

void PlateletSecurityEntity::finish()
{
    // free objects before runtime vanishes
    mEntity.reset();
    mSignHeaderPolicy.reset();
    mCertificateCache.reset();
    mCertificateValidator.reset();
    mCertificateProvider.reset();
    mBackend.reset();
}

std::unique_ptr<vs::Backend> PlateletSecurityEntity::createBackend(const std::string& name) const
{
    auto backend = vs::create_backend(name.c_str());
    if (!backend) {
        error("No security backend found with name \"%s\"", name.c_str());
    }
    return backend;
}

std::unique_ptr<vs2::CertificateProvider> PlateletSecurityEntity::createCertificateProvider(const std::string& name) const
{
    std::unique_ptr<vs2::CertificateProvider> certificates;
    if (name == "Null") {
        certificates.reset(new vs2::NullCertificateProvider());
    } else if (name == "Naive") {
        certificates.reset(new vs2::NaiveCertificateProvider(*notNullPtr(mRuntime)));
    } else if (name == "Static") {
        certificates.reset(new artery::StaticCertificateProvider());
    } else if (name == "Sybil") {
        certificates.reset(new artery::SybilCertificateProvider());
    } else {
        error("No certificate provider available with name \"%s\"", name.c_str());
    }
    return certificates;
}

std::unique_ptr<vs2::CertificateValidator> PlateletSecurityEntity::createCertificateValidator(const std::string& name) const
{
    // allocate as base type to match return signature
    std::unique_ptr<vs2::CertificateValidator> validator = std::make_unique<vs2::NullCertificateValidator>();

    if (name == "Null") {
        // no-op
    } else if (name == "NullOk") {
        static const vs2::CertificateValidator ok;
        ASSERT(ok);
        // call concrete API via downcast
        if (auto concrete = dynamic_cast<vs2::NullCertificateValidator*>(validator.get())) {
            concrete->certificate_check_result(ok);
        }
    } else {
        error("No certificate validator available with name \"%s\"", name.c_str());
    }

    return validator;
}

vs2::SignService PlateletSecurityEntity::createSignService(const std::string& name) const
{
    vs2::SignService sign_service;

    if (name == "straight") {
        sign_service = vs2::straight_sign_service(*notNullPtr(mCertificateProvider), *notNullPtr(mBackend), *notNullPtr(mSignHeaderPolicy));
    } else if (name == "deferred") {
        sign_service = vs2::deferred_sign_service(*notNullPtr(mCertificateProvider), *notNullPtr(mBackend), *notNullPtr(mSignHeaderPolicy));
    } else if (name == "dummy") {
        sign_service = vs2::dummy_sign_service(*notNullPtr(mRuntime), vs2::NullCertificateProvider::null_certificate());
    } else {
        error("No security sign service available with name \"%s\"", name.c_str());
    }

    return sign_service;
}

vs2::VerifyService PlateletSecurityEntity::createVerifyService(const std::string& name) const
{
    vs2::VerifyService verify_service;

    if (name == "straight") {
        verify_service = vs2::straight_verify_service(*notNullPtr(mRuntime), *notNullPtr(mCertificateProvider), *notNullPtr(mCertificateValidator),
                    *notNullPtr(mBackend), *notNullPtr(mCertificateCache), *notNullPtr(mSignHeaderPolicy), *notNullPtr(mPositionProvider));
    } else if (name == "dummy") {
        verify_service = vs2::dummy_verify_service(vs2::VerificationReport::Success, vs2::CertificateValidity::valid());
    } else {
        error("No security verify service available with name \"%s\"", name.c_str());
    }

    return verify_service;
}

vs2::EncapConfirm PlateletSecurityEntity::encapsulate_packet(vs2::EncapRequest&& request)
{
    return notNullPtr(mEntity)->encapsulate_packet(std::move(request));
}

vs2::DecapConfirm PlateletSecurityEntity::decapsulate_packet(vs2::DecapRequest&& request)
{
    return notNullPtr(mEntity)->decapsulate_packet(std::move(request));
}
}  // namespace artery

