#!/bin/sh

rpl -RF "vanetza/security/certificate.hpp" "vanetza/security/v2/certificate.hpp" src/
rpl -RF "vanetza/security/certificate_cache.hpp" "vanetza/security/v2/certificate_cache.hpp" src/
rpl -RF "vanetza/security/certificate_provider.hpp" "vanetza/security/v2/certificate_provider.hpp" src/
rpl -RF "vanetza/security/certificate_validator.hpp" "vanetza/security/v2/certificate_validator.hpp" src/
rpl -RF "vanetza/security/sign_header_policy.hpp" "vanetza/security/v2/sign_header_policy.hpp" src/
rpl -RF "vanetza/security/sign_service.hpp" "vanetza/security/v2/sign_service.hpp" src/

rpl -RF "vanetza/security/naive_certificate_provider.hpp" "vanetza/security/v2/naive_certificate_provider.hpp" src/
rpl -RF "vanetza/security/null_certificate_provider.hpp" "vanetza/security/v2/null_certificate_provider.hpp" src/
rpl -RF "vanetza/security/null_certificate_validator.hpp" "vanetza/security/v2/null_certificate_validator.hpp" src/

rpl -RF "vanetza/security/trust_store.hpp" "vanetza/security/v2/trust_store.hpp" src/

# rpl -RF "= vanetza::security;" "= vanetza::security::v2;" src/