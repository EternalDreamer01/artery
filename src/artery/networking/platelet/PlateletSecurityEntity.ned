package artery.networking.platelet;

import artery.networking.ISecurityEntity;

simple PlateletSecurityEntity like ISecurityEntity
{
    @class(PlateletSecurityEntity);
        string runtimeModule;
        string positionModule;

        string CryptoBackend = default("Null");
        string CertificateProvider = default("Null");
        string CertificateValidator = default("NullOk");
        string SignService = default("dummy");
        string VerifyService = default("dummy");
}
