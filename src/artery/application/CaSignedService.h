/*
* Artery V2X Simulation Framework
* Copyright 2014-2019 Raphael Riebl et al.
* Licensed under GPLv2, see COPYING file for detailed license and warranty terms.
*/

#ifndef ARTERY_CASIGNEDSERVICE_H_
#define ARTERY_CASIGNEDSERVICE_H_

#include <fstream>
#include "artery/application/CaService.h"
#include "artery/application/SignedCam.hpp"
#include <vanetza/security/certificate.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/secured_message.hpp>


namespace artery
{


class CaSignedService : public CaService
{
	public:
		CaSignedService();
		void trigger() override;
		void indicate(const vanetza::btp::DataIndication& ind, std::unique_ptr<vanetza::UpPacket> packet) override;
	protected:
		void checkTriggeringConditions(const omnetpp::SimTime&);
		void sendSignedCam(const omnetpp::SimTime&);
    	vanetza::asn1::Cam *createCooperativeAwarenessMessagePointer(const VehicleDataProvider& vdp, uint16_t genDeltaTime);
		vanetza::security::SecuredMessage createSignedCam(vanetza::ByteBuffer camByteBuffer, bool includeCertificate);
		void logMessage(vanetza::security::SecuredMessage message);
		void consumeSignedCam(vanetza::UpPacket *packet);
		vanetza::security::SecuredMessage deserialize_secured_message(vanetza::ChunkPacket *packet);

		vanetza::ManualRuntime runtime;
		vanetza::security::NaiveCertificateProvider certificateProvider;
		vanetza::security::CertificateCache certificateCache;
		std::list<vanetza::security::HashedId3> certificateToRequest;

	private:
		std::string logFilePath;
		uint64_t lastCertificateSend;
		bool certificateRequested;
};

} // namespace artery

#endif /* ARTERY_CASIGNEDSERVICE_H_ */
