/*
 * Artery V2X Simulation Framework
 * Copyright 2014-2019 Raphael Riebl et al.
 * Licensed under GPLv2, see COPYING file for detailed license and warranty terms.
 */


#include "artery/application/CaSignedService.h"


#include "artery/application/CaObject.h"
#include "artery/application/Asn1PacketVisitor.h"
#include "artery/application/MultiChannelPolicy.h"
#include "artery/application/VehicleDataProvider.h"
#include "artery/utility/simtime_cast.h"
#include "veins/base/utils/Coord.h"
#include <boost/units/cmath.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <omnetpp/cexception.h>
#include <vanetza/btp/ports.hpp>
#include <vanetza/dcc/transmission.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/dcc/transmit_rate_control.hpp>
#include <vanetza/facilities/cam_functions.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/asn1/security/Ieee1609Dot2Data.h>
#include <vanetza/asn1/signedCam.hpp>



#include <chrono>

namespace artery
{

using namespace vanetza;
using namespace vanetza::security;

static const simsignal_t scSignalCamReceived = cComponent::registerSignal("CamReceived");
static const simsignal_t scSignalCamSent = cComponent::registerSignal("CamSent");
static const auto scLowFrequencyContainerInterval = std::chrono::milliseconds(500);


Define_Module(CaSignedService)
CaSignedService::CaSignedService() : CaService(), runtime(Clock::at("2016-08-01 00:00")), certificateProvider(runtime)
{
    EV_TRACE << "hello world!" << std::endl;
	createCertificate();
}

void CaSignedService::createCertificate() {
	/*
	auto securityBackend = vanetza::security::builtin_backends().create();
	BackendCryptoPP cryptoBackend;

    vanetza::security::ecdsa256::KeyPair keypair = cryptoBackend.generate_key_pair();

    vehiculeCert.subject_attributes.push_back(VerificationKey { keypair.public_key });
    vehiculeCert.subject_attributes.push_back(vanetza::security::SubjectAssurance());

    vehiculeCert.validity_restriction = vanetza::security::StartAndEndValidity();

	std::string name = "testCert";
	std::vector<unsigned char> v(name.begin(), name.end());
    
    vanetza::security::SubjectInfo subjectInfo;
    subjectInfo.subject_type = vanetza::security::SubjectType::Root_CA;
    subjectInfo.subject_name = v;

    vehiculeCert.subject_info = subjectInfo;
    vehiculeCert.signer_info = vanetza::security::calculate_hash(vehiculeCert);

    auto certificateByteBuffer = vanetza::security::convert_for_signing(vehiculeCert);


    vehiculeCert.signature = securityBackend.get()->sign_data(keypair.private_key, certificateByteBuffer);

    vehiculeCertificate = vehiculeCert;
    vehiculeKeyPair = keypair;
	*/
}

void CaSignedService::trigger()
{
    Enter_Method("trigger");
    checkTriggeringConditions(simTime());
}

std::string get_hex_string(unsigned char *buf, int size) {
	std::string str;
	for (int i = 0; i < size; i++) {
		str.append("\\x");
		char hexString[20];
		sprintf(hexString, "%x", buf[i]);
		str.append(hexString);
	}
	return str;
}

void CaSignedService::indicate(const vanetza::btp::DataIndication& ind, std::unique_ptr<vanetza::UpPacket> packet)
{
	Enter_Method("indicate");
	Asn1PacketVisitor<vanetza::asn1::SignedCam> visitor;
	const vanetza::asn1::SignedCam* signedCam = boost::apply_visitor(visitor, *packet);

	EV_INFO << getName() << ": Received a secure message" << std::endl;

	if (signedCam) {
		Ieee1609Dot2Content *content = (*visitor.shared_wrapper.get())->content;
		OCTET_STRING obj_string = content->choice.signedData->tbsData->payload->data->content->choice.unsecuredData;
		
		if (content->choice.signedData->signer.present == SignerIdentifier_PR::SignerIdentifier_PR_certificate) {
			Certificate_t *cert = (Certificate_t *)content->choice.signedData->signer.choice.certificate.list.array[0];
			EV_INFO << "Received a certificate" << std::endl;
		}
		
		OCTET_STRING signature = content->choice.signedData->signature.choice.ecdsaNistP256Signature.sSig;
		
		std::string signatureStr(get_hex_string(signature.buf, signature.size));

		EV_INFO << getName() << ": Received a signed CAM packet. signature: " << signatureStr << std::endl;
		
		std::vector<uint8_t> vec;
		vec.insert(vec.end(), obj_string.buf, obj_string.buf+obj_string.size);
		ByteBuffer camByteBuffer(vec);
		vanetza::asn1::Cam cam;
		cam.decode(camByteBuffer);

		if (cam.validate()) {
			EV_INFO << getName() << ": Cam packet is valid!" << std::endl;
			CaObject obj(std::move(cam));
			emit(scSignalCamReceived, &obj);
			mLocalDynamicMap->updateAwareness(obj);
		}

		}
}

void CaSignedService::checkTriggeringConditions(const SimTime& T_now)
{
	// provide variables named like in EN 302 637-2 V1.3.2 (section 6.1.3)
	SimTime& T_GenCam = mGenCam;
	const SimTime& T_GenCamMin = mGenCamMin;
	const SimTime& T_GenCamMax = mGenCamMax;
	const SimTime T_GenCamDcc = mDccRestriction ? genCamDcc() : T_GenCamMin;
	const SimTime T_elapsed = T_now - mLastCamTimestamp;



	if (T_elapsed >= T_GenCamDcc) {
		if (mFixedRate) {
			sendSignedCam(T_now);
		} else if (checkHeadingDelta() || checkPositionDelta() || checkSpeedDelta()) {
			sendSignedCam(T_now);
			T_GenCam = std::min(T_elapsed, T_GenCamMax); /*< if middleware update interval is too long */
			mGenCamLowDynamicsCounter = 0;
		} else if (T_elapsed >= T_GenCam) {
			sendSignedCam(T_now);
			if (++mGenCamLowDynamicsCounter >= mGenCamLowDynamicsLimit) {
				T_GenCam = T_GenCamMax;
			}
		}
	}
}

Certificate_t *convertCertificateHighToLow(vanetza::security::Certificate cert) {

	Certificate_t *good_cert = vanetza::asn1::allocate<Certificate_t>();

	good_cert->version = 3;
	good_cert->type = CertificateType::CertificateType_explicit;

	good_cert->issuer.present = IssuerIdentifier_PR::IssuerIdentifier_PR_sha256AndDigest;
	good_cert->issuer.choice.sha256AndDigest = *OCTET_STRING_new_fromBuf(&asn_DEF_IssuerIdentifier, (char *)&boost::get<HashedId8>(cert.signer_info), 8);

	good_cert->toBeSigned.id.present = CertificateId_PR::CertificateId_PR_none;
	good_cert->toBeSigned.cracaId.buf = (uint8_t *)std::calloc(3, 1);
	good_cert->toBeSigned.cracaId.size = 3;

	const ValidityRestriction *sev = cert.get_restriction(ValidityRestrictionType::Time_Start_And_End);
	good_cert->toBeSigned.validityPeriod.start = boost::get<StartAndEndValidity>(sev)->start_validity;
	good_cert->toBeSigned.validityPeriod.duration.present = Duration_PR::Duration_PR_seconds;
	good_cert->toBeSigned.validityPeriod.duration.choice.seconds = boost::get<StartAndEndValidity>(sev)->end_validity / 1000 - boost::get<StartAndEndValidity>(sev)->start_validity / 1000;

	const VerificationKey *key = boost::get<VerificationKey>(cert.get_attribute(SubjectAttributeType::Verification_Key));
	good_cert->toBeSigned.verifyKeyIndicator.present = VerificationKeyIndicator_PR::VerificationKeyIndicator_PR_verificationKey;
	good_cert->toBeSigned.verifyKeyIndicator.choice.verificationKey.present = PublicVerificationKey_PR::PublicVerificationKey_PR_ecdsaNistP256;
	good_cert->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.present = EccP256CurvePoint_PR::EccP256CurvePoint_PR_uncompressedP256;
	EccPoint pkey = boost::get<ecdsa_nistp256_with_sha256>(key->key).public_key;
	good_cert->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.uncompressedP256.x = *OCTET_STRING_new_fromBuf(&asn_DEF_EccP256CurvePoint, (char *)boost::get<Uncompressed>(pkey).x.data(), boost::get<Uncompressed>(pkey).x.size());
	good_cert->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.uncompressedP256.y = *OCTET_STRING_new_fromBuf(&asn_DEF_EccP256CurvePoint, (char *)boost::get<Uncompressed>(pkey).y.data(), boost::get<Uncompressed>(pkey).y.size());


	good_cert->signature = vanetza::asn1::allocate<Signature_t>();
	good_cert->signature->present = Signature_PR::Signature_PR_ecdsaNistP256Signature;
	EcdsaSignature signature = boost::get<EcdsaSignature>(cert.signature);
	good_cert->signature->choice.ecdsaNistP256Signature.rSig.present = EccP256CurvePoint_PR::EccP256CurvePoint_PR_x_only;
	good_cert->signature->choice.ecdsaNistP256Signature.rSig.choice.x_only = *OCTET_STRING_new_fromBuf(&asn_DEF_EccP256CurvePoint, (char *)boost::get<X_Coordinate_Only>(signature.R).x.data(), boost::get<X_Coordinate_Only>(signature.R).x.size());
	good_cert->signature->choice.ecdsaNistP256Signature.sSig = *OCTET_STRING_new_fromBuf(&asn_DEF_EcdsaP256Signature, (char *)signature.s.data(), signature.s.size());;

	return good_cert;
}

void CaSignedService::sendSignedCam(const SimTime& T_now)
{
	bool send_certificate = true;
	uint16_t genDeltaTimeMod = countTaiMilliseconds(mTimer->getTimeFor(mVehicleDataProvider->updated()));
	auto cam = createCooperativeAwarenessMessage(*mVehicleDataProvider, genDeltaTimeMod);

	mLastCamPosition = mVehicleDataProvider->position();
	mLastCamSpeed = mVehicleDataProvider->speed();
	mLastCamHeading = mVehicleDataProvider->heading();
	mLastCamTimestamp = T_now;
	if (T_now - mLastLowCamTimestamp >= artery::simtime_cast(scLowFrequencyContainerInterval)) {
		addLowFrequencyContainer(cam, par("pathHistoryLength"));
		mLastLowCamTimestamp = T_now;
	}


	using namespace vanetza;
	btp::DataRequestB request;
	request.destination_port = btp::ports::CAM;
	request.gn.its_aid = aid::CA;
	request.gn.transport_type = geonet::TransportType::SHB;
	request.gn.maximum_lifetime = geonet::Lifetime { geonet::Lifetime::Base::One_Second, 1 };
	request.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP2));
	request.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;

	ByteBuffer camByteBuffer = cam.encode();

	CaObject obj(std::move(cam));
	emit(artery::scSignalCamSent, &obj);


	using CamByteBuffer = convertible::byte_buffer_impl<asn1::Cam>;
	std::unique_ptr<convertible::byte_buffer> buffer { new CamByteBuffer(obj.shared_ptr()) };

    vanetza::security::Payload securedPayload;
    securedPayload.type = vanetza::security::PayloadType::Signed;
    securedPayload.data = vanetza::CohesivePacket(vanetza::buffer_copy(buffer.get()), OsiLayer::Application);

    security::SecuredMessage securedMessage;

    securedMessage.payload = securedPayload;
	securedMessage.header_fields.push_back(convert_time64(Clock::at("2016-08-01 00:00")));
	securedMessage.header_fields.push_back(aid::CA);


	auto securedMessageByteBuffer = security::convert_for_signing(securedMessage, securedMessage.trailer_fields);
	auto securityBackend = security::create_backend("default");
	auto backendObject = securityBackend.get();
	auto signature = backendObject->sign_data(certificateProvider.own_private_key(), securedMessageByteBuffer);
	securedMessage.trailer_fields.push_back(signature);

	std::unique_ptr<geonet::DownPacket> payload { new geonet::DownPacket() };

	asn1::SignedCam correctSignedMessage;
	correctSignedMessage->protocolVersion = 3;

	correctSignedMessage->content = vanetza::asn1::allocate<Ieee1609Dot2Content_t>();
	correctSignedMessage->content->present = Ieee1609Dot2Content_PR::Ieee1609Dot2Content_PR_signedData;

	correctSignedMessage->content->choice.signedData = vanetza::asn1::allocate<SignedData_t>();
	correctSignedMessage->content->choice.signedData->hashId = 0;
	if (!send_certificate){
		correctSignedMessage->content->choice.signedData->signer.present =  SignerIdentifier_PR::SignerIdentifier_PR_digest;
		HashedId8 hashed = calculate_hash(certificateProvider.own_certificate());
		correctSignedMessage->content->choice.signedData->signer.choice.digest = *OCTET_STRING_new_fromBuf(&asn_DEF_HashedId8, (char *)hashed.data(), hashed.size());
	} else {
		correctSignedMessage->content->choice.signedData->signer.present = SignerIdentifier_PR::SignerIdentifier_PR_certificate;
		
		ASN_SEQUENCE_ADD(&correctSignedMessage->content->choice.signedData->signer.choice.certificate, (void *)convertCertificateHighToLow(certificateProvider.own_certificate()));
	}
	
	correctSignedMessage->content->choice.signedData->signature.present = Signature_PR::Signature_PR_ecdsaNistP256Signature;
	correctSignedMessage->content->choice.signedData->signature.choice.ecdsaNistP256Signature.rSig.present = EccP256CurvePoint_PR::EccP256CurvePoint_PR_x_only;
	correctSignedMessage->content->choice.signedData->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only = *OCTET_STRING_new_fromBuf(&asn_DEF_EccP256CurvePoint, (char *)boost::get<X_Coordinate_Only>(signature.R).x.data(), boost::get<X_Coordinate_Only>(signature.R).x.size());
	correctSignedMessage->content->choice.signedData->signature.choice.ecdsaNistP256Signature.sSig = *OCTET_STRING_new_fromBuf(&asn_DEF_EcdsaP256Signature, (char *)signature.s.data(), signature.s.size());

	correctSignedMessage->content->choice.signedData->tbsData = vanetza::asn1::allocate<ToBeSignedData_t>();
	correctSignedMessage->content->choice.signedData->tbsData->headerInfo.psid = aid::CA;
	correctSignedMessage->content->choice.signedData->tbsData->headerInfo.generationTime = vanetza::asn1::allocate<Time64_t>();
	asn_uint642INTEGER(correctSignedMessage->content->choice.signedData->tbsData->headerInfo.generationTime, convert_time64(Clock::at("2016-08-01 00:00")));
	correctSignedMessage->content->choice.signedData->tbsData->payload = vanetza::asn1::allocate<SignedDataPayload_t>();
	correctSignedMessage->content->choice.signedData->tbsData->payload->data = vanetza::asn1::allocate<Ieee1609Dot2Data_t>();
	correctSignedMessage->content->choice.signedData->tbsData->payload->data->protocolVersion = 3;
	correctSignedMessage->content->choice.signedData->tbsData->payload->data->content = vanetza::asn1::allocate<Ieee1609Dot2Content_t>();
	correctSignedMessage->content->choice.signedData->tbsData->payload->data->content->present = Ieee1609Dot2Content_PR::Ieee1609Dot2Content_PR_unsecuredData;
	correctSignedMessage->content->choice.signedData->tbsData->payload->data->content->choice.unsecuredData = *OCTET_STRING_new_fromBuf(&asn_DEF_Ieee1609Dot2Data, (char *)&camByteBuffer[0], camByteBuffer.size());

	auto signedCamSharedPtr = std::make_shared<asn1::SignedCam>(correctSignedMessage);

	using SignedCamByteBuffer = convertible::byte_buffer_impl<asn1::SignedCam>;
	std::unique_ptr<convertible::byte_buffer> signedBuffer { new SignedCamByteBuffer(signedCamSharedPtr) };

	

	//std::string signatureStr(signature.s.begin(), signature.s.end());

	EV_INFO << getName() << ": Send a signed CAM packet! signature: " << get_hex_string(&signature.s[0], signature.s.size()) << std::endl;


	payload->layer(OsiLayer::Application) = std::move(signedBuffer);
	this->request(request, std::move(payload));
}


}  // namespace artery
