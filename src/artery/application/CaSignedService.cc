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
#include <boost/iostreams/stream.hpp>
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
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/common/byte_buffer_source.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/asn1/security/Ieee1609Dot2Data.h>


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
	system("rm results/*");
    EV_TRACE << "hello world!" << std::endl;
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


void CaSignedService::logMessage(asn1::SignedCam message) {
	std::fstream logFile;
	std::ostringstream logFilePathStr;
	auto signed_date = message->content->choice.signedData;
	logFilePathStr << "results/" << getParentModule()->getParentModule()->getFullName() << ".log";
	logFilePath = logFilePathStr.str();
	logFile.open(logFilePath, std::ios::app);
	logFile << "[" << simTime() << "]" << " Cam Message sent : ";
	logFile << "{ contains certificate : " << (signed_date->signer.present == SignerIdentifier_PR::SignerIdentifier_PR_certificate ? "true" : "false");
	logFile << ", signature : " << get_hex_string(signed_date->signature.choice.ecdsaNistP256Signature.sSig.buf, signed_date->signature.choice.ecdsaNistP256Signature.sSig.size).c_str() << " }" << std::endl;
	logFile.close();
}

void encodeArray(OutputArchive ar, unsigned char *arr, size_t size) {
	for (int i = 0; i < size; i++) {
		ar << arr[i];
	}
} 

ByteBuffer encodeToSign(const asn1::SignedCam *message) {

	ByteBuffer buf;
    byte_buffer_sink sink(buf);

    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream);

	SignedData *signedData = (*message)->content->choice.signedData;

	ar << (*message)->protocolVersion;
	ar << 3; // length of header field;
	if (signedData->signer.present == SignerIdentifier_PR_certificate) {
		Certificate_t *cert = (Certificate_t *)signedData->signer.choice.certificate.list.array[0];
		ar << cert->version;
		ar << cert->type;
		encodeArray(ar, cert->issuer.choice.sha256AndDigest.buf, cert->issuer.choice.sha256AndDigest.size);
	} else {
		encodeArray(ar, signedData->signer.choice.digest.buf, signedData->signer.choice.digest.size);
	}

	encodeArray(ar, signedData->tbsData->headerInfo.generationTime->buf, signedData->tbsData->headerInfo.generationTime->size);
	ar << signedData->tbsData->headerInfo.psid;

	ar << signedData->tbsData->payload->data->protocolVersion;
	ar << static_cast<int>(signedData->tbsData->payload->data->content->present);


	encodeArray(ar, signedData->tbsData->payload->data->content->choice.unsecuredData.buf, signedData->tbsData->payload->data->content->choice.unsecuredData.size);

	ar << 1; // length of trail field 
	ar << static_cast<int>(signedData->signature.present);

	stream.close();
	return buf;
}

void CaSignedService::indicate(const vanetza::btp::DataIndication& ind, std::unique_ptr<vanetza::UpPacket> packet)
{
	Enter_Method("indicate");
	Asn1PacketVisitor<vanetza::asn1::SignedCam> visitor;
	const vanetza::asn1::SignedCam* signedCam = boost::apply_visitor(visitor, *packet);

	EV_INFO << getName() << ": Received a secure message" << std::endl;

	if (signedCam) {
		Ieee1609Dot2Content *content = (*visitor.shared_wrapper.get())->content;
		
		ByteBuffer buffer(content->choice.unsecuredData.buf, content->choice.unsecuredData.buf + content->choice.unsecuredData.size);

		byte_buffer_source source(buffer);
    	boost::iostreams::stream_buffer<byte_buffer_source> outstream(source);
		
    	InputArchive iar(outstream);

		SecuredMessage test_des;

		deserialize(iar, test_des);

		asn1::Cam cam;

		cam.decode(boost::get<CohesivePacket>(test_des.payload.data).buffer());
		/*
		Certificate_t *cert;

		if (content->choice.signedData->signer.present == SignerIdentifier_PR::SignerIdentifier_PR_certificate) {
			cert = (Certificate_t *)content->choice.signedData->signer.choice.certificate.list.array[0];
			EV_INFO << "Received a certificate" << std::endl;
		} else {
			// TODO: Not implemented yet
		}

		ecdsa256::PublicKey p_key;
		auto key = cert->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256;
		std::copy_n(key.choice.uncompressedP256.x.buf, 32, p_key.x.begin());
		std::copy_n(key.choice.uncompressedP256.y.buf, 32, p_key.y.begin());
		
		EcdsaSignature signature;
		std::vector<uint8_t> s(content->choice.signedData->signature.choice.ecdsaNistP256Signature.sSig.buf, content->choice.signedData->signature.choice.ecdsaNistP256Signature.sSig.buf + cert->signature->choice.ecdsaNistP256Signature.sSig.size);
		signature.s = s;
		std::vector<uint8_t> r(content->choice.signedData->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only.buf, content->choice.signedData->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only.buf + cert->signature->choice.ecdsaNistP256Signature.rSig.choice.x_only.size);
		X_Coordinate_Only x;
		x.x = r;
		signature.R = x;

		auto securityBackend = security::create_backend("default");
		auto backendObject = securityBackend.get();
		
		if (backendObject->verify_data(p_key, encodeToSign(visitor.shared_wrapper.get()), signature)) {

			vanetza::asn1::Cam cam;
			OCTET_STRING obj_string = content->choice.signedData->tbsData->payload->data->content->choice.unsecuredData;

			std::vector<uint8_t> vec;
			vec.insert(vec.end(), obj_string.buf, obj_string.buf+obj_string.size);
			ByteBuffer camByteBuffer(vec);
			cam.decode(camByteBuffer);

			if (cam.validate()) {
				EV_INFO << getName() << ": Cam packet is valid!" << std::endl;
				CaObject obj(std::move(cam));
				emit(scSignalCamReceived, &obj);
				mLocalDynamicMap->updateAwareness(obj);
			}
		} else {
			EV_WARN << "Signature is not valid!" << std::endl;
		}
		*/
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

	Certificate_t *ll_certificate = vanetza::asn1::allocate<Certificate_t>();

	ll_certificate->version = 3;
	ll_certificate->type = CertificateType::CertificateType_explicit;

	ll_certificate->issuer.present = IssuerIdentifier_PR::IssuerIdentifier_PR_sha256AndDigest;
	ll_certificate->issuer.choice.sha256AndDigest = *OCTET_STRING_new_fromBuf(&asn_DEF_IssuerIdentifier, (char *)&boost::get<HashedId8>(cert.signer_info), 8);

	ll_certificate->toBeSigned.id.present = CertificateId_PR::CertificateId_PR_none;
	ll_certificate->toBeSigned.cracaId.buf = (uint8_t *)std::calloc(3, 1);
	ll_certificate->toBeSigned.cracaId.size = 3;

	const ValidityRestriction *sev = cert.get_restriction(ValidityRestrictionType::Time_Start_And_End);
	ll_certificate->toBeSigned.validityPeriod.start = boost::get<StartAndEndValidity>(sev)->start_validity;
	ll_certificate->toBeSigned.validityPeriod.duration.present = Duration_PR::Duration_PR_seconds;
	ll_certificate->toBeSigned.validityPeriod.duration.choice.seconds = boost::get<StartAndEndValidity>(sev)->end_validity / 1000 - boost::get<StartAndEndValidity>(sev)->start_validity / 1000;

	const VerificationKey *key = boost::get<VerificationKey>(cert.get_attribute(SubjectAttributeType::Verification_Key));
	ll_certificate->toBeSigned.verifyKeyIndicator.present = VerificationKeyIndicator_PR::VerificationKeyIndicator_PR_verificationKey;
	ll_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.present = PublicVerificationKey_PR::PublicVerificationKey_PR_ecdsaNistP256;
	ll_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.present = EccP256CurvePoint_PR::EccP256CurvePoint_PR_uncompressedP256;
	EccPoint pkey = boost::get<ecdsa_nistp256_with_sha256>(key->key).public_key;
	ll_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.uncompressedP256.x = *OCTET_STRING_new_fromBuf(&asn_DEF_EccP256CurvePoint, (char *)boost::get<Uncompressed>(pkey).x.data(), boost::get<Uncompressed>(pkey).x.size());
	ll_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.uncompressedP256.y = *OCTET_STRING_new_fromBuf(&asn_DEF_EccP256CurvePoint, (char *)boost::get<Uncompressed>(pkey).y.data(), boost::get<Uncompressed>(pkey).y.size());


	ll_certificate->signature = vanetza::asn1::allocate<Signature_t>();
	ll_certificate->signature->present = Signature_PR::Signature_PR_ecdsaNistP256Signature;
	EcdsaSignature signature = boost::get<EcdsaSignature>(cert.signature);
	ll_certificate->signature->choice.ecdsaNistP256Signature.rSig.present = EccP256CurvePoint_PR::EccP256CurvePoint_PR_x_only;
	ll_certificate->signature->choice.ecdsaNistP256Signature.rSig.choice.x_only = *OCTET_STRING_new_fromBuf(&asn_DEF_EccP256CurvePoint, (char *)boost::get<X_Coordinate_Only>(signature.R).x.data(), boost::get<X_Coordinate_Only>(signature.R).x.size());
	ll_certificate->signature->choice.ecdsaNistP256Signature.sSig = *OCTET_STRING_new_fromBuf(&asn_DEF_EcdsaP256Signature, (char *)signature.s.data(), signature.s.size());;

	return ll_certificate;
}

asn1::SignedCam CaSignedService::createSignedCam(ByteBuffer camByteBuffer) {

	asn1::SignedCam signedMessage;
	signedMessage->protocolVersion = 3;

	bool send_certificate = true;

	signedMessage->content = vanetza::asn1::allocate<Ieee1609Dot2Content_t>();
	signedMessage->content->present = Ieee1609Dot2Content_PR::Ieee1609Dot2Content_PR_signedData;

	signedMessage->content->choice.signedData = vanetza::asn1::allocate<SignedData_t>();
	signedMessage->content->choice.signedData->hashId = 0;
	if (!send_certificate){
		signedMessage->content->choice.signedData->signer.present =  SignerIdentifier_PR::SignerIdentifier_PR_digest;
		HashedId8 hashed = calculate_hash(certificateProvider.own_certificate());
		signedMessage->content->choice.signedData->signer.choice.digest = *OCTET_STRING_new_fromBuf(&asn_DEF_HashedId8, (char *)hashed.data(), hashed.size());
	} else {
		signedMessage->content->choice.signedData->signer.present = SignerIdentifier_PR::SignerIdentifier_PR_certificate;
		
		ASN_SEQUENCE_ADD(&signedMessage->content->choice.signedData->signer.choice.certificate, (void *)convertCertificateHighToLow(certificateProvider.own_certificate()));
	}
	
		signedMessage->content->choice.signedData->tbsData = vanetza::asn1::allocate<ToBeSignedData_t>();
	signedMessage->content->choice.signedData->tbsData->headerInfo.psid = aid::CA;
	signedMessage->content->choice.signedData->tbsData->headerInfo.generationTime = vanetza::asn1::allocate<Time64_t>();
	asn_uint642INTEGER(signedMessage->content->choice.signedData->tbsData->headerInfo.generationTime, convert_time64(Clock::at("2016-08-01 00:00")));
	signedMessage->content->choice.signedData->tbsData->payload = vanetza::asn1::allocate<SignedDataPayload_t>();
	signedMessage->content->choice.signedData->tbsData->payload->data = vanetza::asn1::allocate<Ieee1609Dot2Data_t>();
	signedMessage->content->choice.signedData->tbsData->payload->data->protocolVersion = 3;
	signedMessage->content->choice.signedData->tbsData->payload->data->content = vanetza::asn1::allocate<Ieee1609Dot2Content_t>();
	signedMessage->content->choice.signedData->tbsData->payload->data->content->present = Ieee1609Dot2Content_PR::Ieee1609Dot2Content_PR_unsecuredData;
	signedMessage->content->choice.signedData->tbsData->payload->data->content->choice.unsecuredData = *OCTET_STRING_new_fromBuf(&asn_DEF_Ieee1609Dot2Data, (char *)&camByteBuffer[0], camByteBuffer.size());

	signedMessage->content->choice.signedData->signature.present = Signature_PR::Signature_PR_ecdsaNistP256Signature;
	return signedMessage;
}

void CaSignedService::sendSignedCam(const SimTime& T_now)
{
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
	/*

	asn1::SignedCam signedCam = createSignedCam(camByteBuffer);

	auto securityBackend = security::create_backend("default");
	auto backendObject = securityBackend.get();
	auto signature = backendObject->sign_data(certificateProvider.own_private_key(), encodeToSign(&signedCam));

	signedCam->content->choice.signedData->signature.choice.ecdsaNistP256Signature.rSig.present = EccP256CurvePoint_PR::EccP256CurvePoint_PR_x_only;
	signedCam->content->choice.signedData->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only = *OCTET_STRING_new_fromBuf(&asn_DEF_EccP256CurvePoint, (char *)boost::get<X_Coordinate_Only>(signature.R).x.data(), boost::get<X_Coordinate_Only>(signature.R).x.size());
	signedCam->content->choice.signedData->signature.choice.ecdsaNistP256Signature.sSig = *OCTET_STRING_new_fromBuf(&asn_DEF_EcdsaP256Signature, (char *)signature.s.data(), signature.s.size());

	logMessage(signedCam);



	*/
	std::unique_ptr<geonet::DownPacket> payload { new geonet::DownPacket() };
	SecuredMessage secured_message;

	secured_message.payload.type = PayloadType::Signed;
	secured_message.payload.data = CohesivePacket(camByteBuffer, OsiLayer::Application);

	secured_message.header_fields.push_front((uint64_t)simTime().raw());
	ByteBuffer buf;
	byte_buffer_sink sink(buf);
    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream);

	serialize(ar, secured_message);

	stream.close();

	byte_buffer_source source(buf);
    boost::iostreams::stream_buffer<byte_buffer_source> outstream(source);
    InputArchive iar(outstream);

	SecuredMessage test_des;

	deserialize(iar, test_des);


	asn1::SignedCam wrapper;
	wrapper->protocolVersion = 3;

	wrapper->content = vanetza::asn1::allocate<Ieee1609Dot2Content_t>();
	wrapper->content->present = Ieee1609Dot2Content_PR::Ieee1609Dot2Content_PR_unsecuredData;
	wrapper->content->choice.unsecuredData = *OCTET_STRING_new_fromBuf(&asn_DEF_Ieee1609Dot2Content, (const char *)buf.data(), buf.size());

	auto wrapperSharedPtr = std::make_shared<asn1::SignedCam>(wrapper);

	using SignedCamByteBuffer = convertible::byte_buffer_impl<asn1::SignedCam>;
	std::unique_ptr<convertible::byte_buffer> wrapperBuffer { new SignedCamByteBuffer(wrapperSharedPtr) };

	payload->layer(OsiLayer::Application) = std::move(wrapperBuffer);
	this->request(request, std::move(payload));
}
}  // namespace artery