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
#include <vanetza/security/certificate.hpp>
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


void CaSignedService::logMessage(SecuredMessage message) {
	std::fstream logFile;
	std::ostringstream logFilePathStr;
	logFilePathStr << "results/" << getParentModule()->getParentModule()->getFullName() << ".log";
	logFilePath = logFilePathStr.str();
	logFile.open(logFilePath, std::ios::app);
	logFile << "[" << simTime() << "]" << " Cam Message sent : ";
	logFile << "{ contains certificate : " << (boost::get<HashedId8>(boost::get<SignerInfo>(message.header_field(HeaderFieldType::Signer_Info))) == nullptr ? "true" : "false");
	EcdsaSignature *signature = boost::get<EcdsaSignature>(boost::get<vanetza::security::Signature>(message.trailer_field(TrailerFieldType::Signature)));
	logFile << ", signature : " << get_hex_string(&signature->s[0], signature->s.size()).c_str() << " }" << std::endl;
	logFile.close();
}

ecdsa256::PublicKey convertKey(ecdsa_nistp256_with_sha256 wrong_key) {

	ecdsa256::PublicKey pkey;
	Uncompressed point = boost::get<Uncompressed>(wrong_key.public_key);

	std::copy_n(point.x.begin(), pkey.x.size(), pkey.x.begin());
	std::copy_n(point.y.begin(), pkey.y.size(), pkey.y.begin());

	return pkey;
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
    	InputArchive ar(outstream);

		SecuredMessage received_secured_message;

		deserialize(ar, received_secured_message);

		SignerInfo *signer_info = boost::get<SignerInfo>(received_secured_message.header_field(HeaderFieldType::Signer_Info));

		auto test = boost::get<HashedId8>(signer_info);
		struct vanetza::security::Certificate certificate;

		if (boost::get<HashedId8>(signer_info)) {
			// TODO not implemented yet
		} else if (boost::get<std::list<struct vanetza::security::Certificate>>(signer_info) != nullptr) {
			certificate = *boost::get<std::list<struct vanetza::security::Certificate>>(signer_info)->begin();
		}

		EcdsaSignature *signature = boost::get<EcdsaSignature>(boost::get<vanetza::security::Signature>(received_secured_message.trailer_field(TrailerFieldType::Signature)));
		ecdsa256::PublicKey pkey = convertKey(boost::get<ecdsa_nistp256_with_sha256>(boost::get<VerificationKey>(certificate.get_attribute(SubjectAttributeType::Verification_Key))->key));

		auto securityBackend = security::create_backend("default");
		auto backendObject = securityBackend.get();
		std::list<TrailerField> emptyTrailerField;
		if (backendObject->verify_data(pkey, convert_for_signing(received_secured_message, emptyTrailerField), *signature)) {
			asn1::Cam cam;
			cam.decode(boost::get<CohesivePacket>(received_secured_message.payload.data).buffer());

			if (cam.validate()) {
				EV_INFO << getName() << ": Cam packet is valid!" << std::endl;
				CaObject obj(std::move(cam));
				emit(scSignalCamReceived, &obj);
				mLocalDynamicMap->updateAwareness(obj);
			}
		} else {
			EV_WARN << "Signature is not valid!" << std::endl;
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

SecuredMessage CaSignedService::createSignedCam(ByteBuffer camByteBuffer, bool includeCertificate) {

	SecuredMessage secured_message;
	secured_message.header_fields.push_front(vanetza::aid::CA);
	secured_message.header_fields.push_front((uint64_t)simTime().raw());

	secured_message.payload.type = PayloadType::Signed;
	secured_message.payload.data = CohesivePacket(camByteBuffer, OsiLayer::Application);

	SignerInfo signerInfo;

	if (includeCertificate) {
		std::list<struct vanetza::security::Certificate> certificateList;
		certificateList.push_back(certificateProvider.own_certificate());
		signerInfo = certificateList;
	} else {
		signerInfo = calculate_hash(certificateProvider.own_certificate());
	}

	secured_message.header_fields.push_front(signerInfo);
	
	ByteBuffer secured_message_byte_buffer = convert_for_signing(secured_message, secured_message.trailer_fields);
	auto securityBackend = security::create_backend("default");
	auto backendObject = securityBackend.get();
	auto signature = backendObject->sign_data(certificateProvider.own_private_key(), secured_message_byte_buffer);

	ecdsa_nistp256_with_sha256 wrong_type_pkey = boost::get<ecdsa_nistp256_with_sha256>(boost::get<VerificationKey>(certificateProvider.own_certificate().get_attribute(SubjectAttributeType::Verification_Key))->key);
	ecdsa256::PublicKey pkey;
	Uncompressed point = boost::get<Uncompressed>(wrong_type_pkey.public_key);

	std::copy_n(point.x.begin(), pkey.x.size(), pkey.x.begin());
	std::copy_n(point.y.begin(), pkey.y.size(), pkey.y.begin());

	auto valid = backendObject->verify_data(pkey, secured_message_byte_buffer, signature);

	secured_message.trailer_fields.push_front(signature);

	return secured_message;
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

	std::unique_ptr<geonet::DownPacket> payload { new geonet::DownPacket() };
	SecuredMessage securedMessage = createSignedCam(camByteBuffer, true);	


	ByteBuffer buf;
	byte_buffer_sink sink(buf);
    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream);

	serialize(ar, securedMessage);
	stream.close();

	logMessage(securedMessage);

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