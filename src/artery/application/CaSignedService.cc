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
CaSignedService::CaSignedService() : CaService(), runtime(Clock::at("2016-08-01 00:00")), certificateProvider(runtime), certificateCache(runtime)
{
	system("rm results/logs/*"); // remove all previously log files
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
	logFilePathStr << "results/logs/" << getParentModule()->getParentModule()->getFullName() << ".log";
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

SecuredMessage CaSignedService::deserialize_secured_message(vanetza::ChunkPacket *packet ) {

		vanetza::convertible::byte_buffer *ptr = packet->layer(OsiLayer::Application).ptr();
		auto impl = dynamic_cast<vanetza::convertible::byte_buffer_impl<ByteBuffer>*>(ptr);

		ByteBuffer buffer(impl->m_buffer);
		byte_buffer_source source(buffer);
    	boost::iostreams::stream_buffer<byte_buffer_source> outstream(source);
    	InputArchive ar(outstream);
		SecuredMessage received_secured_message;

		deserialize(ar, received_secured_message);

		return received_secured_message;
}

void CaSignedService::consumeSignedCam(vanetza::UpPacket *packet) {

		SecuredMessage secured_message = deserialize_secured_message(boost::get<ChunkPacket>(packet));

		SignerInfo *signer_info = boost::get<SignerInfo>(secured_message.header_field(HeaderFieldType::Signer_Info));
		
		std::list<HashedId3> *requested_certificate_list = boost::get<std::list<HashedId3>>(secured_message.header_field(HeaderFieldType::Request_Unrecognized_Certificate));

		if (requested_certificate_list) {
			HashedId3 own_hash = truncate(calculate_hash(certificateProvider.own_certificate()));
			for (std::list<HashedId3>::iterator it = requested_certificate_list->begin(); it != requested_certificate_list->end(); it++) {
				if (*it == own_hash) {
					certificateRequested = true;
				}
			}
		}

		struct vanetza::security::Certificate certificate;

		// check if we got full certificate or only a hash of it
		if (boost::get<HashedId8>(signer_info)) {
			// if we got only the hash of it we check if it is already in the cache
			HashedId8 certificate_hash = *boost::get<HashedId8>(signer_info);
			std::list<struct vanetza::security::Certificate> match_list = certificateCache.lookup(certificate_hash, SubjectType::Authorization_Ticket);
			if (match_list.size() == 0) {
				// if it isn't we request it in the next cam
				certificateToRequest.push_back(truncate(certificate_hash));
				return;
			}
			certificate = *match_list.begin();
		} else if (boost::get<std::list<struct vanetza::security::Certificate>>(signer_info) != nullptr) {
			// if we got the complete certificate we use it and store it in the cache
			certificate = *boost::get<std::list<struct vanetza::security::Certificate>>(signer_info)->begin();
			certificateCache.insert(certificate);
		}

		EcdsaSignature *signature = boost::get<EcdsaSignature>(boost::get<vanetza::security::Signature>(secured_message.trailer_field(TrailerFieldType::Signature)));
		ecdsa256::PublicKey pkey = convertKey(boost::get<ecdsa_nistp256_with_sha256>(boost::get<VerificationKey>(certificate.get_attribute(SubjectAttributeType::Verification_Key))->key));

		auto securityBackend = security::create_backend("default");
		auto backendObject = securityBackend.get();
		std::list<TrailerField> emptyTrailerField;

		// verify signature of incoming cam packet
		if (backendObject->verify_data(pkey, convert_for_signing(secured_message, emptyTrailerField), *signature)) {
			asn1::Cam cam;
			// Decode u8 vector into an asn1 Cam object
			cam.decode(boost::get<CohesivePacket>(secured_message.payload.data).buffer());

			// consume packet to update awereness if packet is valid
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

void CaSignedService::indicate(const vanetza::btp::DataIndication& ind, std::unique_ptr<vanetza::UpPacket> packet)
{
	Enter_Method("indicate");

	EV_INFO << getName() << ": Received a secure message" << std::endl;

	consumeSignedCam(packet.get());
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
		lastCertificateSend = simTime().inUnit(SimTimeUnit::SIMTIME_MS);
	} else {
		signerInfo = calculate_hash(certificateProvider.own_certificate());
	}

	secured_message.header_fields.push_front(signerInfo);

	if (certificateToRequest.size() > 0) {
		secured_message.header_fields.push_front(certificateToRequest);
		certificateToRequest.clear();
		certificateRequested = false;
	}
	
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
	SecuredMessage securedMessage = createSignedCam(camByteBuffer, ((simTime().inUnit(SimTimeUnit::SIMTIME_MS) - lastCertificateSend > 1000) || certificateRequested) ? true : false);	


	ByteBuffer buf;
	byte_buffer_sink sink(buf);
    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream);

	serialize(ar, securedMessage);
	stream.close();

	logMessage(securedMessage);

	payload->layer(OsiLayer::Application) = std::move(buf);
	this->request(request, std::move(payload));
}
}  // namespace artery