/*
* Artery V2X Simulation Framework
* Copyright 2014-2019 Raphael Riebl et al.
* Licensed under GPLv2, see COPYING file for detailed license and warranty terms.
*/

#include "artery/application/CaObject.h"
#include "artery/application/CaServiceZombie.h"
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
#include <vanetza/dcc/transmit_rate_control.hpp>
#include <vanetza/facilities/cam_functions.hpp>
#include <chrono>

namespace artery
{

using namespace omnetpp;


static const simsignal_t scSignalCamReceivedZombie = cComponent::registerSignal("CamReceived");
static const simsignal_t scSignalCamSentZombie = cComponent::registerSignal("CamSent");
static const auto scLowFrequencyContainerIntervalZombie = std::chrono::milliseconds(500);


Define_Module(CaServiceZombie)

CaServiceZombie::CaServiceZombie() :
        mGenCamMin { 100, SIMTIME_MS },
        mGenCamMax { 1000, SIMTIME_MS },
        mGenCam(mGenCamMax),
        mGenCamLowDynamicsCounter(0),
        mGenCamLowDynamicsLimit(3)
{
}

void CaServiceZombie::initialize()
{
    ItsG5BaseService::initialize();
    mNetworkInterfaceTable = &getFacilities().get_const<NetworkInterfaceTable>();
    mVehicleDataProvider = &getFacilities().get_const<VehicleDataProvider>();
    mTimer = &getFacilities().get_const<Timer>();
    mLocalDynamicMap = &getFacilities().get_mutable<artery::LocalDynamicMap>();

    // avoid unreasonable high elapsed time values for newly inserted vehicles
    mLastCamTimestamp = simTime();

    // first generated CAM shall include the low frequency container
    mLastLowCamTimestamp = mLastCamTimestamp - artery::simtime_cast(scLowFrequencyContainerIntervalZombie);

    // generation rate boundaries
    mGenCamMin = par("minInterval");
    mGenCamMax = par("maxInterval");
    mGenCam = mGenCamMax;

    // vehicle dynamics thresholds
    mHeadingDelta = vanetza::units::Angle { par("headingDelta").doubleValue() * vanetza::units::degree };
    mPositionDelta = par("positionDelta").doubleValue() * vanetza::units::si::meter;
    mSpeedDelta = par("speedDelta").doubleValue() * vanetza::units::si::meter_per_second;

    mDccRestriction = par("withDccRestriction");
    mFixedRate = par("fixedRate");

    // look up primary channel for CA
    mPrimaryChannel = getFacilities().get_const<MultiChannelPolicy>().primaryChannel(vanetza::aid::CA);
}

void CaServiceZombie::trigger()
{
    Enter_Method("trigger");
    checkTriggeringConditions(simTime());
}

void CaServiceZombie::indicate(const vanetza::btp::DataIndication& ind, std::unique_ptr<vanetza::UpPacket> packet)
{
    Enter_Method("indicate");
    Asn1PacketVisitor<vanetza::asn1::Cam> visitor;
    const vanetza::asn1::Cam* cam = boost::apply_visitor(visitor, *packet);

    EV_INFO << getName() << ": Received a CAM packet!" << std::endl;

    if (cam && cam->validate()) {
        CaObject obj = visitor.shared_wrapper;
        emit(scSignalCamReceivedZombie, &obj);
        mLocalDynamicMap->updateAwareness(obj);
    }
}

void CaServiceZombie::checkTriggeringConditions(const SimTime& T_now)
{

    // provide variables named like in EN 302 637-2 V1.3.2 (section 6.1.3)
    SimTime& T_GenCam = mGenCam;
    const SimTime& T_GenCamMin = mGenCamMin;
    const SimTime& T_GenCamMax = mGenCamMax;
    const SimTime T_GenCamDcc = mDccRestriction ? genCamDcc() : T_GenCamMin;
    const SimTime T_elapsed = T_now - mLastCamTimestamp;

    if(par("isZombie")) {
        sendCam(T_now);
    } else {

        if (T_elapsed >= T_GenCamDcc) {
            if (mFixedRate) {
                sendCam(T_now);
            } else if (checkHeadingDelta() || checkPositionDelta() || checkSpeedDelta()) {
                sendCam(T_now);
                T_GenCam = std::min(T_elapsed, T_GenCamMax); /*< if middleware update interval is too long */
                mGenCamLowDynamicsCounter = 0;
            } else if (T_elapsed >= T_GenCam) {
                sendCam(T_now);
                if (++mGenCamLowDynamicsCounter >= mGenCamLowDynamicsLimit) {
                    T_GenCam = T_GenCamMax;
                }
            }
        }
    }

}

bool CaServiceZombie::checkHeadingDelta() const
{
    return !vanetza::facilities::similar_heading(mLastCamHeading, mVehicleDataProvider->heading(), mHeadingDelta);
}

bool CaServiceZombie::checkPositionDelta() const
{
    return (distance(mLastCamPosition, mVehicleDataProvider->position()) > mPositionDelta);
}

bool CaServiceZombie::checkSpeedDelta() const
{
    return abs(mLastCamSpeed - mVehicleDataProvider->speed()) > mSpeedDelta;
}

void CaServiceZombie::sendCam(const SimTime& T_now)
{
    uint16_t genDeltaTimeMod = countTaiMilliseconds(mTimer->getTimeFor(mVehicleDataProvider->updated()));
    auto cam = createCooperativeAwarenessMessage(*mVehicleDataProvider, genDeltaTimeMod);

    mLastCamPosition = mVehicleDataProvider->position();
    mLastCamSpeed = mVehicleDataProvider->speed();
    mLastCamHeading = mVehicleDataProvider->heading();
    mLastCamTimestamp = T_now;
    if (T_now - mLastLowCamTimestamp >= artery::simtime_cast(scLowFrequencyContainerIntervalZombie)) {
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

    CaObject obj(std::move(cam));
    emit(scSignalCamSentZombie, &obj);

    using CamByteBuffer = convertible::byte_buffer_impl<asn1::Cam>;
    std::unique_ptr<geonet::DownPacket> payload { new geonet::DownPacket() };
    std::unique_ptr<convertible::byte_buffer> buffer { new CamByteBuffer(obj.shared_ptr()) };
    payload->layer(OsiLayer::Application) = std::move(buffer);
    this->request(request, std::move(payload));
}

SimTime CaServiceZombie::genCamDcc()
{
    // network interface may not be ready yet during initialization, so look it up at this later point
    auto netifc = mNetworkInterfaceTable->select(mPrimaryChannel);
    vanetza::dcc::TransmitRateThrottle* trc = netifc ? netifc->getDccEntity().getTransmitRateThrottle() : nullptr;
    if (!trc) {
        throw cRuntimeError("No DCC TRC found for CA's primary channel %i", mPrimaryChannel);
    }

    static const vanetza::dcc::TransmissionLite ca_tx(vanetza::dcc::Profile::DP2, 0);
    vanetza::Clock::duration interval = trc->interval(ca_tx);
    SimTime dcc { std::chrono::duration_cast<std::chrono::milliseconds>(interval).count(), SIMTIME_MS };
    return std::min(mGenCamMax, std::max(mGenCamMin, dcc));
}





} // namespace artery
