// SybilService_v0_8.cc
// Full replacement adapted to your v0.8 headers and wrapper semantics.

#include "SybilService.h"
#include "artery/application/CaObject.h"
#include "artery/application/Asn1PacketVisitor.h"

#include <vanetza/btp/data_request.hpp>
#include <vanetza/btp/ports.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/geonet/transport_interface.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/common/byte_buffer_convertible.hpp>

#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <boost/variant/apply_visitor.hpp>

namespace artery {

Define_Module(SybilService);

void SybilService::initialize() {
    attackTimer = new omnetpp::cMessage("attackTimer");
    std::cout << "AttackTimer initialized at simTime: " << omnetpp::simTime() << std::endl;
    scheduleAt(omnetpp::simTime() + omnetpp::SimTime(0.1), attackTimer);
    std::srand(static_cast<unsigned>(std::time(nullptr)));
}

void SybilService::indicate(const vanetza::btp::DataIndication& indication, std::unique_ptr<vanetza::UpPacket> packet, const NetworkInterface& interface) {
    Asn1PacketVisitor<vanetza::asn1::Cam> visitor;
    const vanetza::asn1::Cam* cam = boost::apply_visitor(visitor, *packet);

    if (cam && cam->validate()) {
        sniffedCams.push_back(*cam);
    }

    ItsG5Service::indicate(indication, std::move(packet), interface);
}

void SybilService::handleMessage(omnetpp::cMessage* msg) {
    if (msg == attackTimer) {
        double now = omnetpp::simTime().dbl();

        // Interleaving: 180s OFF / 180s ON / 240s OFF
        // The attack only executes between second 180 and second 360
        if (now >= 180.0 && now <= 360.0) {
            executeAttack();
        }

        // Keep the timer ticking at 10Hz (0.1s)
        scheduleAt(omnetpp::simTime() + omnetpp::SimTime(0.1), attackTimer);
    }
}

void SybilService::executeAttack() {
    using namespace vanetza;

    if (sniffedCams.empty()) {
        return;
    }

    long minSpeed = LONG_MAX, maxSpeed = LONG_MIN;
    long minLat = LONG_MAX, maxLat = LONG_MIN;
    long minLon = LONG_MAX, maxLon = LONG_MIN;
    long minHeading = LONG_MAX, maxHeading = LONG_MIN;

    // Calculate boundaries based on sniffed CAMs
    for (const auto& c_wrapper : sniffedCams) {
        // c_wrapper is vanetza::asn1::Cam (wrapper). Use operator-> to access underlying CAM_t
        const auto& c = c_wrapper->cam; // alias to wrapper
        if (c.camParameters.highFrequencyContainer.present != HighFrequencyContainer_PR_basicVehicleContainerHighFrequency) {
            continue;
        }

        long s = c.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue;
        long lat = c.camParameters.basicContainer.referencePosition.latitude;
        long lon = c.camParameters.basicContainer.referencePosition.longitude;
        long h = c.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingValue;

        if (s < minSpeed) minSpeed = s;
        if (s > maxSpeed) maxSpeed = s;
        if (lat < minLat) minLat = lat;
        if (lat > maxLat) maxLat = lat;
        if (lon < minLon) minLon = lon;
        if (lon > maxLon) maxLon = lon;
        if (h < minHeading) minHeading = h;
        if (h > maxHeading) maxHeading = h;
    }

    auto safeRandom = [](long min, long max) -> long {
        if (min >= max) return min;
        return min + (std::rand() % static_cast<int>(max - min + 1));
    };

    // Generate ghosts
    for (const auto& sniffed : sniffedCams) {
        // create shared wrapper copy
        auto ghostCamPtr = std::make_shared<vanetza::asn1::Cam>(sniffed);

        // Use underlying structure through operator->: (*ghostCamPtr)->...
        if ((*ghostCamPtr)->cam.camParameters.highFrequencyContainer.present == HighFrequencyContainer_PR_basicVehicleContainerHighFrequency) {
            (*ghostCamPtr)->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue =
                safeRandom(minSpeed, maxSpeed);

            (*ghostCamPtr)->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingValue =
                safeRandom(minHeading, maxHeading);
        }

        (*ghostCamPtr)->cam.camParameters.basicContainer.referencePosition.latitude = safeRandom(minLat, maxLat);
        (*ghostCamPtr)->cam.camParameters.basicContainer.referencePosition.longitude = safeRandom(minLon, maxLon);

        // Randomize Station ID
        long randomID = safeRandom(1000, 999999);
        {
            std::ofstream f("/root/platelet/ids.log", std::ios_base::app);
            if (f) f << "Random ID " << randomID << std::endl;
        }

        // Set station id on underlying CAM header
        (*ghostCamPtr)->header.stationID = randomID;

        CaObject obj(ghostCamPtr);

        // v0.8: use DataRequestB which ItsG5Service expects
        vanetza::btp::DataRequestB request;
        request.destination_port = vanetza::btp::ports::CAM;
        request.gn.its_aid = vanetza::aid::CA;
        request.gn.transport_type = vanetza::geonet::TransportType::SHB;

        // CommunicationProfile may be defined elsewhere in your headers; if not present remove/adjust this line.
        // Try to set if available; if not, default-initialized struct is used.
#ifdef VANETZA_HAS_COMMUNICATION_PROFILE
        request.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
#endif

        // Encode ASN.1 CAM (Unaligned PER) into a ByteBuffer and wrap in convertible::byte_buffer_impl<ByteBuffer>
        ByteBuffer encoded = vanetza::asn1::encode_per(asn_DEF_CAM, &ghostCamPtr);
        std::unique_ptr<vanetza::convertible::byte_buffer> buffer_ptr(
            new vanetza::convertible::byte_buffer_impl<ByteBuffer>(std::move(encoded))
        );

        std::unique_ptr<vanetza::DownPacket> payload(new vanetza::DownPacket());
        payload->layer(vanetza::OsiLayer::Application) = std::move(buffer_ptr);

        // Submit request using ItsG5Service overload that accepts DataRequestB + DownPacket
        this->request(request, std::move(payload));
    }

    sniffedCams.clear();
}

} // namespace artery
