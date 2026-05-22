#include "SybilService.h"
#include "artery/application/CaObject.h"
#include "artery/application/Asn1PacketVisitor.h"

#include <vanetza/btp/data_request.hpp>
#include <vanetza/btp/ports.hpp>
#include <vanetza/aid.hpp>
#include <vanetza/geonet/transport_type.hpp>
#include <vanetza/geonet/communication_profile.hpp>

#include <cstdlib>
#include <ctime>
#include <cstdio>
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
    for (const auto& c : sniffedCams) {
        if (c.cam.camParameters.highFrequencyContainer.present != vanetza::asn1::HighFrequencyContainer_PR_basicVehicleContainerHighFrequency) {
            continue;
        }

        long s = c.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue;
        long lat = c.cam.camParameters.basicContainer.referencePosition.latitude;
        long lon = c.cam.camParameters.basicContainer.referencePosition.longitude;
        long h = c.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingValue;

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
    for (auto& sniffed : sniffedCams) {
        auto ghostCamPtr = std::make_shared<asn1::Cam>(sniffed);

        // Randomize Telemetry
        if (ghostCamPtr->cam.camParameters.highFrequencyContainer.present == vanetza::asn1::HighFrequencyContainer_PR_basicVehicleContainerHighFrequency) {
            ghostCamPtr->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue = safeRandom(minSpeed, maxSpeed);
            ghostCamPtr->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingValue = safeRandom(minHeading, maxHeading);
        }

        ghostCamPtr->cam.camParameters.basicContainer.referencePosition.latitude = safeRandom(minLat, maxLat);
        ghostCamPtr->cam.camParameters.basicContainer.referencePosition.longitude = safeRandom(minLon, maxLon);

        // Randomize Station ID
        long randomID = safeRandom(1000, 999999);
        std::ofstream f;
        f.open("/root/platelet/ids.log", std::ios_base::app);
        if (!f) {
            std::cerr << "Could not open file" << std::endl;
        } else {
            f << "Random ID " << randomID << std::endl;
            f.close();
        }

        ghostCamPtr->header.stationID = randomID;

        auto novoHeader = ghostCamPtr->header();
        novoHeader.station_id = randomID;
        ghostCamPtr->header(novoHeader);

        CaObject obj(ghostCamPtr);

        btp::DataRequestB request;
        request.destination_port = btp::ports::CAM;
        request.gn.its_aid = aid::CA;
        request.gn.transport_type = geonet::TransportType::SHB;
        request.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;

        using CamByteBuffer = convertible::byte_buffer_impl<asn1::Cam>;
        std::unique_ptr<geonet::DownPacket> payload{ new geonet::DownPacket() };
        std::unique_ptr<convertible::byte_buffer> buffer{ new CamByteBuffer(obj.shared_ptr()) };
        payload->layer(OsiLayer::Application) = std::move(buffer);

        // Note: MAC spoofing removed for INET 3.7 compatibility.
        // If you want to set custom L2 addresses for INET 3.7, use the INET control-info class
        // supported in your setup and call payload->getPacket()->setControlInfo(...).

        this->request(request, std::move(payload));
    }

    sniffedCams.clear();
}

} // namespace artery
