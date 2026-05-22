#pragma once
#include "artery/application/ItsG5Service.h"
#include <vanetza/btp/data_indication.hpp>
#include <vanetza/net/packet.hpp>
#include <omnetpp.h>
#include <vector>
#include <memory>
#include <vanetza/asn1/cam.hpp>

namespace artery {

class NetworkInterface; 
class SybilService : public ItsG5Service {
public:
    virtual void initialize() override;
    virtual void handleMessage(omnetpp::cMessage* msg) override;
    
    virtual void indicate(const vanetza::btp::DataIndication& indication, std::unique_ptr<vanetza::UpPacket> packet, const NetworkInterface& interface) override;

private:
    omnetpp::cMessage* attackTimer = nullptr;
    std::vector<vanetza::asn1::Cam> sniffedCams; 
    void executeAttack();
};

} // namespace artery