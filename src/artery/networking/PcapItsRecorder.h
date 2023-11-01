#ifndef PCAP_ITS_RECORDER_H
#define PCAP_ITS_RECORDER_H

#include <omnetpp.h>
#include <artery/networking/GeoNetPacket.h>

using namespace omnetpp;
namespace artery {
class PcapItsRecorder : public cSimpleModule, protected cListener {
  public:
    PcapItsRecorder();
  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details) override;
        typedef std::map<simsignal_t, bool> SignalList;
    SignalList signalList;
};
}


#endif