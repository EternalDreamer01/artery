namespace artery
{

class Middleware;
class NetworkInterface;
class RadioDriverBase;

class PcapCamRecorder : public omnetpp::cSimpleModule, public omnetpp::cListener
{
  protected:
    typedef std::map<simsignal_t, bool> SignalList;
    SignalList signalList;
    PacketDump packetDumper;
    PcapDump pcapDumper;
    unsigned int snaplen = 0;
    bool dumpBadFrames = false;

  public:
    PcapRecorder();
    ~PcapRecorder();

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details) override;
    virtual void recordPacket(cPacket *msg, bool l2r);
};
};

} // namespace artery
