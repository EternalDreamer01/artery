#include "PcapItsRecorder.h"

#include<omnetpp.h>

namespace artery {
PcapItsRecorder::PcapItsRecorder(): cSimpleModule() {

}

Define_Module(PcapItsRecorder);


void PcapItsRecorder::initialize()
{

    signalList.clear();

    {
        cStringTokenizer signalTokenizer(par("sendingSignalNames"));

        while (signalTokenizer.hasMoreTokens())
            signalList[registerSignal(signalTokenizer.nextToken())] = true;
    }

    {
        cStringTokenizer signalTokenizer(par("receivingSignalNames"));

        while (signalTokenizer.hasMoreTokens())
            signalList[registerSignal(signalTokenizer.nextToken())] = false;
    }

    const char *moduleNames = par("moduleNamePatterns");
    cStringTokenizer moduleTokenizer(moduleNames);

    while (moduleTokenizer.hasMoreTokens()) {

        bool found = false;
        std::string mname(moduleTokenizer.nextToken());
        bool isAllIndex = (mname.length() > 3) && mname.rfind("[*]") == mname.length() - 3;

        if (isAllIndex)
            mname.replace(mname.length() - 3, 3, "");

        for (cModule::SubmoduleIterator i(getParentModule()); !i.end(); i++) {
            cModule *submod = *i;
            if (0 == strcmp(isAllIndex ? submod->getName() : submod->getFullName(), mname.c_str())) {
                found = true;

                for (auto & elem : signalList) {
                    if (!submod->isSubscribed(elem.first, this)) {
                        submod->subscribe(elem.first, this);
                        EV << "PcapRecorder " << getFullPath() << " subscribed to "
                           << submod->getFullPath() << ":" << getSignalName(elem.first) << endl;
                    }
                }
            }
        }
    }
}

void PcapItsRecorder::handleMessage(cMessage * msg)
{
}

void PcapItsRecorder::finish()
{
}

void PcapItsRecorder::receiveSignal(cComponent * source, simsignal_t signalID, cObject * obj, cObject * details)
{
    EV_INFO << "Received Message" << std::endl;
    GeoNetPacket *message = dynamic_cast<GeoNetPacket *>(obj);
}
}

