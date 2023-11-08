#include "PcapItsRecorder.h"

#include<omnetpp.h>
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include <light_pcapng_ext.h>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <boost/iostreams/stream.hpp>



namespace artery {
PcapItsRecorder::PcapItsRecorder(): cSimpleModule() {

}

Define_Module(PcapItsRecorder);


void PcapItsRecorder::initialize()
{
    EV << "Initializing pcapitsrecorder module" << std::endl;
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
    light_pcapng_t *pcapng_write = light_pcapng_open("output.pcapng", "wb");
	light_packet_interface pkt_interface_eth = { 0 };
    pkt_interface_eth.link_type = 1; // link_type: ETHERNET
	pkt_interface_eth.name = "interface1";
	pkt_interface_eth.description = "Interface description";
	pkt_interface_eth.timestamp_resolution = 1000000000;
    light_write_interface_block(pcapng_write, &pkt_interface_eth);

    light_pcapng_close(pcapng_write);

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
    const char *className = obj->getClassName();
    inet::ieee80211::Ieee80211DataFrameWithSNAP packet = *dynamic_cast<inet::ieee80211::Ieee80211DataFrameWithSNAP *>(obj);
    GeoNetPacket *test = dynamic_cast<GeoNetPacket *>(packet.getEncapsulatedPacket());
    std::unique_ptr<vanetza::PacketVariant> packet_variant = std::move(*test).extractPayload();
    vanetza::ChunkPacket chunk_packet = boost::get<vanetza::ChunkPacket>(*packet_variant);
    vanetza::ByteBuffer buf;
	vanetza::byte_buffer_sink sink(buf);
    boost::iostreams::stream_buffer<vanetza::byte_buffer_sink> stream(sink);
    vanetza::OutputArchive ar(stream);

	serialize(ar, *packet_variant);
	stream.close();

    auto size = buf.size();
    light_pcapng_t *writer = light_pcapng_open("output.pcapng", "ab");


	light_packet_interface pkt_interface_eth = { 0 };
    pkt_interface_eth.link_type = 1; // link_type: ETHERNET
	pkt_interface_eth.name = "interface1";
	pkt_interface_eth.description = "Interface description";
	pkt_interface_eth.timestamp_resolution = 1000000000;

	light_packet_header pkt_header1 = { 0 };
	struct timespec ts1 = { 1627228100 , 5000 };
	pkt_header1.timestamp = ts1;
	pkt_header1.captured_length = size;
	pkt_header1.original_length = size;
	pkt_header1.flags = 0x1; // direction indicator
	pkt_header1.dropcount = 0;
	pkt_header1.queue = 1;
	pkt_header1.comment = "Packet comment";
	light_write_packet(writer, &pkt_interface_eth, &pkt_header1, (uint8_t*)&buf);
    light_pcapng_close(writer);

}
}

