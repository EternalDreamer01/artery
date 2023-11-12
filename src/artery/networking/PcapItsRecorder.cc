#include "PcapItsRecorder.h"

#include<omnetpp.h>
#include <vanetza/geonet/serialization.hpp>
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include <light_pcapng_ext.h>
#include <vanetza/common/byte_buffer_source.hpp>
#include <vanetza/geonet/pdu.hpp>
#include <vanetza/geonet/pdu_conversion.hpp>
#include <vanetza/geonet/pdu_variant.hpp>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/basic_header.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <boost/iostreams/stream.hpp>
#include <vanetza/btp/header_conversion.hpp>
#include <vanetza/asn1/cam.hpp>



using namespace vanetza;

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
    light_pcapng_t *pcapng_write = light_pcapng_open(par("outputFile"), "wb");
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

void serialize_bit_vector(OutputArchive& ar, std::vector<unsigned char, std::allocator<unsigned char>> bit_vector) {
    for (auto iter = bit_vector.begin(); iter < bit_vector.end(); iter++) {
        ar << *iter;
    }
}

void PcapItsRecorder::receiveSignal(cComponent * source, simsignal_t signalID, cObject * obj, cObject * details)
{
    EV_INFO << "Received Message" << std::endl;
    const char *className = obj->getClassName();
    inet::ieee80211::Ieee80211DataFrameWithSNAP packet = *dynamic_cast<inet::ieee80211::Ieee80211DataFrameWithSNAP *>(obj);
    GeoNetPacket *test = dynamic_cast<GeoNetPacket *>(packet.getEncapsulatedPacket());
    std::unique_ptr<vanetza::PacketVariant> packet_variant = std::move(*test).extractPayload();
    vanetza::ChunkPacket chunk_packet = boost::get<vanetza::ChunkPacket>(*packet_variant);
    geonet::ExtendedPdu<geonet::ShbHeader> pdu = *dynamic_cast<geonet::ExtendedPdu<geonet::ShbHeader>*>(vanetza::geonet::pdu_cast(chunk_packet.layer(OsiLayer::Network)));
    convertible::byte_buffer * ptr = chunk_packet.layer(OsiLayer::Transport).ptr();
    convertible::byte_buffer_impl<std::vector<unsigned char, std::allocator<unsigned char>>> *ptr_cast = dynamic_cast<convertible::byte_buffer_impl<std::vector<unsigned char, std::allocator<unsigned char>>> *>(ptr);
    convertible::byte_buffer * ptr2 = chunk_packet.layer(OsiLayer::Application).ptr();
    convertible::byte_buffer_impl<asn1::Cam> *ptr_cast2 = dynamic_cast<convertible::byte_buffer_impl<asn1::Cam > *>(ptr2);
    vanetza::ByteBuffer buf;
	vanetza::byte_buffer_sink sink(buf);
    boost::iostreams::stream_buffer<vanetza::byte_buffer_sink> stream(sink);
    vanetza::OutputArchive ar(stream);

	vanetza::geonet::serialize(pdu.basic(), ar);
    vanetza::geonet::serialize(pdu.common(), ar);
    vanetza::geonet::serialize(pdu.extended(), ar);
    serialize_bit_vector(ar, ptr_cast->m_buffer);
    ByteBuffer camBuffer;
    ptr_cast2->convert(camBuffer);
    serialize_bit_vector(ar, camBuffer);
	stream.close();

    auto size = buf.size();

    uint8_t *packet_buffer = (uint8_t *)malloc(size + 14);

    uint8_t from[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t to[6] = { 0, 0, 0, 0, 0, 0};
    uint8_t protocol[2] = { 0x89, 0x47};

    memcpy(packet_buffer, from, 6);
    memcpy(packet_buffer + 6, to, 6);
    memcpy(packet_buffer + 12, protocol, 2);
    memcpy(packet_buffer + 14, &buf[0], size);

    light_pcapng_t *writer = light_pcapng_open(par("outputFile"), "ab");


	light_packet_interface pkt_interface_eth = { 0 };
    pkt_interface_eth.link_type = 1; // link_type: ETHERNET
	pkt_interface_eth.name = "interface1";
	pkt_interface_eth.description = "Interface description";
	pkt_interface_eth.timestamp_resolution = 1000000000;

	light_packet_header pkt_header1 = { 0 };
	struct timespec ts1 = { 1627228100 , 5000 };
	pkt_header1.timestamp = ts1;
	pkt_header1.captured_length = size + 14;
	pkt_header1.original_length = size + 14;
	pkt_header1.flags = 0x1; // direction indicator
	pkt_header1.dropcount = 0;
	pkt_header1.queue = 1;
	pkt_header1.comment = "Packet comment";
	light_write_packet(writer, &pkt_interface_eth, &pkt_header1, packet_buffer);
    light_pcapng_close(writer);

}
}

