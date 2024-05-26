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
#include <vanetza/security/secured_message.hpp>


using namespace vanetza;

namespace artery {
PcapItsRecorder::PcapItsRecorder(): cSimpleModule() {

}

Define_Module(PcapItsRecorder);

    light_packet_interface geonet_interface = {
        .link_type = 1,
        .name = (char*)"wireless lan",
        .description = (char*)"interface used for transmitting geonet packet",
        .timestamp_resolution = 1000000000
    };

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
        light_write_interface_block(pcapng_write, &geonet_interface);

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

    template<typename T>
    void serialize_layer(OutputArchive ar, ChunkPacket chunk_packet, OsiLayer osi_layer) {
        convertible::byte_buffer * layer_buffer = chunk_packet.layer(osi_layer).ptr();
        convertible::byte_buffer_impl<T>* layer_buffer_impl = dynamic_cast<convertible::byte_buffer_impl<T> *>(layer_buffer);

        ByteBuffer layer_byte_buffer;
        layer_buffer->convert(layer_byte_buffer);
        serialize_bit_vector(ar, layer_byte_buffer);
    }

    ByteBuffer serialize_packet(ChunkPacket packet) {
        
        vanetza::ByteBuffer buf;
        vanetza::byte_buffer_sink sink(buf);
        boost::iostreams::stream_buffer<vanetza::byte_buffer_sink> stream(sink);
        OutputArchive ar(stream);

        geonet::ExtendedPdu<geonet::ShbHeader> pdu = *dynamic_cast<geonet::ExtendedPdu<geonet::ShbHeader>*>(vanetza::geonet::pdu_cast(packet.layer(OsiLayer::Network)));

        vanetza::geonet::serialize(pdu.basic(), ar);
        if (pdu.secured()) vanetza::security::serialize(ar, *pdu.secured());
        vanetza::geonet::serialize(pdu.common(), ar);
        vanetza::geonet::serialize(pdu.extended(), ar);

        serialize_layer<std::vector<unsigned char, std::allocator<unsigned char>>>(ar, packet, OsiLayer::Transport);
        serialize_layer<asn1::Cam>(ar, packet, OsiLayer::Application);

        stream.close();
        return buf;
    }

    void write_packet(const char *filename, uint8_t *packet_buffer, size_t size) {

        light_pcapng_t *writer = light_pcapng_open(filename, "ab");
        light_packet_header pkt_header1 = { 0 };
        
        auto current_time = simTime();
        struct timespec ts1 = { current_time.inUnit(omnetpp::SimTimeUnit::SIMTIME_S) , current_time.remainderForUnit(omnetpp::SimTimeUnit::SIMTIME_S).inUnit(omnetpp::SimTimeUnit::SIMTIME_NS) };;
        
        pkt_header1.timestamp = ts1;
        pkt_header1.captured_length = size + 14;
        pkt_header1.original_length = size + 14;
        pkt_header1.comment = (char *)"Packet comment";
        
        light_write_packet(writer, &geonet_interface, &pkt_header1, packet_buffer);
        
        light_pcapng_close(writer);
    }

    void PcapItsRecorder::receiveSignal(cComponent * source, simsignal_t signalID, cObject * obj, cObject * details)
    {
        EV_INFO << "Received Message" << std::endl;
        const char *className = obj->getClassName();
        inet::ieee80211::Ieee80211DataFrameWithSNAP packet = *dynamic_cast<inet::ieee80211::Ieee80211DataFrameWithSNAP *>(obj);
        auto from_address = packet.getTransmitterAddress();
        auto to_address = packet.getReceiverAddress();

        GeoNetPacket *geonet_packet = dynamic_cast<GeoNetPacket *>(packet.getEncapsulatedPacket());
        std::unique_ptr<vanetza::PacketVariant> packet_variant = std::move(*geonet_packet).extractPayload();
        vanetza::ChunkPacket chunk_packet = boost::get<vanetza::ChunkPacket>(*packet_variant);

        ByteBuffer buffer = serialize_packet(chunk_packet);
        size_t size = buffer.size();
        
        pcap_packet_header packet_header;

        from_address.getAddressBytes(packet_header.from_addr);
        to_address.getAddressBytes(packet_header.to_addr);

        uint8_t *packet_buffer = (uint8_t *)malloc(size + 14);

        memcpy(packet_buffer, &packet_header, sizeof(pcap_packet_header));
        memcpy(packet_buffer + sizeof(pcap_packet_header), &buffer[0], size);

        write_packet(par("outputFile"), packet_buffer, size);
    }
}

