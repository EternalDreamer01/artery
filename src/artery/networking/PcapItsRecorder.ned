package artery.networking;

simple PcapItsRecorder
{
    parameters:
        @display("i=block/process;is=s");
        string outputFile = default("output.pcap");
        string moduleNamePatterns = default("wlan[*] eth[*] ppp[*] ext[*]"); // space-separated list of sibling module names to listen on
        string sendingSignalNames = default("packetSentToLower"); // space-separated list of outbound packet signals to subscribe to
        string receivingSignalNames = default("packetReceivedFromLower"); // space-separated list of inbound packet signals to subscribe to
}