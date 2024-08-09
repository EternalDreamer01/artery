package artery.networking.platelet;

simple PcapItsRecorder
{
    parameters:
        @display("i=block/process;is=s");
        string outputFile = default("output.pcapng");
        string moduleNamePatterns = default("wlan[*]"); // space-separated list of sibling module names to listen on
        string sendingSignalNames = default("packetSentToLower"); // space-separated list of outbound packet signals to subscribe to
        string receivingSignalNames = default(""); // space-separated list of inbound packet signals to subscribe to
}