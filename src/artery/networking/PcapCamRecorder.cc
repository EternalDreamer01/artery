#include "PcapCamRecorder.h"

Define_Module(PcapRecorder);

PcapRecorder::~PcapRecorder()
{
}

PcapRecorder::PcapRecorder() : cSimpleModule(), pcapDumper()
{
}

void artery::PcapCamRecorder::initialize()
{
}

void artery::PcapCamRecorder::handleMessage(cMessage * msg)
{
}

void artery::PcapCamRecorder::finish()
{
}

void artery::PcapCamRecorder::receiveSignal(cComponent * source, simsignal_t signalID, cObject * obj, cObject * details)
{
}

void artery::PcapCamRecorder::recordPacket(cPacket * msg, bool l2r)
{
}