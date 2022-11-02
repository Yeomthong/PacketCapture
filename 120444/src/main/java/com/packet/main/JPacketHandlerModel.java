package com.packet.main;

import org.jnetpcap.packet.PcapPacket;

public class JPacketHandlerModel {
	PcapPacket packet;

	int num;

	StringBuilder info = new StringBuilder();
	StringBuilder frame = new StringBuilder();
	StringBuilder ethernet = new StringBuilder();
	StringBuilder internetProtocol = new StringBuilder();
	StringBuilder transportLayer = new StringBuilder();
	StringBuilder applicationLayer = new StringBuilder();

	StringBuilder time = new StringBuilder();
	StringBuilder sourceIp = new StringBuilder();
	StringBuilder destinationIp = new StringBuilder();
	StringBuilder protocol = new StringBuilder();
	StringBuilder length = new StringBuilder();
	StringBuilder infomation = new StringBuilder();

	StringBuilder payloadHeader = new StringBuilder();
	StringBuilder payloadHex = new StringBuilder();

	public PcapPacket getPacket() {
		return packet;
	}

	public void setPacket(PcapPacket packet) {
		this.packet = packet;
	}

	public int getNum() {
		return num;
	}

	public void setNum(int num) {
		this.num = num;
	}

	public StringBuilder getInfo() {
		return info;
	}

	public void setInfo(StringBuilder info) {
		this.info = info;
	}

	public StringBuilder getFrame() {
		return frame;
	}

	public void setFrame(StringBuilder frame) {
		this.frame = frame;
	}

	public StringBuilder getEthernet() {
		return ethernet;
	}

	public void setEthernet(StringBuilder ethernet) {
		this.ethernet = ethernet;
	}

	public StringBuilder getInternetProtocol() {
		return internetProtocol;
	}

	public void setInternetProtocol(StringBuilder internetProtocol) {
		this.internetProtocol = internetProtocol;
	}

	public StringBuilder getTransportLayer() {
		return transportLayer;
	}

	public void setTransportLayer(StringBuilder transportLayer) {
		this.transportLayer = transportLayer;
	}

	public StringBuilder getApplicationLayer() {
		return applicationLayer;
	}

	public void setApplicationLayer(StringBuilder applicationLayer) {
		this.applicationLayer = applicationLayer;
	}

	public StringBuilder getTime() {
		return time;
	}

	public void setTime(StringBuilder time) {
		this.time = time;
	}

	public StringBuilder getSourceIp() {
		return sourceIp;
	}

	public void setSourceIp(StringBuilder sourceIp) {
		this.sourceIp = sourceIp;
	}

	public StringBuilder getDestinationIp() {
		return destinationIp;
	}

	public void setDestinationIp(StringBuilder destinationIp) {
		this.destinationIp = destinationIp;
	}

	public StringBuilder getProtocol() {
		return protocol;
	}

	public void setProtocol(StringBuilder protocol) {
		this.protocol = protocol;
	}

	public StringBuilder getLength() {
		return length;
	}

	public void setLength(StringBuilder length) {
		this.length = length;
	}

	public StringBuilder getInfomation() {
		return infomation;
	}

	public void setInfomation(StringBuilder infomation) {
		this.infomation = infomation;
	}

	public StringBuilder getPayloadHeader() {
		return payloadHeader;
	}

	public void setPayloadHeader(StringBuilder payloadHeader) {
		this.payloadHeader = payloadHeader;
	}

	public String getPayloadHex() {
		return packet.toHexdump().replaceAll("<" , "&lt;").replaceAll(">" , "&gt;");
	}

	public void setPayloadHex(StringBuilder payloadHex) {
		this.payloadHex = payloadHex;
	}

}