package main;

import java.util.ArrayList;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class Jcap {

	private int num;

	public int getNum() {
		return num;
	}

	public void setNum(int num) {
		this.num = num;
	}

	public static ArrayList<PcapIf> choicePacket() {
		ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>(); // 장치의 배열 리스트
		StringBuilder errbuf = new StringBuilder(); // 장치의 데이터를 저장하기 위한 문자열 빌더
		int r = Pcap.findAllDevs(allDevs, errbuf); // 컴퓨터에 연결된 모든 장치를 찾아봄

		if (r == Pcap.NOT_OK || allDevs.isEmpty()) { // Pcap에 오류가 발생했거나 연결된 장치가 없는 경우
			System.out.println("네트워크 장치를 찾을 수 없습니다. " + errbuf.toString()); // 문자열 빌더에 오류 메세지 출력
		}

		long currentNum = 0;
		int currentCnt = 0;
			System.out.println("[네트워크 장비 탐색 성공]");
			int i = 0;
			for (PcapIf device : allDevs) {
				String description = (device.getDescription() != null) ? device.getDescription() : "장비에 대한 설명이 없습니다.";
				System.out.printf("[%d번]: %s [%s]\n", i++, device.getName(), description);
			}
			System.out.print("원하는 장치의 번호를 입력해주세요(종료:-1): ");
			return allDevs;
		
	}

	public static PcapPacket packet(int num) {

		ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>(); // 장치의 배열 리스트
		StringBuilder errbuf = new StringBuilder(); // 장치의 데이터를 저장하기 위한 문자열 빌더
		int r = Pcap.findAllDevs(allDevs, errbuf); // 컴퓨터에 연결된 모든 장치를 찾아봄
		
		/*
		if (r == Pcap.NOT_OK || allDevs.isEmpty()) { // Pcap에 오류가 발생했거나 연결된 장치가 없는 경우
			System.out.println("네트워크 장치를 찾을 수 없습니다. " + errbuf.toString()); // 문자열 빌더에 오류 메세지 출력
			return;
		}
		*/

		long currentNum = 0;
		int currentCnt = 0;
		while (true) {
			System.out.println("[네트워크 장비 탐색 성공]");
			int i = 0;
			
			
			long start = System.currentTimeMillis();
			
			PcapIf device = allDevs.get(num);
			System.out.printf("선택한 장치: %s\n", (device.getDescription() != null) ? device.getDescription() : device.getName());

			int snaplen = 64 * 1024;
			int flags = Pcap.MODE_PROMISCUOUS;
			int timeout = 1;

			Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

			if (pcap == null) {
				System.out.printf("패킷 캡쳐를 위해 네트워크 장치를 여는 데에 실패했습니다. 오류: " + errbuf.toString() + "\n");
				continue;
			}
			while (true) {
				try {
					Ethernet eth = new Ethernet();
					Ip4 ip = new Ip4();
					Tcp tcp = new Tcp();
					Udp udp = new Udp();
					Icmp icmp = new Icmp();
					Payload payload = new Payload();
					PcapHeader header = new PcapHeader(JMemory.POINTER);
					JBuffer buf = new JBuffer(JMemory.POINTER);
					int id = JRegistry.mapDLTToId(pcap.datalink());
					long end = System.currentTimeMillis();
					if (end - start > 20 * 1000) {
						System.out.println("대기시간 초과");
						break;
					}
					
					
					
					// 패킷 정보 출력 부분이옵니다.
					while ((pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK)) {
						PcapPacket packet = new PcapPacket(header, buf);
						packet.scan(id);
						int len = 0;
						String info = "info\n";
						String pload = "payload\n";
						if (packet.getFrameNumber() - currentNum <= 10) {
							System.out.printf("[ #%d ]\n", packet.getFrameNumber() - currentCnt);
							if (packet.hasHeader(eth)) {
								// System.out.printf("출발지 MAC 주소 = %s 도착지 MAC 주소= %s\n",
								// FormatUtils.mac(eth.source()), FormatUtils.mac(eth.destination()));
								len += eth.getLength();
								info += "출발지 MAC 주소 = ";
								info += FormatUtils.mac(eth.source());
								info += " ";
								info += "도착지 MAC 주소 = ";
								info += FormatUtils.mac(eth.destination());
								info += "\n";
								pload += "MAC\n";
								pload += eth.toHexdump();
								pload += "";
							}
							if (packet.hasHeader(ip)) {
								System.out.printf("출발지 IP 주소 = %s 도착지 IP 주소= %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
								len += ip.getLength();
								pload += "IP\n";
								pload += ip.toHexdump();
								pload += "";
							}
							if (packet.hasHeader(tcp)) {
								// System.out.printf("출발지 포트 번호 = %d 도착지 포트 번호= %d\n",
								// tcp.source(), tcp.destination());
								// System.out.print("seq: "+tcp.seq()+", ack: "+tcp.ack()+"\n");
								// System.out.print(tcp+"\n");
								info += "출발지 포트 번호 = ";
								info += tcp.source();
								info += " ";
								info += "도착지 포트 번호 = ";
								info += tcp.destination();
								info += " ";
								info += "seq: ";
								info += tcp.seq();
								info += " ";
								info += "ack: ";
								info += tcp.ack();
								info += "\n";
								len += tcp.getLength();
								pload += "TCP\n";
								pload += tcp.toHexdump();
								pload += "";
							}
							if (packet.hasHeader(udp)) {
								// System.out.printf("출발지 포트 번호 = %d 도착지 포트 번호= %d\n",
								// udp.source(), udp.destination());
								info += "출발지 포트 번호 = ";
								info += udp.source();
								info += " ";
								info += "도착지 포트 번호 = ";
								info += udp.destination();
								info += "\n";
								len += udp.getLength();
								pload += "UDP\n";
								pload += udp.toHexdump();
								pload += "";
							}
							if (packet.hasHeader(icmp)) {
								len += icmp.getLength();
								pload += "ICMP\n";
								pload += icmp.toHexdump();
								pload += "";
							}
							if (packet.hasHeader(payload)) {
								System.out.print(payload);
								len += payload.getLength();
								pload += "Payload\n";
								pload += payload.toHexdump();
								pload += "";
							}
							System.out.printf("길이: %d\n", len);
							System.out.print(info);
							System.out.print(pload);
						} else {
							currentNum = packet.getFrameNumber();
							currentCnt += 1;
							System.out.println("탐색 완료");
							break;
						}
						return packet;
					}
					
					break;
				} catch (NullPointerException e) {
				}
			}
		}
		
	}
}