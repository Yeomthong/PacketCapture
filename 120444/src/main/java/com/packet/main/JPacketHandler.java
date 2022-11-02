package com.packet.main;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * 
 * JPacketHandler
 * 
 * @author SooHyun Park 2021.12.04
 * 
 *         구성 1) console창에서 출력되는 printf 2) web상에서 출력되는 model
 *
 */
public class JPacketHandler implements PcapPacketHandler<String> {

	Pcap pcap;
	

	public JPacketHandler() {

	}

	public JPacketHandler(Pcap pcap) {
		this.pcap = pcap;
	}

	// model을 저장해 List로 반환할 예정
	private ArrayList<JPacketHandlerModel> modelList = new ArrayList<JPacketHandlerModel>();

	public ArrayList<JPacketHandlerModel> getModelList() {
		return modelList;
	}

	public void setModelList(ArrayList<JPacketHandlerModel> modelList) {
		this.modelList = modelList;
	}
	
	
	int modelNum = 0;
	
	public void nextPacket(PcapPacket packet, String user) {

		/**
		 * model 선언
		 */
		JPacketHandlerModel model = new JPacketHandlerModel();
		
		model.num = modelNum++;

		// model에 packet 저장
		model.packet = packet;

		Udp udp = new Udp();
//		if (!packet.hasHeader(udp)) {
//			return;
//		}
		Scanner scanner=new Scanner(System.in);
		int selectProtocol=-1;
		while((selectProtocol>=4)||(selectProtocol<0)) {
		System.out.print("원하는 프로토콜을 선택해주세요(0: 전체, 1: TCP, 2: UDP, 3: ICMP): ");
		selectProtocol = scanner.nextInt();
		if ((selectProtocol>=4)||(selectProtocol<0)) {
			System.out.println("다시 입력해주세요.");
			continue;
		}
		}
		/**
		 * 테이블에 띄울 정보들
		 */
		Ethernet eth = new Ethernet();
		Ip4 ip = new Ip4();
		Tcp tcp = new Tcp();
		Icmp icmp = new Icmp();
		Payload payload = new Payload();

		int len = 0;
		String info = "info\n";
		String pload = "payload\n";
		String protocol = "";
		
		System.out.println("frameNumber------------------------------------------");
		System.out.println(packet.getFrameNumber());
		
		switch(selectProtocol) {
		case 0:
		if (packet.hasHeader(eth)) {
			// System.out.printf("출발지 MAC 주소 = %s 도착지 MAC 주소= %s\n",
			// FormatUtils.mac(eth.source()), FormatUtils.mac(eth.destination()));
			len += eth.getLength();
			info += "출발지 MAC 주소=";
			info += FormatUtils.mac(eth.source());
			info += " ";
			info += "도착지 MAC 주소=";
			info += FormatUtils.mac(eth.destination());
			info += " ";
		}
		if (packet.hasHeader(ip)) {
			System.out.printf("출발지 IP 주소 = %s 도착지 IP 주소= %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
			model.sourceIp.append(String.format("%s", FormatUtils.ip(ip.source())));
			model.destinationIp.append(String.format("%s", FormatUtils.ip(ip.destination())));
			len += ip.getLength();
		}
		if (packet.hasHeader(tcp)) {
			// System.out.printf("출발지 포트 번호 = %d 도착지 포트 번호= %d\n",
			// tcp.source(), tcp.destination());
			// System.out.print("seq: "+tcp.seq()+", ack: "+tcp.ack()+"\n");
			// System.out.print(tcp+"\n");
			info += "출발지 포트 번호=";
			info += tcp.source();
			info += " ";
			info += "도착지 포트 번호=";
			info += tcp.destination();
			info += " ";
			info += "seq=";
			info += tcp.seq();
			info += " ";
			info += "ack=";
			info += tcp.ack();
			info += " ";
			len += tcp.getLength();
			protocol = "TCP";
			
		}
		else if (packet.hasHeader(udp)) {
			// System.out.printf("출발지 포트 번호 = %d 도착지 포트 번호= %d\n",
			// udp.source(), udp.destination());
			info += "출발지 포트 번호=";
			info += udp.source();
			info += " ";
			info += "도착지 포트 번호=";
			info += udp.destination();
			info += " ";
			len += udp.getLength();
			protocol = "UDP";
		}
		else if (packet.hasHeader(icmp)) {
			len += icmp.getLength();
			protocol = "ICMP";
		}
		if (packet.hasHeader(payload)) {
			System.out.print(payload);
			len += payload.getLength();
		}
		model.length.append(len);
		model.infomation.append(info);
		model.protocol.append(protocol);

		/**
		 * INFO : 가장 처음에 나오는 info
		 */
		System.out.println(packet.toString()); // Uncomment this to cheat (Also great way to check if you're doing it right)

		/**
		 * ****************************FRAME*********************************************
		 */
		// console 창에 출력
		System.out.println("\n---------Frame---------");
		System.out.printf("Arrival time: %s\nWire Length: %-4d\nCaptured Length: %-4d\n", new Date(packet.getCaptureHeader().timestampInMillis()),
				packet.getCaptureHeader().wirelen(), // Original length
				packet.getCaptureHeader().caplen() // Length actually captured
		);
		// model에 저장
		model.frame.append("Arrival time: " + new Date(packet.getCaptureHeader().timestampInMillis()) + "\n" + "Wire Length: "
				+ packet.getCaptureHeader().wirelen() + "\n" + "Captured Length: " + packet.getCaptureHeader().caplen() + "\n");
		model.time.append(String.format("%s", new Date(packet.getCaptureHeader().timestampInMillis())));

		int size = packet.size();
		int x = 0, modelx = 0; // The current byte pointer

		/**
		 * ******************************ETHERNET***************************************
		 */
		// http://www.comptechdoc.org/independent/networking/guide/ethernetdata.gif
		System.out.println("\n---------Ethernet---------");
		// console 창에 출력
		System.out.printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(x), packet.getUByte(++x), packet.getUByte(++x),
				packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
		// model에 저장
		model.ethernet
				.append(String.format("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(modelx), packet.getUByte(++modelx),
						packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));

		// console 창에 출력
		System.out.printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
				packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
		// model에 저장
		model.ethernet
				.append(String.format("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(++modelx), packet.getUByte(++modelx),
						packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));

		int ethernetType = packet.getUShort(++x); // 12th byte
		++modelx;

		if (ethernetType == 2048) {
			System.out.printf("EtherType: 0x%x [IPv4]\n", ethernetType); // console
			model.ethernet.append(String.format("EtherType: 0x%x [IPv4]\n", ethernetType)); // model
		} else if (ethernetType == 34525) {
			System.out.printf("EtherType: 0x%x [IPv6]\n", ethernetType); // console
			model.ethernet.append(String.format("EtherType: 0x%x [IPv6]\n", ethernetType)); // model
		} else {
			System.out.printf("EtherType: 0x%x [Other]\n", ethernetType); // console
			model.ethernet.append(String.format("EtherType: 0x%x [Other]\n", ethernetType)); // model
		}
		x++; // console
		modelx++; // model

		/**
		 * *****************************Internet Protocol***********************************
		 */
		// http://www.diablotin.com/librairie/networking/puis/figs/puis_1603.gif
		System.out.println("\n---------Internet Protocol---------"); // IPv6 not handled (not even sure many sites use IPv6)
		int version = packet.getUByte(++x) >> 4; // console
		++modelx; // model

		int protocolType = 0;
		System.out.printf("Version: %d\n", version); // console
		model.internetProtocol.append("Version: " + version + "\n"); // model

		if (version == 4) { // IPv4
			System.out.printf("Header Length: %d\n", (packet.getUByte(x) >> 4) * (packet.getUByte(x) & 15)); // console
			model.internetProtocol.append("Header Length: " + (packet.getUByte(x) >> 4) * (packet.getUByte(x) & 15) + "\n"); // model

			System.out.printf("Differentiated Services Field: %d\n", packet.getUByte(++x)); // console
			model.internetProtocol.append("Differentiated Services Field: " + packet.getUByte(++modelx) + "\n"); // model

			System.out.printf("Total Length: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x))); // console
			model.internetProtocol.append("Total Length: " + ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)) + "\n"); // model

			System.out.printf("Identification: 0x%x (%d)\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x)),
					((packet.getUByte(--x) << 8) | packet.getUByte(++x))); // console
			model.internetProtocol.append(String.format("Identification: 0x%x (%d)\n", ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)),
					((packet.getUByte(--modelx) << 8) | packet.getUByte(++modelx)))); // model

			System.out.printf("Flags: 0x%x\n", packet.getUByte(++x) >> 5); // console
			model.internetProtocol.append(String.format("Flags: 0x%x\n", packet.getUByte(++modelx) >> 5)); // model

			System.out.printf("Fragment offset: %d\n", ((packet.getUByte(x) & 31) << 8) | packet.getUByte(++x)); // console
			model.internetProtocol.append("Fragment offset: " + (((packet.getUByte(modelx) & 31) << 8) | packet.getUByte(++modelx)) + "\n"); // model

			System.out.printf("Time to live: %d\n", packet.getUByte(++x)); // console
			model.internetProtocol.append("Time to live: " + packet.getUByte(++modelx) + "\n"); // model

			protocolType = packet.getUByte(++x); // console
			++modelx; // model

			System.out.printf("Protocol: %d", protocolType); // console
			model.internetProtocol.append("Protocol: " + protocolType); // model

			if (protocolType == 6) {
				System.out.printf(" (TCP)\n"); // console
				model.internetProtocol.append(" (TCP)\n"); // model
			} else if (protocolType == 17) {
				System.out.printf(" (UDP)\n"); // console
				model.internetProtocol.append(" (UDP)\n"); // model
			}
			System.out.printf("Checksum: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x))); // console
			model.internetProtocol.append("Checksum: " + ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)) + "\n"); // model

			System.out.printf("Source IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x)); // console
			model.internetProtocol.append("Source IP: " + packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "."
					+ packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "\n"); // model

			System.out.printf("Destination IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
					packet.getUByte(++x)); // console
			model.internetProtocol.append("Destination IP: " + packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "."
					+ packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "\n"); // model
		}
		if (version == 6) { // IPv6
			System.out.printf("Traffic Class: %d\n", (packet.getUByte(x) & 15) << 4 | packet.getUByte(++x) >> 4); // console
			model.internetProtocol.append("Traffic Class: " + ((packet.getUByte(modelx) & 15) << 4 | packet.getUByte(++modelx) >> 4) + "\n"); // model

			System.out.printf("Flow Label: %d\n", (packet.getUByte(x) & 15) << 12 | packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
			model.internetProtocol.append(
					"Flow Label: " + ((packet.getUByte(modelx) & 15) << 12 | packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)) + "\n"); // model

			System.out.printf("Payload Length: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
			model.internetProtocol.append("Payload Length: " + (packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)) + "\n"); // model

			protocolType = packet.getUByte(++x); // console
			++modelx; // model

			System.out.printf("Next Header: %d", protocolType); // console
			model.internetProtocol.append("Next Header: " + protocolType); // model
			if (protocolType == 6) {
				System.out.printf(" (TCP)\n");
				model.internetProtocol.append(" (TCP)\n"); // model
			} else if (protocolType == 17) {
				System.out.printf(" (UDP)\n");
				model.internetProtocol.append(" (UDP)\n"); // model
			} else {
				System.out.printf("\n");
				model.internetProtocol.append("\n"); // model
			}
			System.out.printf("Hop Limit: %d\n", packet.getUByte(++x));
			model.internetProtocol.append("Hop Limit: " + packet.getUByte(++modelx) + "\n"); // model

			// console
			System.out.printf("Source IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x),
					packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
					packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
					packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
					packet.getUByte(++x) << 8 | packet.getUByte(++x));
			// model
			model.internetProtocol.append(String.format("Source IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n",
					packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
					packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
					packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
					packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

			// console
			System.out.printf("Destination IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x),
					packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
					packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
					packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
					packet.getUByte(++x) << 8 | packet.getUByte(++x));
			// model
			model.internetProtocol.append(String.format("Destination IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n",
					packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
					packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
					packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
					packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

		}
		/**
		 * *****************************Transport Layer***********************************
		 */
		boolean port53 = false;
		if (protocolType == 6) {// TCP
			System.out.println("\n---------Transmission Control Protocol---------");
			System.out.printf("Source Port: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
			model.transportLayer.append(String.format("Source Port: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx))); // model

			System.out.printf("Destination Port: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
			model.transportLayer.append(String.format("Destination Port: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx))); // model

			byte input[] = new byte[8];
			for (int i = 0; i < 4; i++) {
				input[i] = 0;
			}
			for (int i = 4; i < 8; i++) {
				input[i] = (byte) (packet.getUByte(++x)); // console
				++modelx; // model
			}
			BigInteger unsigned = new BigInteger(input);
			System.out.printf("Sequence Number: %d\n", unsigned); // console
			model.transportLayer.append(String.format("Sequence Number: %d\n", unsigned)); // model

			for (int i = 4; i < 8; i++) {
				input[i] = (byte) (packet.getUByte(++x)); // console
				++modelx; // model
			}
			unsigned = new BigInteger(input);
			System.out.printf("Acknowledge Number: %d\n", unsigned);
			model.transportLayer.append(String.format("Acknowledge Number: %d\n", unsigned));

			System.out.printf("Data Offset: %d\n", packet.getUByte(++x) >> 4);
			model.transportLayer.append(String.format("Data Offset: %d\n", packet.getUByte(++modelx) >> 4));

			System.out.printf("Reserved: %d\n", (packet.getUByte(x) & 15) >> 1);
			model.transportLayer.append(String.format("Reserved: %d\n", (packet.getUByte(modelx) & 15) >> 1));

			System.out.printf("Flags: %d\n", (packet.getUByte(x) & 1) << 8 | packet.getUByte(++x));
			model.transportLayer.append(String.format("Flags: %d\n", (packet.getUByte(modelx) & 1) << 8 | packet.getUByte(++modelx)));

			System.out.printf("Window Size: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
			model.transportLayer.append(String.format("Window Size: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

			System.out.printf("Checksum: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
			model.transportLayer.append(String.format("Checksum: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

			System.out.printf("Urgent Pointer: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
			model.transportLayer.append(String.format("Urgent Pointer: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

		} else if (protocolType == 17) {// UDP
			System.out.println("\n---------User Datagram Protocol---------");
			int tempPort = packet.getUByte(++x) << 8 | packet.getUByte(++x);
			modelx = x;

			System.out.printf("Source Port: %d\n", tempPort);
			model.transportLayer.append(String.format("Source Port: %d\n", tempPort));
			if (tempPort == 53) {
				port53 = true;
			}
			tempPort = packet.getUByte(++x) << 8 | packet.getUByte(++x);
			modelx = x;
			if (tempPort == 53) {
				port53 = true;
			}
			System.out.printf("Destination Port: %d\n", tempPort);
			model.transportLayer.append(String.format("Destination Port: %d\n", tempPort));

			System.out.printf("Length: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
			model.transportLayer.append(String.format("Length: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

			System.out.printf("Checksum: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
			model.transportLayer.append(String.format("Checksum: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));
		}

		System.out.println("\n---------Application Layer---------");
		/**
		 * *****************************Application Layer***********************************
		 */
		// Checks for HTTP or DNS Packet or other packet.
		/**
		 * *********************************************************************************
		 */
		// Uncomment this if you want it to print(see) every Byte of the packet
		x++;// move pointer to start of Application Layer
		byte s[] = new byte[5];
		for (int i = x; i < x + 5; i++) {
			if ((i) >= size) {
				break;
			}
			s[i - x] = (byte) packet.getUByte(i);
		}
		String s2 = new String(s);
		if (s2.contains("HTTP")) {
			System.out.printf("RequestVersion: ");
			model.applicationLayer.append("RequestVersion: ");
			for (int i = x; i < size; i++) {
				if ((byte) packet.getUByte(i) == ' ') {
					x++;
					modelx++;
					break;
				}
				System.out.print((char) packet.getUByte(i));
				model.applicationLayer.append((char) packet.getUByte(i));
				x++;
				modelx++;
			}
			System.out.printf("\nResponseCode: ");
			model.applicationLayer.append("\nResponseCode: ");
			for (int i = x; i < size; i++) {
				if ((byte) packet.getUByte(i) == ' ') {
					x++;
					modelx++;
					break;
				}
				System.out.print((char) packet.getUByte(i));
				model.applicationLayer.append((char) packet.getUByte(i));
				x++;
				modelx++;
			}
			System.out.printf("\nResponseCodeMsg: ");
			model.applicationLayer.append("\\nResponseCodeMsg: ");
			for (int i = x; i < size; i++) {
				if ((byte) packet.getUByte(i) == ' ') {
					x++;
					modelx++;
					break;
				}
				System.out.print((char) packet.getUByte(i));
				model.applicationLayer.append((char) packet.getUByte(i));
				x++;
				modelx++;
			}
			while (x <= size) {
				x += printNextString(x, size, packet, model);
				modelx = x;
			}
		} else if (s2.contains("GET") || s2.contains("POST")) {
			System.out.printf("RequestMethod: ");
			model.applicationLayer.append("RequestMethod: ");
			for (int i = x; i < size; i++) {
				if ((byte) packet.getUByte(i) == ' ') {
					x++;
					modelx++;
					break;
				}
				System.out.print((char) packet.getUByte(i));
				model.applicationLayer.append((char) packet.getUByte(i));
				x++;
				modelx++;
			}
			System.out.printf("\nRequestURL: ");
			model.applicationLayer.append("\nRequestURL: ");
			for (int i = x; i < size; i++) {
				if ((byte) packet.getUByte(i) == ' ') {
					x++;
					modelx++;
					break;
				}
				System.out.print((char) packet.getUByte(i));
				model.applicationLayer.append((char) packet.getUByte(i));
				x++;
				modelx++;
			}
			System.out.printf("\nRequestVersion: ");
			model.applicationLayer.append("\nRequestVersion: ");
			for (int i = x; i < size; i++) {
				if ((byte) packet.getUByte(i) == ' ') {
					x++;
					modelx++;
					break;
				}
				System.out.print((char) packet.getUByte(i));
				model.applicationLayer.append((char) packet.getUByte(i));
				x++;
				modelx++;
			}
			while (x <= size) {
				x += printNextString(x, size, packet, model);
				modelx = x;
			}
		} else if (protocolType == 17 && port53 == true) {// UDP
			// http://stackoverflow.com/questions/7565300/identifying-dns-packets
			int i = x;
			// Check if it's DNS
			int id = (packet.getUByte(i) << 8) | packet.getUByte(++i);
			int qr = packet.getUByte(++i) >> 7;// qr is 8th bit //Set to 0 when the query is generated; changed to 1 when that query is changed to a
												// response by a replying server.
			int opCode = (packet.getUByte(i) >> 3) & 15;// opCode is bits 4-7
			// Flags
			int aa = (packet.getUByte(i) % 4) >> 2; // aa is bit 3
			int tc = (packet.getUByte(i) % 2) >> 1; // tc is bit 2
			int rd = (packet.getUByte(i)) & 1; // rd is bit 1
			int ra = (packet.getUByte(++i) >> 7);
			int zero = (packet.getUByte(i) >> 4) & 7; // padding
			int responseCode = (packet.getUByte(i) & 15);
			int qdCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
			if (qdCount == 1 && zero == 0) { // Must be 0 for DNS
				int anCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
				int nsCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
				int arCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
				System.out.printf("--------DNS---------\n");
				System.out.printf("Id: %d\n", id);
				model.applicationLayer.append(String.format("Id: %d\n", id));
				System.out.printf("Qr: %d\n", qr);
				model.applicationLayer.append(String.format("Qr: %d\n", qr));
				System.out.printf("OpCode: %d\n", opCode);
				model.applicationLayer.append(String.format("OpCode: %d\n", opCode));
				System.out.printf("Authoritative Answer Flag: %d\n", aa);
				model.applicationLayer.append(String.format("Authoritative Answer Flag: %d\n", aa));
				System.out.printf("Truncation Flag: %d\n", tc);
				model.applicationLayer.append(String.format("Truncation Flag: %d\n", tc));
				System.out.printf("Recursion Desired: %d\n", rd);
				model.applicationLayer.append(String.format("Recursion Desired: %d\n", rd));
				System.out.printf("RecursionAvailable: %d\n", ra);
				model.applicationLayer.append(String.format("RecursionAvailable: %d\n", ra));
				System.out.printf("ResponseCode: %d\n", responseCode);
				model.applicationLayer.append(String.format("ResponseCode: %d\n", responseCode));
				System.out.printf("QD Count: %d\n", qdCount);
				model.applicationLayer.append(String.format("QD Count: %d\n", qdCount));
				System.out.printf("AN Count: %d\n", anCount);
				model.applicationLayer.append(String.format("AN Count: %d\n", anCount));
				System.out.printf("NS Count: %d\n", nsCount);
				model.applicationLayer.append(String.format("NS Count: %d\n", nsCount));
				System.out.printf("AR Count: %d\n", arCount);
				model.applicationLayer.append(String.format("AR Count: %d\n", arCount));
				System.out.printf("\nQuery:\n");
				model.applicationLayer.append("\nQuery:\n");
				x += 13;
				System.out.printf("\nName: ");
				model.applicationLayer.append("\nName: ");
				int xcount = printNextStringDNS(x, size, packet, model);
				x += xcount;
				modelx = x;
				System.out.printf("[Name Length: %d]\n", xcount - 1);
				model.applicationLayer.append(String.format("[Name Length: %d]\n", xcount - 1));
				xcount = x - xcount;
				System.out.printf("Type: %d\n", (packet.getUByte(x) << 8) | packet.getUByte(++x));
				model.applicationLayer.append(String.format("Type: %d\n", (packet.getUByte(modelx) << 8) | packet.getUByte(++modelx)));
				System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
				model.applicationLayer.append(String.format("Class: %d\n", (packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)));
				if ((x + 1) < size) {
					System.out.printf("\nAnswer:\n\n");
					model.applicationLayer.append("\nAnswer:\n\n");
					if (packet.getUByte(++x) == 0) {
						System.out.printf("Name: <Root>\n");
						model.applicationLayer.append("Name: <Root>\n");
						x = AuthoritativeNameServer(x, size, packet, model);
						modelx = x;
					} else {
						int ptr = packet.getUByte(++x);
						++modelx;
						int placeHolder = 0;
						while ((x + 1) < size) {
							if (((packet.getUByte(x + 1) << 8) | packet.getUByte(x + 2)) == 6) {
								System.out.printf("Name: ");
								model.applicationLayer.append("Name: ");
								printNextStringDNS(placeHolder, size, packet, model);
								x = AuthoritativeNameServer(x, size, packet, model);
								modelx = x;
								continue;
							} else if (ptr == 12) {
								System.out.printf("Name: ");
								model.applicationLayer.append("Name: ");
								printNextStringDNS(xcount, size, packet, model);
							} else if (ptr == 43) {
								System.out.printf("Name: ");
								model.applicationLayer.append("Name: ");
								printNextStringDNS(placeHolder, size, packet, model);
							} else {
								x++;
								modelx++;
								while (x < size) {
									x += dumpPayload(x, size, packet, model);
									modelx = x;
								}
								break;
							}
							int type = (packet.getUByte(++x) << 8) | packet.getUByte(++x);
							System.out.printf("Type: %d\n", type);
							model.applicationLayer.append(String.format("Type: %d\n", type));
							modelx = x;
							System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
							model.applicationLayer.append(String.format("Class: %d\n", (packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)));

							byte input[] = new byte[8];
							for (int i2 = 0; i2 < 4; i2++) {
								input[i2] = 0;
							}
							for (int i2 = 4; i2 < 8; i2++) {
								input[i2] = (byte) (packet.getUByte(++x));
								++modelx;
							}
							BigInteger unsigned = new BigInteger(input);
							System.out.printf("Time to Live: %d\n", unsigned);
							model.applicationLayer.append(String.format("Time to Live: %d\n", unsigned));
							int dataLength = (packet.getUByte(++x) << 8) | packet.getUByte(++x);
							modelx = x;
							System.out.printf("Data Length: %d\n", dataLength);
							model.applicationLayer.append(String.format("Data Length: %d\n", dataLength));
							if (dataLength < 3) {

							} else if (type == 5) {
								packet.getUByte(++x);
								++modelx;
								System.out.printf("CNAME: ");
								model.applicationLayer.append("CNAME: ");
								placeHolder = x + 1;
								x += printNextStringDNS(x + 1, size, packet, model);
								modelx = x;
								System.out.printf("\n");
								model.applicationLayer.append("\n ");
							} else if (type == 28) {
								System.out.printf("AAAA Address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
										packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
										packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
										packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
										packet.getUByte(++x));
								model.applicationLayer.append(String.format(
										"AAAA Address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
										packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx),
										packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx),
										packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx),
										packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));
							} else if (dataLength > 4) {
								packet.getUByte(++x);
								++modelx;
								System.out.printf("Domain Name: ");
								model.applicationLayer.append("Domain Name: ");
								placeHolder = x + 1;
								x += printNextStringDNS(x + 1, size, packet, model);
								modelx = x;
								System.out.printf("\n");
								model.applicationLayer.append("\n ");
							} else {
								System.out.printf("Address: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
										packet.getUByte(++x));
								model.applicationLayer.append(String.format("Address: %d.%d.%d.%d\n", packet.getUByte(++modelx),
										packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));
							}
							System.out.printf("\n");
							model.applicationLayer.append("\n ");
							if ((x + 1) < size) {
								if (packet.getUByte(++x) == 192) {
									ptr = packet.getUByte(++x);
									++modelx;
								}
							}
						}
					}
					// x+=dumpPayload(x,size,packet);
				}
			} else {// UDP
				if (x < size) {
					// System.out.printf("\n------Payload-------\n");
				}
				while (x < size) {
					x += dumpPayload(x, size, packet, model);
					modelx = x;
				}
			}
		} else { // TCP
			if (x + 3 >= size) {
				return;
			}
			if (packet.getUByte(x) == 1 && packet.getUByte(x + 1) == 1 && packet.getUByte(x + 2) == 8 && packet.getUByte(x + 3) == 10) {
				if (packet.getUByte(x + 12) == 'G' || packet.getUByte(x + 12) == 'P' || packet.getUByte(x + 12) == 'H') {
					x += 12;
					modelx += 12;
					while (x < size) {
						x += printNextString(x, size, packet, model);
						modelx = x;
					}
				}
			}
			while (x < size) {
				x += dumpPayload(x, size, packet, model);
				modelx = x;
			}
		}
		case 1: //TCP
			if (packet.hasHeader(eth)) {
				// System.out.printf("출발지 MAC 주소 = %s 도착지 MAC 주소= %s\n",
				// FormatUtils.mac(eth.source()), FormatUtils.mac(eth.destination()));
				len += eth.getLength();
				info += "출발지 MAC 주소=";
				info += FormatUtils.mac(eth.source());
				info += " ";
				info += "도착지 MAC 주소=";
				info += FormatUtils.mac(eth.destination());
				info += " ";
			}
			if (packet.hasHeader(ip)) {
				System.out.printf("출발지 IP 주소 = %s 도착지 IP 주소= %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
				model.sourceIp.append(String.format("%s", FormatUtils.ip(ip.source())));
				model.destinationIp.append(String.format("%s", FormatUtils.ip(ip.destination())));
				len += ip.getLength();
			}
			if (packet.hasHeader(tcp)) {
				// System.out.printf("출발지 포트 번호 = %d 도착지 포트 번호= %d\n",
				// tcp.source(), tcp.destination());
				// System.out.print("seq: "+tcp.seq()+", ack: "+tcp.ack()+"\n");
				// System.out.print(tcp+"\n");
				info += "출발지 포트 번호=";
				info += tcp.source();
				info += " ";
				info += "도착지 포트 번호=";
				info += tcp.destination();
				info += " ";
				info += "seq=";
				info += tcp.seq();
				info += " ";
				info += "ack=";
				info += tcp.ack();
				info += " ";
				len += tcp.getLength();
				protocol = "TCP";
				
			}
			
			if (packet.hasHeader(payload)) {
				System.out.print(payload);
				len += payload.getLength();
			}
			model.length.append(len);
			model.infomation.append(info);
			model.protocol.append(protocol);

			/**
			 * INFO : 가장 처음에 나오는 info
			 */
			System.out.println(packet.toString()); // Uncomment this to cheat (Also great way to check if you're doing it right)

			/**
			 * ****************************FRAME*********************************************
			 */
			// console 창에 출력
			System.out.println("\n---------Frame---------");
			System.out.printf("Arrival time: %s\nWire Length: %-4d\nCaptured Length: %-4d\n", new Date(packet.getCaptureHeader().timestampInMillis()),
					packet.getCaptureHeader().wirelen(), // Original length
					packet.getCaptureHeader().caplen() // Length actually captured
			);
			// model에 저장
			model.frame.append("Arrival time: " + new Date(packet.getCaptureHeader().timestampInMillis()) + "\n" + "Wire Length: "
					+ packet.getCaptureHeader().wirelen() + "\n" + "Captured Length: " + packet.getCaptureHeader().caplen() + "\n");
			model.time.append(String.format("%s", new Date(packet.getCaptureHeader().timestampInMillis())));

			size = packet.size();
			x = 0;
			modelx = 0; // The current byte pointer

			/**
			 * ******************************ETHERNET***************************************
			 */
			// http://www.comptechdoc.org/independent/networking/guide/ethernetdata.gif
			System.out.println("\n---------Ethernet---------");
			// console 창에 출력
			System.out.printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(x), packet.getUByte(++x), packet.getUByte(++x),
					packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
			// model에 저장
			model.ethernet
					.append(String.format("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(modelx), packet.getUByte(++modelx),
							packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));

			// console 창에 출력
			System.out.printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
					packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
			// model에 저장
			model.ethernet
					.append(String.format("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(++modelx), packet.getUByte(++modelx),
							packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));

			ethernetType = packet.getUShort(++x); // 12th byte
			++modelx;

			if (ethernetType == 2048) {
				System.out.printf("EtherType: 0x%x [IPv4]\n", ethernetType); // console
				model.ethernet.append(String.format("EtherType: 0x%x [IPv4]\n", ethernetType)); // model
			} else if (ethernetType == 34525) {
				System.out.printf("EtherType: 0x%x [IPv6]\n", ethernetType); // console
				model.ethernet.append(String.format("EtherType: 0x%x [IPv6]\n", ethernetType)); // model
			} else {
				System.out.printf("EtherType: 0x%x [Other]\n", ethernetType); // console
				model.ethernet.append(String.format("EtherType: 0x%x [Other]\n", ethernetType)); // model
			}
			x++; // console
			modelx++; // model

			/**
			 * *****************************Internet Protocol***********************************
			 */
			// http://www.diablotin.com/librairie/networking/puis/figs/puis_1603.gif
			System.out.println("\n---------Internet Protocol---------"); // IPv6 not handled (not even sure many sites use IPv6)
			version = packet.getUByte(++x) >> 4; // console
			++modelx; // model

			protocolType = 0;
			System.out.printf("Version: %d\n", version); // console
			model.internetProtocol.append("Version: " + version + "\n"); // model

			if (version == 4) { // IPv4
				System.out.printf("Header Length: %d\n", (packet.getUByte(x) >> 4) * (packet.getUByte(x) & 15)); // console
				model.internetProtocol.append("Header Length: " + (packet.getUByte(x) >> 4) * (packet.getUByte(x) & 15) + "\n"); // model

				System.out.printf("Differentiated Services Field: %d\n", packet.getUByte(++x)); // console
				model.internetProtocol.append("Differentiated Services Field: " + packet.getUByte(++modelx) + "\n"); // model

				System.out.printf("Total Length: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x))); // console
				model.internetProtocol.append("Total Length: " + ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)) + "\n"); // model

				System.out.printf("Identification: 0x%x (%d)\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x)),
						((packet.getUByte(--x) << 8) | packet.getUByte(++x))); // console
				model.internetProtocol.append(String.format("Identification: 0x%x (%d)\n", ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)),
						((packet.getUByte(--modelx) << 8) | packet.getUByte(++modelx)))); // model

				System.out.printf("Flags: 0x%x\n", packet.getUByte(++x) >> 5); // console
				model.internetProtocol.append(String.format("Flags: 0x%x\n", packet.getUByte(++modelx) >> 5)); // model

				System.out.printf("Fragment offset: %d\n", ((packet.getUByte(x) & 31) << 8) | packet.getUByte(++x)); // console
				model.internetProtocol.append("Fragment offset: " + (((packet.getUByte(modelx) & 31) << 8) | packet.getUByte(++modelx)) + "\n"); // model

				System.out.printf("Time to live: %d\n", packet.getUByte(++x)); // console
				model.internetProtocol.append("Time to live: " + packet.getUByte(++modelx) + "\n"); // model

				protocolType = packet.getUByte(++x); // console
				++modelx; // model

				System.out.printf("Protocol: %d", protocolType); // console
				model.internetProtocol.append("Protocol: " + protocolType); // model

				if (protocolType == 6) {
					System.out.printf(" (TCP)\n"); // console
					model.internetProtocol.append(" (TCP)\n"); // model
				} else if (protocolType == 17) {
					System.out.printf(" (UDP)\n"); // console
					model.internetProtocol.append(" (UDP)\n"); // model
				}
				System.out.printf("Checksum: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x))); // console
				model.internetProtocol.append("Checksum: " + ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)) + "\n"); // model

				System.out.printf("Source IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x)); // console
				model.internetProtocol.append("Source IP: " + packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "."
						+ packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "\n"); // model

				System.out.printf("Destination IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
						packet.getUByte(++x)); // console
				model.internetProtocol.append("Destination IP: " + packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "."
						+ packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "\n"); // model
			}
			if (version == 6) { // IPv6
				System.out.printf("Traffic Class: %d\n", (packet.getUByte(x) & 15) << 4 | packet.getUByte(++x) >> 4); // console
				model.internetProtocol.append("Traffic Class: " + ((packet.getUByte(modelx) & 15) << 4 | packet.getUByte(++modelx) >> 4) + "\n"); // model

				System.out.printf("Flow Label: %d\n", (packet.getUByte(x) & 15) << 12 | packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
				model.internetProtocol.append(
						"Flow Label: " + ((packet.getUByte(modelx) & 15) << 12 | packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)) + "\n"); // model

				System.out.printf("Payload Length: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
				model.internetProtocol.append("Payload Length: " + (packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)) + "\n"); // model

				protocolType = packet.getUByte(++x); // console
				++modelx; // model

				System.out.printf("Next Header: %d", protocolType); // console
				model.internetProtocol.append("Next Header: " + protocolType); // model
				if (protocolType == 6) {
					System.out.printf(" (TCP)\n");
					model.internetProtocol.append(" (TCP)\n"); // model
				} else if (protocolType == 17) {
					System.out.printf(" (UDP)\n");
					model.internetProtocol.append(" (UDP)\n"); // model
				} else {
					System.out.printf("\n");
					model.internetProtocol.append("\n"); // model
				}
				System.out.printf("Hop Limit: %d\n", packet.getUByte(++x));
				model.internetProtocol.append("Hop Limit: " + packet.getUByte(++modelx) + "\n"); // model

				// console
				System.out.printf("Source IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x),
						packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
						packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
						packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
						packet.getUByte(++x) << 8 | packet.getUByte(++x));
				// model
				model.internetProtocol.append(String.format("Source IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n",
						packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
						packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
						packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
						packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

				// console
				System.out.printf("Destination IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x),
						packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
						packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
						packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
						packet.getUByte(++x) << 8 | packet.getUByte(++x));
				// model
				model.internetProtocol.append(String.format("Destination IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n",
						packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
						packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
						packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
						packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

			}
			/**
			 * *****************************Transport Layer***********************************
			 */
			port53 = false;
			if (protocolType == 6) {// TCP
				System.out.println("\n---------Transmission Control Protocol---------");
				System.out.printf("Source Port: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
				model.transportLayer.append(String.format("Source Port: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx))); // model

				System.out.printf("Destination Port: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
				model.transportLayer.append(String.format("Destination Port: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx))); // model

				byte input[] = new byte[8];
				for (int i = 0; i < 4; i++) {
					input[i] = 0;
				}
				for (int i = 4; i < 8; i++) {
					input[i] = (byte) (packet.getUByte(++x)); // console
					++modelx; // model
				}
				BigInteger unsigned = new BigInteger(input);
				System.out.printf("Sequence Number: %d\n", unsigned); // console
				model.transportLayer.append(String.format("Sequence Number: %d\n", unsigned)); // model

				for (int i = 4; i < 8; i++) {
					input[i] = (byte) (packet.getUByte(++x)); // console
					++modelx; // model
				}
				unsigned = new BigInteger(input);
				System.out.printf("Acknowledge Number: %d\n", unsigned);
				model.transportLayer.append(String.format("Acknowledge Number: %d\n", unsigned));

				System.out.printf("Data Offset: %d\n", packet.getUByte(++x) >> 4);
				model.transportLayer.append(String.format("Data Offset: %d\n", packet.getUByte(++modelx) >> 4));

				System.out.printf("Reserved: %d\n", (packet.getUByte(x) & 15) >> 1);
				model.transportLayer.append(String.format("Reserved: %d\n", (packet.getUByte(modelx) & 15) >> 1));

				System.out.printf("Flags: %d\n", (packet.getUByte(x) & 1) << 8 | packet.getUByte(++x));
				model.transportLayer.append(String.format("Flags: %d\n", (packet.getUByte(modelx) & 1) << 8 | packet.getUByte(++modelx)));

				System.out.printf("Window Size: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
				model.transportLayer.append(String.format("Window Size: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

				System.out.printf("Checksum: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
				model.transportLayer.append(String.format("Checksum: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

				System.out.printf("Urgent Pointer: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
				model.transportLayer.append(String.format("Urgent Pointer: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

			} 

			System.out.println("\n---------Application Layer---------");
			/**
			 * *****************************Application Layer***********************************
			 */
			// Checks for HTTP or DNS Packet or other packet.
			/**
			 * *********************************************************************************
			 */
			// Uncomment this if you want it to print(see) every Byte of the packet
			x++;// move pointer to start of Application Layer
			s = new byte[5];
			for (int i = x; i < x + 5; i++) {
				if ((i) >= size) {
					break;
				}
				s[i - x] = (byte) packet.getUByte(i);
			}
			s2 = new String(s);
			if (s2.contains("HTTP")) {
				System.out.printf("RequestVersion: ");
				model.applicationLayer.append("RequestVersion: ");
				for (int i = x; i < size; i++) {
					if ((byte) packet.getUByte(i) == ' ') {
						x++;
						modelx++;
						break;
					}
					System.out.print((char) packet.getUByte(i));
					model.applicationLayer.append((char) packet.getUByte(i));
					x++;
					modelx++;
				}
				System.out.printf("\nResponseCode: ");
				model.applicationLayer.append("\nResponseCode: ");
				for (int i = x; i < size; i++) {
					if ((byte) packet.getUByte(i) == ' ') {
						x++;
						modelx++;
						break;
					}
					System.out.print((char) packet.getUByte(i));
					model.applicationLayer.append((char) packet.getUByte(i));
					x++;
					modelx++;
				}
				System.out.printf("\nResponseCodeMsg: ");
				model.applicationLayer.append("\\nResponseCodeMsg: ");
				for (int i = x; i < size; i++) {
					if ((byte) packet.getUByte(i) == ' ') {
						x++;
						modelx++;
						break;
					}
					System.out.print((char) packet.getUByte(i));
					model.applicationLayer.append((char) packet.getUByte(i));
					x++;
					modelx++;
				}
				while (x <= size) {
					x += printNextString(x, size, packet, model);
					modelx = x;
				}
			} else if (s2.contains("GET") || s2.contains("POST")) {
				System.out.printf("RequestMethod: ");
				model.applicationLayer.append("RequestMethod: ");
				for (int i = x; i < size; i++) {
					if ((byte) packet.getUByte(i) == ' ') {
						x++;
						modelx++;
						break;
					}
					System.out.print((char) packet.getUByte(i));
					model.applicationLayer.append((char) packet.getUByte(i));
					x++;
					modelx++;
				}
				System.out.printf("\nRequestURL: ");
				model.applicationLayer.append("\nRequestURL: ");
				for (int i = x; i < size; i++) {
					if ((byte) packet.getUByte(i) == ' ') {
						x++;
						modelx++;
						break;
					}
					System.out.print((char) packet.getUByte(i));
					model.applicationLayer.append((char) packet.getUByte(i));
					x++;
					modelx++;
				}
				System.out.printf("\nRequestVersion: ");
				model.applicationLayer.append("\nRequestVersion: ");
				for (int i = x; i < size; i++) {
					if ((byte) packet.getUByte(i) == ' ') {
						x++;
						modelx++;
						break;
					}
					System.out.print((char) packet.getUByte(i));
					model.applicationLayer.append((char) packet.getUByte(i));
					x++;
					modelx++;
				}
				while (x <= size) {
					x += printNextString(x, size, packet, model);
					modelx = x;
				}
			} 
			else { // TCP
				if (x + 3 >= size) {
					return;
				}
				if (packet.getUByte(x) == 1 && packet.getUByte(x + 1) == 1 && packet.getUByte(x + 2) == 8 && packet.getUByte(x + 3) == 10) {
					if (packet.getUByte(x + 12) == 'G' || packet.getUByte(x + 12) == 'P' || packet.getUByte(x + 12) == 'H') {
						x += 12;
						modelx += 12;
						while (x < size) {
							x += printNextString(x, size, packet, model);
							modelx = x;
						}
					}
				}
				while (x < size) {
					x += dumpPayload(x, size, packet, model);
					modelx = x;
				}
				
			}
			case 2: //UDP
				if (packet.hasHeader(eth)) {
					// System.out.printf("출발지 MAC 주소 = %s 도착지 MAC 주소= %s\n",
					// FormatUtils.mac(eth.source()), FormatUtils.mac(eth.destination()));
					len += eth.getLength();
					info += "출발지 MAC 주소=";
					info += FormatUtils.mac(eth.source());
					info += " ";
					info += "도착지 MAC 주소=";
					info += FormatUtils.mac(eth.destination());
					info += " ";
				}
				if (packet.hasHeader(ip)) {
					System.out.printf("출발지 IP 주소 = %s 도착지 IP 주소= %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
					model.sourceIp.append(String.format("%s", FormatUtils.ip(ip.source())));
					model.destinationIp.append(String.format("%s", FormatUtils.ip(ip.destination())));
					len += ip.getLength();
				}
				if (packet.hasHeader(udp)) {
					// System.out.printf("출발지 포트 번호 = %d 도착지 포트 번호= %d\n",
					// udp.source(), udp.destination());
					info += "출발지 포트 번호=";
					info += udp.source();
					info += " ";
					info += "도착지 포트 번호=";
					info += udp.destination();
					info += " ";
					len += udp.getLength();
					protocol = "UDP";
				}
				
				if (packet.hasHeader(payload)) {
					System.out.print(payload);
					len += payload.getLength();
				}
				model.length.append(len);
				model.infomation.append(info);
				model.protocol.append(protocol);

				/**
				 * INFO : 가장 처음에 나오는 info
				 */
				System.out.println(packet.toString()); // Uncomment this to cheat (Also great way to check if you're doing it right)

				/**
				 * ****************************FRAME*********************************************
				 */
				// console 창에 출력
				System.out.println("\n---------Frame---------");
				System.out.printf("Arrival time: %s\nWire Length: %-4d\nCaptured Length: %-4d\n", new Date(packet.getCaptureHeader().timestampInMillis()),
						packet.getCaptureHeader().wirelen(), // Original length
						packet.getCaptureHeader().caplen() // Length actually captured
				);
				// model에 저장
				model.frame.append("Arrival time: " + new Date(packet.getCaptureHeader().timestampInMillis()) + "\n" + "Wire Length: "
						+ packet.getCaptureHeader().wirelen() + "\n" + "Captured Length: " + packet.getCaptureHeader().caplen() + "\n");
				model.time.append(String.format("%s", new Date(packet.getCaptureHeader().timestampInMillis())));

				size = packet.size();
				x = 0;
				modelx = 0; // The current byte pointer

				/**
				 * ******************************ETHERNET***************************************
				 */
				// http://www.comptechdoc.org/independent/networking/guide/ethernetdata.gif
				System.out.println("\n---------Ethernet---------");
				// console 창에 출력
				System.out.printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(x), packet.getUByte(++x), packet.getUByte(++x),
						packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
				// model에 저장
				model.ethernet
						.append(String.format("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(modelx), packet.getUByte(++modelx),
								packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));

				// console 창에 출력
				System.out.printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
						packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
				// model에 저장
				model.ethernet
						.append(String.format("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(++modelx), packet.getUByte(++modelx),
								packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));

				ethernetType = packet.getUShort(++x); // 12th byte
				++modelx;

				if (ethernetType == 2048) {
					System.out.printf("EtherType: 0x%x [IPv4]\n", ethernetType); // console
					model.ethernet.append(String.format("EtherType: 0x%x [IPv4]\n", ethernetType)); // model
				} else if (ethernetType == 34525) {
					System.out.printf("EtherType: 0x%x [IPv6]\n", ethernetType); // console
					model.ethernet.append(String.format("EtherType: 0x%x [IPv6]\n", ethernetType)); // model
				} else {
					System.out.printf("EtherType: 0x%x [Other]\n", ethernetType); // console
					model.ethernet.append(String.format("EtherType: 0x%x [Other]\n", ethernetType)); // model
				}
				x++; // console
				modelx++; // model

				/**
				 * *****************************Internet Protocol***********************************
				 */
				// http://www.diablotin.com/librairie/networking/puis/figs/puis_1603.gif
				System.out.println("\n---------Internet Protocol---------"); // IPv6 not handled (not even sure many sites use IPv6)
				version = packet.getUByte(++x) >> 4; // console
				++modelx; // model

				protocolType = 0;
				System.out.printf("Version: %d\n", version); // console
				model.internetProtocol.append("Version: " + version + "\n"); // model

				if (version == 4) { // IPv4
					System.out.printf("Header Length: %d\n", (packet.getUByte(x) >> 4) * (packet.getUByte(x) & 15)); // console
					model.internetProtocol.append("Header Length: " + (packet.getUByte(x) >> 4) * (packet.getUByte(x) & 15) + "\n"); // model

					System.out.printf("Differentiated Services Field: %d\n", packet.getUByte(++x)); // console
					model.internetProtocol.append("Differentiated Services Field: " + packet.getUByte(++modelx) + "\n"); // model

					System.out.printf("Total Length: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x))); // console
					model.internetProtocol.append("Total Length: " + ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)) + "\n"); // model

					System.out.printf("Identification: 0x%x (%d)\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x)),
							((packet.getUByte(--x) << 8) | packet.getUByte(++x))); // console
					model.internetProtocol.append(String.format("Identification: 0x%x (%d)\n", ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)),
							((packet.getUByte(--modelx) << 8) | packet.getUByte(++modelx)))); // model

					System.out.printf("Flags: 0x%x\n", packet.getUByte(++x) >> 5); // console
					model.internetProtocol.append(String.format("Flags: 0x%x\n", packet.getUByte(++modelx) >> 5)); // model

					System.out.printf("Fragment offset: %d\n", ((packet.getUByte(x) & 31) << 8) | packet.getUByte(++x)); // console
					model.internetProtocol.append("Fragment offset: " + (((packet.getUByte(modelx) & 31) << 8) | packet.getUByte(++modelx)) + "\n"); // model

					System.out.printf("Time to live: %d\n", packet.getUByte(++x)); // console
					model.internetProtocol.append("Time to live: " + packet.getUByte(++modelx) + "\n"); // model

					protocolType = packet.getUByte(++x); // console
					++modelx; // model

					System.out.printf("Protocol: %d", protocolType); // console
					model.internetProtocol.append("Protocol: " + protocolType); // model

					if (protocolType == 17) {
						System.out.printf(" (UDP)\n"); // console
						model.internetProtocol.append(" (UDP)\n"); // model
					}
					System.out.printf("Checksum: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x))); // console
					model.internetProtocol.append("Checksum: " + ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)) + "\n"); // model

					System.out.printf("Source IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x)); // console
					model.internetProtocol.append("Source IP: " + packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "."
							+ packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "\n"); // model

					System.out.printf("Destination IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
							packet.getUByte(++x)); // console
					model.internetProtocol.append("Destination IP: " + packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "."
							+ packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "\n"); // model
				}
				if (version == 6) { // IPv6
					System.out.printf("Traffic Class: %d\n", (packet.getUByte(x) & 15) << 4 | packet.getUByte(++x) >> 4); // console
					model.internetProtocol.append("Traffic Class: " + ((packet.getUByte(modelx) & 15) << 4 | packet.getUByte(++modelx) >> 4) + "\n"); // model

					System.out.printf("Flow Label: %d\n", (packet.getUByte(x) & 15) << 12 | packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
					model.internetProtocol.append(
							"Flow Label: " + ((packet.getUByte(modelx) & 15) << 12 | packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)) + "\n"); // model

					System.out.printf("Payload Length: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
					model.internetProtocol.append("Payload Length: " + (packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)) + "\n"); // model

					protocolType = packet.getUByte(++x); // console
					++modelx; // model

					System.out.printf("Next Header: %d", protocolType); // console
					model.internetProtocol.append("Next Header: " + protocolType); // model
					if (protocolType == 17) {
						System.out.printf(" (UDP)\n");
						model.internetProtocol.append(" (UDP)\n"); // model
					} else {
						System.out.printf("\n");
						model.internetProtocol.append("\n"); // model
					}
					System.out.printf("Hop Limit: %d\n", packet.getUByte(++x));
					model.internetProtocol.append("Hop Limit: " + packet.getUByte(++modelx) + "\n"); // model

					// console
					System.out.printf("Source IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x),
							packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
							packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
							packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
							packet.getUByte(++x) << 8 | packet.getUByte(++x));
					// model
					model.internetProtocol.append(String.format("Source IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n",
							packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
							packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
							packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
							packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

					// console
					System.out.printf("Destination IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x),
							packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
							packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
							packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
							packet.getUByte(++x) << 8 | packet.getUByte(++x));
					// model
					model.internetProtocol.append(String.format("Destination IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n",
							packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
							packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
							packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
							packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

				}
				/**
				 * *****************************Transport Layer***********************************
				 */
				port53 = false;
				if (protocolType == 17) {// UDP
					System.out.println("\n---------User Datagram Protocol---------");
					int tempPort = packet.getUByte(++x) << 8 | packet.getUByte(++x);
					modelx = x;

					System.out.printf("Source Port: %d\n", tempPort);
					model.transportLayer.append(String.format("Source Port: %d\n", tempPort));
					if (tempPort == 53) {
						port53 = true;
					}
					tempPort = packet.getUByte(++x) << 8 | packet.getUByte(++x);
					modelx = x;
					if (tempPort == 53) {
						port53 = true;
					}
					System.out.printf("Destination Port: %d\n", tempPort);
					model.transportLayer.append(String.format("Destination Port: %d\n", tempPort));

					System.out.printf("Length: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
					model.transportLayer.append(String.format("Length: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

					System.out.printf("Checksum: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x));
					model.transportLayer.append(String.format("Checksum: %d\n", packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));
				}

				System.out.println("\n---------Application Layer---------");
				/**
				 * *****************************Application Layer***********************************
				 */
				// Checks for HTTP or DNS Packet or other packet.
				/**
				 * *********************************************************************************
				 */
				// Uncomment this if you want it to print(see) every Byte of the packet
				x++;// move pointer to start of Application Layer
				s = new byte[5];
				for (int i = x; i < x + 5; i++) {
					if ((i) >= size) {
						break;
					}
					s[i - x] = (byte) packet.getUByte(i);
				}
				s2 = new String(s);
				if (protocolType == 17 && port53 == true) {// UDP
					// http://stackoverflow.com/questions/7565300/identifying-dns-packets
					int i = x;
					// Check if it's DNS
					int id = (packet.getUByte(i) << 8) | packet.getUByte(++i);
					int qr = packet.getUByte(++i) >> 7;// qr is 8th bit //Set to 0 when the query is generated; changed to 1 when that query is changed to a
														// response by a replying server.
					int opCode = (packet.getUByte(i) >> 3) & 15;// opCode is bits 4-7
					// Flags
					int aa = (packet.getUByte(i) % 4) >> 2; // aa is bit 3
					int tc = (packet.getUByte(i) % 2) >> 1; // tc is bit 2
					int rd = (packet.getUByte(i)) & 1; // rd is bit 1
					int ra = (packet.getUByte(++i) >> 7);
					int zero = (packet.getUByte(i) >> 4) & 7; // padding
					int responseCode = (packet.getUByte(i) & 15);
					int qdCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
					if (qdCount == 1 && zero == 0) { // Must be 0 for DNS
						int anCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
						int nsCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
						int arCount = (packet.getUByte(++i) << 8) | packet.getUByte(++i);
						System.out.printf("--------DNS---------\n");
						System.out.printf("Id: %d\n", id);
						model.applicationLayer.append(String.format("Id: %d\n", id));
						System.out.printf("Qr: %d\n", qr);
						model.applicationLayer.append(String.format("Qr: %d\n", qr));
						System.out.printf("OpCode: %d\n", opCode);
						model.applicationLayer.append(String.format("OpCode: %d\n", opCode));
						System.out.printf("Authoritative Answer Flag: %d\n", aa);
						model.applicationLayer.append(String.format("Authoritative Answer Flag: %d\n", aa));
						System.out.printf("Truncation Flag: %d\n", tc);
						model.applicationLayer.append(String.format("Truncation Flag: %d\n", tc));
						System.out.printf("Recursion Desired: %d\n", rd);
						model.applicationLayer.append(String.format("Recursion Desired: %d\n", rd));
						System.out.printf("RecursionAvailable: %d\n", ra);
						model.applicationLayer.append(String.format("RecursionAvailable: %d\n", ra));
						System.out.printf("ResponseCode: %d\n", responseCode);
						model.applicationLayer.append(String.format("ResponseCode: %d\n", responseCode));
						System.out.printf("QD Count: %d\n", qdCount);
						model.applicationLayer.append(String.format("QD Count: %d\n", qdCount));
						System.out.printf("AN Count: %d\n", anCount);
						model.applicationLayer.append(String.format("AN Count: %d\n", anCount));
						System.out.printf("NS Count: %d\n", nsCount);
						model.applicationLayer.append(String.format("NS Count: %d\n", nsCount));
						System.out.printf("AR Count: %d\n", arCount);
						model.applicationLayer.append(String.format("AR Count: %d\n", arCount));
						System.out.printf("\nQuery:\n");
						model.applicationLayer.append("\nQuery:\n");
						x += 13;
						System.out.printf("\nName: ");
						model.applicationLayer.append("\nName: ");
						int xcount = printNextStringDNS(x, size, packet, model);
						x += xcount;
						modelx = x;
						System.out.printf("[Name Length: %d]\n", xcount - 1);
						model.applicationLayer.append(String.format("[Name Length: %d]\n", xcount - 1));
						xcount = x - xcount;
						System.out.printf("Type: %d\n", (packet.getUByte(x) << 8) | packet.getUByte(++x));
						model.applicationLayer.append(String.format("Type: %d\n", (packet.getUByte(modelx) << 8) | packet.getUByte(++modelx)));
						System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
						model.applicationLayer.append(String.format("Class: %d\n", (packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)));
						if ((x + 1) < size) {
							System.out.printf("\nAnswer:\n\n");
							model.applicationLayer.append("\nAnswer:\n\n");
							if (packet.getUByte(++x) == 0) {
								System.out.printf("Name: <Root>\n");
								model.applicationLayer.append("Name: <Root>\n");
								x = AuthoritativeNameServer(x, size, packet, model);
								modelx = x;
							} else {
								int ptr = packet.getUByte(++x);
								++modelx;
								int placeHolder = 0;
								while ((x + 1) < size) {
									if (((packet.getUByte(x + 1) << 8) | packet.getUByte(x + 2)) == 6) {
										System.out.printf("Name: ");
										model.applicationLayer.append("Name: ");
										printNextStringDNS(placeHolder, size, packet, model);
										x = AuthoritativeNameServer(x, size, packet, model);
										modelx = x;
										continue;
									} else if (ptr == 12) {
										System.out.printf("Name: ");
										model.applicationLayer.append("Name: ");
										printNextStringDNS(xcount, size, packet, model);
									} else if (ptr == 43) {
										System.out.printf("Name: ");
										model.applicationLayer.append("Name: ");
										printNextStringDNS(placeHolder, size, packet, model);
									} else {
										x++;
										modelx++;
										while (x < size) {
											x += dumpPayload(x, size, packet, model);
											modelx = x;
										}
										break;
									}
									int type = (packet.getUByte(++x) << 8) | packet.getUByte(++x);
									System.out.printf("Type: %d\n", type);
									model.applicationLayer.append(String.format("Type: %d\n", type));
									modelx = x;
									System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
									model.applicationLayer.append(String.format("Class: %d\n", (packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)));

									byte input[] = new byte[8];
									for (int i2 = 0; i2 < 4; i2++) {
										input[i2] = 0;
									}
									for (int i2 = 4; i2 < 8; i2++) {
										input[i2] = (byte) (packet.getUByte(++x));
										++modelx;
									}
									BigInteger unsigned = new BigInteger(input);
									System.out.printf("Time to Live: %d\n", unsigned);
									model.applicationLayer.append(String.format("Time to Live: %d\n", unsigned));
									int dataLength = (packet.getUByte(++x) << 8) | packet.getUByte(++x);
									modelx = x;
									System.out.printf("Data Length: %d\n", dataLength);
									model.applicationLayer.append(String.format("Data Length: %d\n", dataLength));
									if (dataLength < 3) {

									} else if (type == 5) {
										packet.getUByte(++x);
										++modelx;
										System.out.printf("CNAME: ");
										model.applicationLayer.append("CNAME: ");
										placeHolder = x + 1;
										x += printNextStringDNS(x + 1, size, packet, model);
										modelx = x;
										System.out.printf("\n");
										model.applicationLayer.append("\n ");
									} else if (type == 28) {
										System.out.printf("AAAA Address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
												packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
												packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
												packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
												packet.getUByte(++x));
										model.applicationLayer.append(String.format(
												"AAAA Address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
												packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx),
												packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx),
												packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx),
												packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));
									} else if (dataLength > 4) {
										packet.getUByte(++x);
										++modelx;
										System.out.printf("Domain Name: ");
										model.applicationLayer.append("Domain Name: ");
										placeHolder = x + 1;
										x += printNextStringDNS(x + 1, size, packet, model);
										modelx = x;
										System.out.printf("\n");
										model.applicationLayer.append("\n ");
									} else {
										System.out.printf("Address: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
												packet.getUByte(++x));
										model.applicationLayer.append(String.format("Address: %d.%d.%d.%d\n", packet.getUByte(++modelx),
												packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));
									}
									System.out.printf("\n");
									model.applicationLayer.append("\n ");
									if ((x + 1) < size) {
										if (packet.getUByte(++x) == 192) {
											ptr = packet.getUByte(++x);
											++modelx;
										}
									}
								}
							}
							// x+=dumpPayload(x,size,packet);
						}
					} else {// UDP
						if (x < size) {
							// System.out.printf("\n------Payload-------\n");
						}
						while (x < size) {
							x += dumpPayload(x, size, packet, model);
							modelx = x;
						}
					}
				}
				case 3:
					if (packet.hasHeader(eth)) {
						// System.out.printf("출발지 MAC 주소 = %s 도착지 MAC 주소= %s\n",
						// FormatUtils.mac(eth.source()), FormatUtils.mac(eth.destination()));
						len += eth.getLength();
						info += "출발지 MAC 주소=";
						info += FormatUtils.mac(eth.source());
						info += " ";
						info += "도착지 MAC 주소=";
						info += FormatUtils.mac(eth.destination());
						info += " ";
					}
					if (packet.hasHeader(icmp)) {
						len += icmp.getLength();
						protocol = "ICMP";
					}
					if (packet.hasHeader(payload)) {
						System.out.print(payload);
						len += payload.getLength();
					}
					model.length.append(len);
					model.infomation.append(info);
					model.protocol.append(protocol);

					/**
					 * INFO : 가장 처음에 나오는 info
					 */
					System.out.println(packet.toString()); // Uncomment this to cheat (Also great way to check if you're doing it right)

					/**
					 * ****************************FRAME*********************************************
					 */
					// console 창에 출력
					System.out.println("\n---------Frame---------");
					System.out.printf("Arrival time: %s\nWire Length: %-4d\nCaptured Length: %-4d\n", new Date(packet.getCaptureHeader().timestampInMillis()),
							packet.getCaptureHeader().wirelen(), // Original length
							packet.getCaptureHeader().caplen() // Length actually captured
					);
					// model에 저장
					model.frame.append("Arrival time: " + new Date(packet.getCaptureHeader().timestampInMillis()) + "\n" + "Wire Length: "
							+ packet.getCaptureHeader().wirelen() + "\n" + "Captured Length: " + packet.getCaptureHeader().caplen() + "\n");
					model.time.append(String.format("%s", new Date(packet.getCaptureHeader().timestampInMillis())));

					size = packet.size();
					x = 0;
					modelx = 0; // The current byte pointer

					/**
					 * ******************************ETHERNET***************************************
					 */
					// http://www.comptechdoc.org/independent/networking/guide/ethernetdata.gif
					System.out.println("\n---------Ethernet---------");
					// console 창에 출력
					System.out.printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(x), packet.getUByte(++x), packet.getUByte(++x),
							packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
					// model에 저장
					model.ethernet
							.append(String.format("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(modelx), packet.getUByte(++modelx),
									packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));

					// console 창에 출력
					System.out.printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
							packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x));
					// model에 저장
					model.ethernet
							.append(String.format("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet.getUByte(++modelx), packet.getUByte(++modelx),
									packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx), packet.getUByte(++modelx)));

					ethernetType = packet.getUShort(++x); // 12th byte
					++modelx;

					if (ethernetType == 2048) {
						System.out.printf("EtherType: 0x%x [IPv4]\n", ethernetType); // console
						model.ethernet.append(String.format("EtherType: 0x%x [IPv4]\n", ethernetType)); // model
					} else if (ethernetType == 34525) {
						System.out.printf("EtherType: 0x%x [IPv6]\n", ethernetType); // console
						model.ethernet.append(String.format("EtherType: 0x%x [IPv6]\n", ethernetType)); // model
					} else {
						System.out.printf("EtherType: 0x%x [Other]\n", ethernetType); // console
						model.ethernet.append(String.format("EtherType: 0x%x [Other]\n", ethernetType)); // model
					}
					x++; // console
					modelx++; // model

					/**
					 * *****************************Internet Protocol***********************************
					 */
					// http://www.diablotin.com/librairie/networking/puis/figs/puis_1603.gif
					System.out.println("\n---------Internet Protocol---------"); // IPv6 not handled (not even sure many sites use IPv6)
					version = packet.getUByte(++x) >> 4; // console
					++modelx; // model

					protocolType = 0;
					System.out.printf("Version: %d\n", version); // console
					model.internetProtocol.append("Version: " + version + "\n"); // model

					if (version == 4) { // IPv4
						System.out.printf("Header Length: %d\n", (packet.getUByte(x) >> 4) * (packet.getUByte(x) & 15)); // console
						model.internetProtocol.append("Header Length: " + (packet.getUByte(x) >> 4) * (packet.getUByte(x) & 15) + "\n"); // model

						System.out.printf("Differentiated Services Field: %d\n", packet.getUByte(++x)); // console
						model.internetProtocol.append("Differentiated Services Field: " + packet.getUByte(++modelx) + "\n"); // model

						System.out.printf("Total Length: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x))); // console
						model.internetProtocol.append("Total Length: " + ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)) + "\n"); // model

						System.out.printf("Identification: 0x%x (%d)\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x)),
								((packet.getUByte(--x) << 8) | packet.getUByte(++x))); // console
						model.internetProtocol.append(String.format("Identification: 0x%x (%d)\n", ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)),
								((packet.getUByte(--modelx) << 8) | packet.getUByte(++modelx)))); // model

						System.out.printf("Flags: 0x%x\n", packet.getUByte(++x) >> 5); // console
						model.internetProtocol.append(String.format("Flags: 0x%x\n", packet.getUByte(++modelx) >> 5)); // model

						System.out.printf("Fragment offset: %d\n", ((packet.getUByte(x) & 31) << 8) | packet.getUByte(++x)); // console
						model.internetProtocol.append("Fragment offset: " + (((packet.getUByte(modelx) & 31) << 8) | packet.getUByte(++modelx)) + "\n"); // model

						System.out.printf("Time to live: %d\n", packet.getUByte(++x)); // console
						model.internetProtocol.append("Time to live: " + packet.getUByte(++modelx) + "\n"); // model

						protocolType = packet.getUByte(++x); // console
						++modelx; // model

						System.out.printf("Protocol: %d", protocolType); // console
						model.internetProtocol.append("Protocol: " + protocolType); // model

						
						System.out.printf("Checksum: %d\n", ((packet.getUByte(++x) << 8) | packet.getUByte(++x))); // console
						model.internetProtocol.append("Checksum: " + ((packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)) + "\n"); // model

						System.out.printf("Source IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x)); // console
						model.internetProtocol.append("Source IP: " + packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "."
								+ packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "\n"); // model

						System.out.printf("Destination IP: %d.%d.%d.%d\n", packet.getUByte(++x), packet.getUByte(++x), packet.getUByte(++x),
								packet.getUByte(++x)); // console
						model.internetProtocol.append("Destination IP: " + packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "."
								+ packet.getUByte(++modelx) + "." + packet.getUByte(++modelx) + "\n"); // model
					}
					if (version == 6) { // IPv6
						System.out.printf("Traffic Class: %d\n", (packet.getUByte(x) & 15) << 4 | packet.getUByte(++x) >> 4); // console
						model.internetProtocol.append("Traffic Class: " + ((packet.getUByte(modelx) & 15) << 4 | packet.getUByte(++modelx) >> 4) + "\n"); // model

						System.out.printf("Flow Label: %d\n", (packet.getUByte(x) & 15) << 12 | packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
						model.internetProtocol.append(
								"Flow Label: " + ((packet.getUByte(modelx) & 15) << 12 | packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)) + "\n"); // model

						System.out.printf("Payload Length: %d\n", packet.getUByte(++x) << 8 | packet.getUByte(++x)); // console
						model.internetProtocol.append("Payload Length: " + (packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)) + "\n"); // model

						protocolType = packet.getUByte(++x); // console
						++modelx; // model

						System.out.printf("Next Header: %d", protocolType); // console
						model.internetProtocol.append("Next Header: " + protocolType); // model
						if ((protocolType != 6)&&(protocolType != 17)){
							System.out.printf("\n");
							model.internetProtocol.append("\n"); // model
						}
						System.out.printf("Hop Limit: %d\n", packet.getUByte(++x));
						model.internetProtocol.append("Hop Limit: " + packet.getUByte(++modelx) + "\n"); // model

						// console
						System.out.printf("Source IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x),
								packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
								packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
								packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
								packet.getUByte(++x) << 8 | packet.getUByte(++x));
						// model
						model.internetProtocol.append(String.format("Source IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n",
								packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
								packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
								packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
								packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

						// console
						System.out.printf("Destination IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", packet.getUByte(++x) << 8 | packet.getUByte(++x),
								packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
								packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
								packet.getUByte(++x) << 8 | packet.getUByte(++x), packet.getUByte(++x) << 8 | packet.getUByte(++x),
								packet.getUByte(++x) << 8 | packet.getUByte(++x));
						// model
						model.internetProtocol.append(String.format("Destination IP: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n",
								packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
								packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
								packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx),
								packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx), packet.getUByte(++modelx) << 8 | packet.getUByte(++modelx)));

					}
					
					
		}
			
		/*
		 * for (int i = x; i < size; i ++) { System.out.printf("%c", packet.getUByte(i)); if(packet.getUByte(i) == 0){ System.out.printf("\n"); } }
		 */
		System.out.println("\n-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.");

		modelList.add(model);
	}

	private int AuthoritativeNameServer(int x, int size, PcapPacket packet, JPacketHandlerModel model) {
		try {
			int modelx = x;

			System.out.printf("Type: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
			model.applicationLayer.append(String.format("Type: %d\n", (packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)));
			System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
			model.applicationLayer.append(String.format("Class: %d\n", (packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)));
			byte input[] = new byte[8];
			for (int i2 = 0; i2 < 4; i2++) {
				input[i2] = 0;
			}
			for (int i2 = 4; i2 < 8; i2++) {
				input[i2] = (byte) (packet.getUByte(++x));
				// ++modelx;
			}
			BigInteger unsigned = new BigInteger(input);
			System.out.printf("Time to Live: %d\n", unsigned);
			model.applicationLayer.append(String.format("Time to Live: %d\n", unsigned));
			System.out.printf("Data Length: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
			model.applicationLayer.append(String.format("Data Length: %d\n", (packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)));
			System.out.printf("Class: %d\n", (packet.getUByte(++x) << 8) | packet.getUByte(++x));
			model.applicationLayer.append(String.format("Class: %d\n", (packet.getUByte(++modelx) << 8) | packet.getUByte(++modelx)));
			System.out.printf("Primary Name Server: ");
			model.applicationLayer.append("Primary Name Server: ");
			x += printNextStringDNS(x, size, packet, model);
			modelx = x;
			x++;
			modelx++;
			System.out.printf("Responsible Authority's Mailbox: ");
			model.applicationLayer.append("Responsible Authority's Mailbox: ");
			x += printNextStringDNS(x, size, packet, model);
			modelx = x;
			x--;
			modelx--;
			for (int i2 = 4; i2 < 8; i2++) {
				input[i2] = (byte) (packet.getUByte(++x));
				// ++modelx;
			}
			unsigned = new BigInteger(input);
			System.out.printf("Serial Number: %d\n", unsigned);
			model.applicationLayer.append(String.format("Serial Number: %d\n", unsigned));
			for (int i2 = 4; i2 < 8; i2++) {
				input[i2] = (byte) (packet.getUByte(++x));
				// ++modelx;
			}
			unsigned = new BigInteger(input);
			System.out.printf("Refresh Invterval: %d\n", unsigned);
			model.applicationLayer.append(String.format("Refresh Invterval: %d\n", unsigned));
			for (int i2 = 4; i2 < 8; i2++) {
				input[i2] = (byte) (packet.getUByte(++x));
				// ++modelx;
			}
			unsigned = new BigInteger(input);
			System.out.printf("Retry Invterval: %d\n", unsigned);
			model.applicationLayer.append(String.format("Retry Invterval: %d\n", unsigned));
			for (int i2 = 4; i2 < 8; i2++) {
				input[i2] = (byte) (packet.getUByte(++x));
				// ++modelx;
			}
			unsigned = new BigInteger(input);
			System.out.printf("Expire Limit: %d\n", unsigned);
			model.applicationLayer.append(String.format("Expire Limit: %d\n", unsigned));
			for (int i2 = 4; i2 < 8; i2++) {
				input[i2] = (byte) (packet.getUByte(++x));
				// ++modelx;
			}
			unsigned = new BigInteger(input);
			System.out.printf("Maximum TTL: %d\n", unsigned);
			model.applicationLayer.append(String.format("Maximum TTL: %d\n", unsigned));
		} catch (Exception e) {
		}
		return x;
	}

	private int printNextString(int x, int size, PcapPacket packet, JPacketHandlerModel model) {
		int incr = 0;
		int i = 0;
		for (i = x; i < size; i++) {
			if ((byte) packet.getUByte(i) == 10) {
				System.out.print("\n");
				model.applicationLayer.append("\n");
				try {
					if ((byte) packet.getUByte(i + 1) == 13) {
						System.out.print("\n");
						model.applicationLayer.append("\n");
						incr += 3;
						while (x + incr < size) {
							incr += dumpPayload(x + incr, size, packet, model);
						}
					}
				} catch (java.nio.BufferUnderflowException e) {
					System.out.print("BufferUnderflowException\n");
					model.applicationLayer.append("BufferUnderflowException\n");
				}
				incr++;
				break;
			}
			System.out.print((char) packet.getUByte(i));
			model.applicationLayer.append((char) packet.getUByte(i));
			incr++;
		}
		return incr;
	}

	private int printNextStringDNS(int x, int size, PcapPacket packet, JPacketHandlerModel model) {
		int incr = 0;
		for (int i = x; i < size; i++) {
			// System.out.print(((byte) packet.getUByte(i))+" ");
			if (((byte) packet.getUByte(i) == 0) || ((byte) packet.getUByte(i) == -64)) {
				System.out.print("\n");
				model.applicationLayer.append("\n");
				incr++;
				if ((byte) packet.getUByte(i) == -64) {
					incr++;
				}
				break;
			}
			if (packet.getUByte(i) >= 32 && packet.getUByte(i) <= 126) {
				System.out.print((char) packet.getUByte(i));
				model.applicationLayer.append((char) packet.getUByte(i));
			} else {
				System.out.print(".");
				model.applicationLayer.append(".");
			}
			incr++;
		}
		return incr;
	}

	private int dumpPayload(int x, int size, PcapPacket packet, JPacketHandlerModel model) {
		int incr = 0;
		char asciiChar[] = new char[16];
		char temp;
		boolean isPrinted = false;
		for (int i = x; i < size; i++) {
			isPrinted = false;
			System.out.printf("%02x ", packet.getUByte(x + incr));
			model.applicationLayer.append(String.format("%02x ", packet.getUByte(x + incr)));
			temp = (char) packet.getUByte(x + incr);
			if (temp >= 32 && temp <= 126) {
				asciiChar[incr % 16] = temp;
			} else {
				asciiChar[incr % 16] = '.';
			}
			incr++;
			if (incr % 4 == 0) {
				System.out.printf(" ");
				model.applicationLayer.append(" ");
			}
			if (incr % 16 == 0) {
				System.out.printf("\t%s\n", new String(asciiChar));
				model.applicationLayer.append(String.format("\t%s\n", new String(asciiChar)));
				isPrinted = true;
			}
		}
		if (!isPrinted) {
			System.out.printf("\t%s\n", new String(asciiChar));
			model.applicationLayer.append(String.format("\t%s\n", new String(asciiChar)));
		}
		return incr;
	}
}
