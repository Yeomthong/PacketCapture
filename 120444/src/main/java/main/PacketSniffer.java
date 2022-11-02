package main;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class PacketSniffer {
	private ArrayList<JPacketHandlerModel> model;
	
	List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs 
	
	public List<PcapIf> getAlldevs() {
		return this.alldevs;
	}
	
	public String toString() {
		return alldevs.toString();
	}
	
	StringBuilder errbuf = new StringBuilder(); // For any error msgs  

    public List<PcapIf> printAllDevs() {

        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return alldevs;
        }

        System.out.println("Network devices found:");

        int i = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }
		return alldevs;
    }
    
    public void setModel(int n) {

        PcapIf device = alldevs.get(n);

        System.out.printf("\nListening to '%s' :\n", (device.getDescription() != null) ? device.getDescription() : device.getName());

        int snaplen = 64 * 1024;           // Capture all packets, no truncation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        JPacketHandler jpacketHandler = new JPacketHandler(pcap);
        
        //pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
        pcap.loop(1, jpacketHandler, "");  
        
        this.model = jpacketHandler.getModelList();

        pcap.close();
        
        System.out.println("--------------------------------------------------model--------------------------------------------------------");
        int i = 0;
        for(JPacketHandlerModel a : model) {
        	System.out.println("--------------------------------------------------model"+i+"--------------------------------------------------------");
        	
        	System.out.println("----------Time : "+a.time.toString());
        	System.out.println("----------Source IP : "+a.sourceIp.toString());
        	System.out.println("----------Destination IP : "+a.destinationIp.toString());
        	System.out.println("----------Length : "+a.length.toString());
        	System.out.println("----------Infomation : "+a.infomation.toString());
        	
        	System.out.println("----------packet\n"+a.packet.toHexdump());
        	System.out.println("----------packet\n"+a.packet.toString());
        	System.out.println("----------info\n"+a.info.toString());
        	System.out.println("----------frame\n"+a.frame.toString());
        	System.out.println("----------ethernet\n"+a.ethernet.toString());
        	System.out.println("----------internetProtocol\n"+a.internetProtocol.toString());
        	System.out.println("----------transportLayer\n"+a.transportLayer.toString());
        	System.out.println("----------applicationLayer\n"+a.applicationLayer.toString());
        	i++;
        }
        
        System.out.println("--------------------------------------------------END--------------------------------------------------------");
        
    }
    
    public ArrayList<JPacketHandlerModel> getModel(){
    	return model;
    }
    
}