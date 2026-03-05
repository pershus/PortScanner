package Project;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;

/** Comment convention
 * * ! what the code checks and when it throws errors (expected)
 * ? unsolved questions (not necessarily problems but when code is unclear)
* * Overall architecture of code
* TODO quite obvious
* @param name description
* @return description
*/
public class surfaceScanner {
    
    private String IPv4;
    private ArrayList<Integer> ports;
    
    public surfaceScanner (String IPv4_address, ArrayList<Integer> portArray) {
        this.IPv4 = IPv4_address;
        this.ports = portArray;
    }
    /**
     * 
     * @return
     */
    private byte[] buildSYNpacket (int dstPort) throws Exception {
        System.out.println("============Building SYN packet============");
        // Get source IPv4 address
        NetworkInterface nif = NetworkInterface.getByName("docker0");
        InetAddress srcAddress = nif.getInetAddresses().nextElement();
        InetAddress destinationAddress = InetAddress.getByName(this.IPv4);
        // Get mac addresses
        byte[] srcMac = NetworkInterface.getByName("wlp3s0").getHardwareAddress();
        byte[] dstMac = NetworkInterface.getByName("docker0").getHardwareAddress();

        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder()
            .srcPort(TcpPort.getInstance((short) 4444))  // random source port
            .dstPort(TcpPort.getInstance((short) dstPort))     // port to scan
            .sequenceNumber(0)
            .acknowledgmentNumber(0)
            .dataOffset((byte) 6)
            .syn(true)          // SYN flag
            .ack(false)
            .window((short) 1024)
            .checksum((short) 0)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .payloadBuilder(new UnknownPacket.Builder().rawData(new byte[0]));

        // Layer 3 — IPv4
        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
            .tos(IpV4Rfc791Tos.newInstance((byte) 0))
            .ttl((byte) 64)
            .protocol(IpNumber.TCP)
            .srcAddr((Inet4Address) srcAddress)
            .dstAddr((Inet4Address) destinationAddress)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .payloadBuilder(tcpBuilder);

        // Layer 2 — Ethernet
        EthernetPacket.Builder ethBuilder = new EthernetPacket.Builder()
            .srcAddr(MacAddress.getByAddress(srcMac))
            .dstAddr(MacAddress.getByAddress(dstMac))
            .type(EtherType.IPV4)
            .payloadBuilder(ipBuilder)
            .paddingAtBuild(true);

        EthernetPacket packet = ethBuilder.build();
        return packet.getRawData();
    }
    

    /**
     * * This code will send a previously built SYN packet to each of the ports contained in this.ports
     * * this.ports is a array of integers, all of which this code will send a SYN packet to. 
     * * If it gets a SYNACK message back, add that port number to the list of open ports. 
     * ! Check if SYNpacket was built correctly
     * @return openports
     */
    public ArrayList<Integer> scanPorts() {
        byte[] SYNpacket;
        ArrayList<Integer> openports = new ArrayList<>();

        for (int i = 0; i < this.ports.size(); i++) {
            PcapHandle handle;
            try {
                SYNpacket = this.buildSYNpacket(ports.get(i));
                PcapNetworkInterface pcapNif = Pcaps.getDevByName("docker0"); // Make tunnel to docker conatiner
                handle = pcapNif.openLive(65536, PromiscuousMode.PROMISCUOUS, 20); // Activate the tunnel we just made
            } catch (Exception e) {
                throw new IllegalStateException("Failed in building of SYN packet or failed in the setup of network interface: " + e.getMessage());
            }

            try {            
                handle.sendPacket(SYNpacket);
                openports.add(this.ports.get(i));
            } catch (NotOpenException | PcapNativeException ex) {
                System.getLogger(surfaceScanner.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            }

        }

        return openports;
    }
}
