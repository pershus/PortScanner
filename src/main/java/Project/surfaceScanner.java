package Project;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

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
import org.pcap4j.packet.namednumber.IpVersion;
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
public class surfaceScanner extends scanner {
    
    private final ArrayList<Integer> ports;
    private final String IPv4;
    
    public surfaceScanner (String IPv4_address, ArrayList<Integer> portArray) {
        super(IPv4_address, portArray.get(0), portArray.get(portArray.size() - 1));

           if (!IPv4_address.startsWith("172.20.")) {
                throw new IllegalArgumentException("IP address must be on the 172.20.0.0/24 network, got: " + IPv4_address);
            }

        this.IPv4 = IPv4_address;
        this.ports = portArray;
    }

    /**
     * * NOTE: this is private beacuse no other class will ever have the need to generate a SYN packet.
     * * More or less just a bunch of flags bundled 
     * @return
     */
    private byte[] buildSYNpacket (int dstPort) throws Exception {
        System.out.println("============Building SYN packet============");
        // Get source IPv4 address
        NetworkInterface nif = NetworkInterface.getByName("br-c4421a0368fb");
        Inet4Address sourceAddress = Collections.list(nif.getInetAddresses())
            .stream()
            .filter(addr -> addr instanceof Inet4Address)
            .map(addr -> (Inet4Address) addr)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("No IPv4 on docker0"));
        
        Inet4Address destinationAddress = (Inet4Address) InetAddress.getByName(this.IPv4);
        System.out.println(destinationAddress);
        System.out.println(sourceAddress);
        // Get mac addresses
        byte[] srcMac;
        byte[] dstMac;
        try (java.net.DatagramSocket socket = new java.net.DatagramSocket()) {
            socket.connect(InetAddress.getByName(this.IPv4), 5555);
            InetAddress sourceAddressT = socket.getLocalAddress();
            NetworkInterface nifT = NetworkInterface.getByInetAddress(sourceAddressT); // finds br-c4421a0368fb automatically
            srcMac = new byte[]{(byte)0x96, (byte)0x21, (byte)0x45, (byte)0x7e, (byte)0x3e, (byte)0x3d};
            dstMac = srcMac; // We are assuming communication between two enteties on one pc, so they have the same mac
            // further, the mac will stay constant, so hardcoding it is fine. 
        }

        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder()
            .srcPort(TcpPort.getInstance((short) 4444))
            .dstPort(TcpPort.getInstance((short) dstPort))
            .sequenceNumber(0)
            .acknowledgmentNumber(0)
            .dataOffset((byte) 6)
            .syn(true)
            .ack(false)
            .window((short) 1024)
            .checksum((short) 0)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .srcAddr(sourceAddress)        // add this
            .dstAddr(destinationAddress)   // add this
            .payloadBuilder(new UnknownPacket.Builder().rawData(new byte[0]));

        // Layer 3 — IPv4
        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
            .version(IpVersion.IPV4)
            .tos(IpV4Rfc791Tos.newInstance((byte) 0))
            .ttl((byte) 64)
            .protocol(IpNumber.TCP)
            .srcAddr((Inet4Address) sourceAddress)
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

        for (int i = 0; i < this.ports.size()-1; i++) {
            // Send packet to destination host and port no. 
            PcapHandle handle;
            try {
                SYNpacket = this.buildSYNpacket(this.ports.get(i));
                System.out.println("==== Built SYN PACKET ====");
                PcapNetworkInterface pcapNif = Pcaps.getDevByName("br-c4421a0368fb"); // Make tunnel to docker conatiner
                handle = pcapNif.openLive(65536, PromiscuousMode.PROMISCUOUS, 20); // Activate the tunnel we just made
            } catch (Exception e) {
                throw new IllegalStateException("Failed in building of SYN packet or failed in the setup of network interface: " + e.getMessage());
            }
            try { // TODO handle adding of openports correctly
                handle.sendPacket(SYNpacket);
                openports.add(this.ports.get(i));
            } catch (NotOpenException | PcapNativeException ex) {
                System.getLogger(surfaceScanner.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            }
            // Recieve (hopefully) SYNACK back from host
                try {
                    byte[] recievedPacket = handle.getNextRawPacket(); // Get next raw packet (including headers)
                    System.out.println(Arrays.toString(recievedPacket));
                } catch (NotOpenException e) {
                    throw new InternalError("Recieved packet of non-accepted format");
                }
                

        }

        return openports;
    }
}
