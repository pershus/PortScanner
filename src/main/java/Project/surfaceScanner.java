package Project;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
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
     * TODO Make the generation of the byte[] SYN packet manual, e.g. remove dependence on pcap4j
     */
    private byte[] buildSYNpacket (int dstPort) throws Exception {
        System.out.println("============Building SYN packet============");
        // Get source IPv4 address
        NetworkInterface nif = NetworkInterface.getByName("br-4843453503f1");
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
    
    public byte[] manualSYNpacket (int dstPort) {
        System.out.println("==== Making a manual SYN packet =====");
        
        // Hardcoded values
        String IPv4_host_hardcoded = "172.20.0.1";
        int dst_port = dstPort; 
        int host_port = 4444;
        int seq_nr = 0; // never sending more than one byte so we dont need to increment
        int ack_nr = 0; // never sending more than one byte so we dont need to increment
        int window_size = 1024; // As synack usually takes 60 to 72 bytes, this size will never miss a filtered response
        int Urgent_pointer = 0;
        String source_mac = "b6:04:ce:e6:50:d9";
        String dst_mac = "aa:bb:cc:dd:ee:ff";
        // =========== Configure TCP packet =============== layer 4
        // =========== Transofrm strings and ints to byte arrays ==============0
        // First we need to find the relevant values to be put into the byte later
        // ! Dest IP, in the params of this class
        // need to convert string to bits
        String[] IPv4_str_numbers = this.IPv4.split("\\."); // \\ for regex

        // IP addresses are never more than 4 bytes, so hardcoding this is fine
        byte[] IPv4_binary_numbers_target = new byte[4];
        IPv4_binary_numbers_target[0] = (byte) Integer.parseInt(IPv4_str_numbers[0]);
        IPv4_binary_numbers_target[1] = (byte) Integer.parseInt(IPv4_str_numbers[1]);
        IPv4_binary_numbers_target[2] = (byte) Integer.parseInt(IPv4_str_numbers[2]);
        IPv4_binary_numbers_target[3] = (byte) Integer.parseInt(IPv4_str_numbers[3]);

        // Host IP
        // Beacuse of how we configured the .yaml file, it will always be on the same subnet, so we just need to look for it
        // TODO Fix this so that it works no matter what you run it against, but for a lab project i deemed it fine. 
        // as the host Ip is hardcoded in the yaml file, we just get that, this will be solved later 
        String[] IPv4_str_numbers_host = IPv4_host_hardcoded.split("\\."); // \\ for regex

        byte[] IPv4_binary_numbers_host = new byte[4];
        IPv4_binary_numbers_host[0] = (byte) Integer.parseInt(IPv4_str_numbers_host[0]);
        IPv4_binary_numbers_host[1] = (byte) Integer.parseInt(IPv4_str_numbers_host[1]);
        IPv4_binary_numbers_host[2] = (byte) Integer.parseInt(IPv4_str_numbers_host[2]);
        IPv4_binary_numbers_host[3] = (byte) Integer.parseInt(IPv4_str_numbers_host[3]);

        // Dst port no
        byte[] dst_port_byte = new byte[2];
        dst_port_byte[0] = (byte) (dst_port >> 8);
        dst_port_byte[1] = (byte) dst_port;
        // Host port no, we can assign a random do it
        // ! Note this can lead to collisons when multithreading, add threadcount to this to mitigate
        byte[] host_port_byte = new byte[2];
        host_port_byte[0] = (byte) (host_port >> 8);
        host_port_byte[1] = (byte) host_port;

        byte[] seq_nr_byte = new byte[4];
        seq_nr_byte[0] = (byte) (seq_nr >> 24);
        seq_nr_byte[1] = (byte) (seq_nr >> 16);
        seq_nr_byte[2] = (byte) (seq_nr >> 8);
        seq_nr_byte[3] = (byte) seq_nr;

        byte[] ack_nr_byte = new byte[4];
        ack_nr_byte[0] = (byte) (ack_nr >> 24);
        ack_nr_byte[1] = (byte) (ack_nr >> 16);
        ack_nr_byte[2] = (byte) (ack_nr >> 8);
        ack_nr_byte[3] = (byte) (ack_nr);

        // Data offset, indicates length of header
        byte[] data_offset_byte = new byte[1];
        data_offset_byte[0] = 0x50;

        // SYN flag
        byte[] flags = new byte[1];
        flags[0] = 0x02;

        byte[] window_size_byte = new byte[2];
        window_size_byte[0] = (byte) (window_size >> 8);
        window_size_byte[1] = (byte) window_size;

        // Checksum
        byte[] TCP_checksum_byte = new byte[2];
        // These values are just placeholders, so we have something set
        TCP_checksum_byte[0] = (byte) 0x00;
        TCP_checksum_byte[1] = (byte) 0x00; 

        // Urgent pointer, needs to be false, set ut as a 16-bit unsigned int, the bit needs to be set to 0
        byte[] Urgent_pointer_byte = new byte[2];
        Urgent_pointer_byte[0] = (byte) (Urgent_pointer >> 8);
        Urgent_pointer_byte[1] = (byte) Urgent_pointer;

        // =========== Make IP Connections ================= Layer 3

        byte[] IP_version_byte = new byte[1];
        IP_version_byte[0] = (byte) 0x45;

        byte[] TOS_byte = new byte[1]; // Type of service
        TOS_byte[0] = (byte) 0x00;

        byte[] Fragmentation_byte = new byte[2];
        Fragmentation_byte[0] = (byte) (0x00 >> 8) ; // Set as nothing as we dont fragment, we do however need to set something
        Fragmentation_byte[1] = (byte) 0x00;

        byte[] protocol_byte = new byte[1];
        protocol_byte[0] = (byte) 0x06;

        byte[] IPlength_byte = new byte[2]; // 16 bits 
        IPlength_byte[0] = (byte) (40 >> 8);
        IPlength_byte[1] = (byte) (40);


        byte[] IPidentification_byte = new byte[2]; // 16 bits
        IPidentification_byte[0] = (byte) 0x00;
        IPidentification_byte[1] = (byte) 0x00;

        byte[] TTL = new byte[1];
        TTL[0] = (byte) 0x40;

        byte[] IP_checksum_byte = new byte[2];
        IP_checksum_byte[0] = (byte) 0x00;
        IP_checksum_byte[1] = (byte) 0x00;

        // ============ Make Network connections ============ Layer 2

        // Network layer
        // host mac, as the mac is hardcoded onto each device, we can confidentely say that this will be constant, so hardcoding is fine
        String[] source_mac_split = source_mac.split(":");
        byte[] mac_parts_source = new byte[6];
        mac_parts_source[0] = (byte) Integer.parseInt(source_mac_split[0],16);
        mac_parts_source[1] = (byte) Integer.parseInt(source_mac_split[1],16);
        mac_parts_source[2] = (byte) Integer.parseInt(source_mac_split[2],16);
        mac_parts_source[3] = (byte) Integer.parseInt(source_mac_split[3],16);
        mac_parts_source[4] = (byte) Integer.parseInt(source_mac_split[4],16);
        mac_parts_source[5] = (byte) Integer.parseInt(source_mac_split[5],16);
        
        // Dst mac, as the mac is hardcoded onto each device, we can confidentely say that this will be constant, so hardcoding is fine
        String[] dst_mac_split = dst_mac.split(":");
        byte[] mac_parts_dst = new byte[6];
        mac_parts_dst[0] = (byte) Integer.parseInt(dst_mac_split[0],16);
        mac_parts_dst[1] = (byte) Integer.parseInt(dst_mac_split[1],16);
        mac_parts_dst[2] = (byte) Integer.parseInt(dst_mac_split[2],16);
        mac_parts_dst[3] = (byte) Integer.parseInt(dst_mac_split[3],16);
        mac_parts_dst[4] = (byte) Integer.parseInt(dst_mac_split[4],16);
        mac_parts_dst[5] = (byte) Integer.parseInt(dst_mac_split[5],16);

        byte[] Ethernet_type_byte = new byte[2];
        Ethernet_type_byte[0] = (byte) (0x0800 >> 8);
        Ethernet_type_byte[1] = (byte) 0x0800;

        // ========================== mash the bytes toghether =======================================
        // We know that our SYN packet will be 20 bytes, because we use no options
        byte[] SYNbyte = new byte[54];
        // Order of the SYN packet is as follows 
        // SrcPort, DstPort, SeqNr, AckNr, HLEN, reserved, URG, ACK, PSH, RSY, SYN, FIN, WindowSize, Checksum, UrgenPointer, Options 
        
        // Put the packets together
        int offset = 0;
        System.arraycopy(mac_parts_dst, 0, SYNbyte, offset, 6); offset += 6;
        System.arraycopy(mac_parts_source, 0, SYNbyte, offset, 6); offset += 6;
        System.arraycopy(Ethernet_type_byte, 0, SYNbyte, offset, 2); offset += 2;

        System.arraycopy(IP_version_byte, 0, SYNbyte, offset, 1); offset += 1;
        System.arraycopy(TOS_byte, 0, SYNbyte, offset, 1); offset += 1;
        System.arraycopy(IPlength_byte, 0, SYNbyte, offset, 2); offset += 2;
        System.arraycopy(IPidentification_byte, 0, SYNbyte, offset, 2); offset += 2;
        System.arraycopy(Fragmentation_byte, 0, SYNbyte, offset, 2); offset += 2;
        System.arraycopy(TTL, 0, SYNbyte, offset, 1); offset += 1;
        System.arraycopy(protocol_byte, 0, SYNbyte, offset, 1); offset += 1;
        System.arraycopy(IP_checksum_byte, 0, SYNbyte, offset, 2); offset += 2;
        System.arraycopy(IPv4_binary_numbers_host, 0, SYNbyte, offset, 4); offset += 4;
        System.arraycopy(IPv4_binary_numbers_target, 0, SYNbyte, offset, 4); offset += 4;

        System.arraycopy(host_port_byte, 0, SYNbyte, offset, 2); offset += 2;
        System.arraycopy(dst_port_byte, 0, SYNbyte, offset, 2); offset += 2;
        System.arraycopy(seq_nr_byte, 0, SYNbyte, offset, 4); offset += 4;
        System.arraycopy(ack_nr_byte, 0, SYNbyte, offset, 4); offset += 4;
        System.arraycopy(data_offset_byte, 0, SYNbyte, offset, 1); offset += 1;
        System.arraycopy(flags, 0, SYNbyte, offset, 1); offset += 1;
        System.arraycopy(window_size_byte, 0, SYNbyte, offset, 2); offset += 2;
        System.arraycopy(TCP_checksum_byte, 0, SYNbyte, offset, 2); offset += 2;
        System.arraycopy(Urgent_pointer_byte, 0, SYNbyte, offset, 2); 
        
        // Calculate checksums
        // Split SYNbyte into a sequence of 16 bit (2 byte) words
        byte[] words = new byte[26];
        for (byte segment : words) {
            
        }

        // add all the indivudual words togheter with 1's complement 




        return SYNbyte;

    }
    

    /**
     * * This code will send a previously built SYN packet to each of the ports contained in this.ports
     * * this.ports is a array of integers, all of which this code will send a SYN packet to. 
     * * If it gets a SYNACK message back, add that port number to the list of open ports. 
     * ! Check if SYNpacket was built correctly
     * @return openports
     * 
     */
    public ArrayList<Integer> scanPorts() {
        byte[] SYNpacket;
        ArrayList<Integer> openports = new ArrayList<>();
        ArrayList<Integer> closedports = new ArrayList<>();
        ArrayList<Integer> filteredports = new ArrayList<>();

        for (int i = 0; i < this.ports.size()-1; i++) {
            // Send packet to destination host and port no. 
            try {
                SYNpacket = this.buildSYNpacket(this.ports.get(i));
            } catch (Exception e) {
                throw new IllegalStateException("Failed in building of SYN packet or failed in the setup of network interface: " + e.getMessage());
            }


            // Send SYN packet to victim at assosiated port nr
            PcapHandle handle;
            try {
                PcapNetworkInterface nif = Pcaps.getDevByName("br-4843453503f1"); 
                handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 2000);

                // Ensures that we log the packets that we recieve, other packets, like IMCP to map the network are ignored
                handle.setFilter(
                    "tcp and src host " + InetAddress.getByName(this.IPv4).getHostAddress() + " and src port " + this.ports.get(i),
                    BpfProgram.BpfCompileMode.OPTIMIZE
                );
                handle.sendPacket(SYNpacket);

            } catch (UnknownHostException | NotOpenException | PcapNativeException e) {
                throw new IllegalStateException("Failed in sending of SYN packet", e);
            }

            // Recieve SYN ACK
            ExecutorService executor = Executors.newSingleThreadExecutor();
            Future<Packet> future = executor.submit(() -> handle.getNextPacketEx());
            
            try {
                Packet response = future.get(2,TimeUnit.SECONDS);
                TcpPacket tcp = response.get(TcpPacket.class); 
                // Reading information from header of response
                if (tcp.getHeader().getSyn() && tcp.getHeader().getAck()) {
                    openports.add(this.ports.get(i));
                } else if (tcp.getHeader().getRst()) {
                    closedports.add(this.ports.get(i));
                }
            } catch (java.util.concurrent.TimeoutException | InterruptedException | ExecutionException e) {
                filteredports.add(this.ports.get(i));
            } finally {
                try {
                    handle.breakLoop(); // ← signals getNextPacketEx to stop
                } catch (NotOpenException e) {
                    // already closed, fine
                }
                if (handle.isOpen()) handle.close();
                executor.shutdown();
            }            
        }
        System.out.println("hei");
        System.out.println(openports + ": bonjour" + closedports + "!!" + filteredports);
    
        return openports;
    }
}
