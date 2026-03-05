package Project;

import java.util.ArrayList;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.util.NifLookup;
import java.net.Inet4Address;


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
    public byte[] buildSYNpacket () {
        
    }

    /**
     * 
     * @return
     */
    public ArrayList<Integer> scanPorts() {


        return ports;
    }
}
