package Project;

import java.util.ArrayList;
import java.util.stream.IntStream;

/** Comment convention
 * * ! what the code checks and when it throws errors (expected)
 * ? unsolved questions (not necessarily problems but when code is unclear)
* * Overall architecture of code
* TODO quite obvious
* @param name description
* @return description
*/


/** What the public class will do and be responsible for
 * * This class will be the controller for both surfaceScan and depthScan
 * * It will control multithreading in the future
 * TODO add multithreading 
 */
public class scanner {
    private final String IPv4_address;
    private final int startPort; 
    private final int endPort;
    private final int threads; 
    

    public scanner (String address, int startPort, int endPort, int threads) {
        System.out.println("=== Scanner started === ");
        this.IPv4_address = address;
        this.startPort = startPort;
        this.endPort = endPort;
        this.threads = threads; 
    }

    /**
     * ! No checks are run, data passed is assumed to be valid
     * * Makes a array, and fills it with the port numbers between startPort and endPort
     * * Then it, based on threadCount, will make threadCount amount of subarrays, this is done
     * * so later, we can call sepertate threads on each of the subarrays, to increase performance
     * 
     * @return ArrayList<ArrayList<Integer>> portArray_split
     */
    public final ArrayList<ArrayList<Integer>> ThreadSplit () {
        System.out.println("============Array splitting underway============");
        // Split the port numbers into equal parts
        // Make a number array containing all ports and make ThreadCount equal splits 
        int[] portArray = IntStream.rangeClosed(this.startPort, this.endPort).toArray();
        
        // Ensure that we split into a integer amount of subarrays, this means some arrays can contain less than max numbers of ports to check
        int lengthOfSubarray = (int) Math.ceil((double) portArray.length / this.threads);

        //Split portArray into ThreadCount segments (as best it can, if last one is shorter no worry)
        ArrayList<ArrayList<Integer>> portArray_split = new ArrayList<>();
        int portArray_split_counter=0;
        for (int i = 0; i < this.threads; i++) {
            ArrayList<Integer> temporary_array = new ArrayList<>();
            // Fill temporary_array with corresponding vals from portArray

            // the reason we take math.min is to account for the last array, which may not line up exactly with amount of subarrays
            for (int counter = portArray_split_counter; counter < Math.min(portArray_split_counter + lengthOfSubarray, portArray.length) ; counter++) {
                temporary_array.add(portArray[counter]);
            }
            portArray_split.add(temporary_array);
            portArray_split_counter += lengthOfSubarray;
        }

        return portArray_split; // Returns array of arrays e.g. [[1,..50],[51,.,100],...]
    }
    public void scan (ArrayList<Integer> portArray) {
        // Per now, we only have 1 thread, still make the spliiting function for adaptability in the future 
        System.out.println("============Scan begun============");
        System.out.println(portArray);

        surfaceScanner surface = new surfaceScanner(this.IPv4_address, portArray);
        ArrayList<ArrayList<Integer>> surface_scan_results = surface.scanPorts();
        

        depthScanner depth = new depthScanner(surface_scan_results.get(0), this.IPv4_address);
        ArrayList<String> depth_scan_results = depth.handshake();
        System.out.println(depth_scan_results + " depth   " + surface_scan_results + " surface");

        // Write to file
        try {
            writer writerObj = new writer();
            writerObj.write(IPv4_address, depth_scan_results, surface_scan_results);
        } catch (Exception e){
            //throw new Exception("Could not write to file" + e);
            System.out.println("Could not write to file" +e);
        }
        
        System.out.println("======== Succsessfully wrote to file ========");
    }

}
