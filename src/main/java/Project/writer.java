package Project;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;

/** Comment convention
 * ! what the code checks and when it throws errors (expected)
 * ? unsolved questions (not necessarily problems but when code is unclear)
* * Overall architecture of code
* TODO quite obvious
* @param name description
* @return description
*/

public class writer {
    public writer () {
      
    }
    /**
     * ! Checks that the writer funtcion logs without error. 
     * * at a time x when the write method of the writer object is called, the system time is noted.
     * * we then loop thorugh the ports scanned, and find the min and max.
     * 
     *  * Then we manufacture the string to fit json format and add it to a history.json file. 
     * @param ArrayOpenPorts
     * @param BannersOpenPorts
     * @param IPv4
    */
    public void write (String IPv4, ArrayList<String> depth_scan_results, ArrayList<ArrayList<Integer>> surface_scan_results) throws Exception{
        LocalDateTime currentTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd HHmmss");
        String timeStamp = currentTime.format(formatter);


        int minPortNumber = 99999; // always larger than the largets port number, meaning 
        int maxPortNumber = 0; // smallest possible port no is always > 0 
        for (int num : surface_scan_results.get(0)) {
            if (num < minPortNumber) minPortNumber = num;
            if (num > maxPortNumber) maxPortNumber = num;
        }
        for (int num : surface_scan_results.get(1)) {
            if (num < minPortNumber) minPortNumber = num;
            if (num > maxPortNumber) maxPortNumber = num;
        }
        for (int num : surface_scan_results.get(2)) {
            if (num < minPortNumber) minPortNumber = num;
            if (num > maxPortNumber) maxPortNumber = num;
        }

        int banner_number = 0;

        String stringifiedInformation = "";
        for (int i = minPortNumber; i <= maxPortNumber; i++) {
    
            if (surface_scan_results.get(0).contains(i)) { // Open
                String portInfo = "            " + '"' + String.valueOf(i) + '"' +": [\"open\", \"" + depth_scan_results.get(banner_number) + "\"],\n" ;
                banner_number++; 
                stringifiedInformation += portInfo;
            } else if (surface_scan_results.get(1).contains(i)) { // Closed
                String portInfo = "            " + '"' + String.valueOf(i) + '"' +": [\"open\", null],\n";
                stringifiedInformation += portInfo;
            } else { // Filtered 
                String portInfo = "            " +'"' + String.valueOf(i) + '"' + ": [\"filtered\", null],\n";
                stringifiedInformation += portInfo;
            }
        }

        String logger = """
                        {
                            "%s": {
                                "timestamp": %s,
                                "ports": {
                        %s
                                }
                            }
                            "overview": ["%s", "%s", "%s", "%s"]
                        }
                        """.formatted(IPv4, timeStamp, stringifiedInformation, minPortNumber, maxPortNumber, IPv4, timeStamp);


        /**
         * FIlewriter is what writes the logger to the file, and bufferedwriter is a writer obj that wraps 
         * the filewriter to reduce the amonut of redundant operations, increasing efficency
         */
        try (FileWriter fw = new FileWriter("history.json", true);
            BufferedWriter writer = new BufferedWriter(fw)) {
            writer.write(logger);
            
        } catch (IOException e) {
            System.out.println("Error" + e);
        }

    }
    /**
     * * checks if the scan has been completed recently on the same ip and the same port range, if so, we skip 
     * * a new scan. 
     * 
     * * Know the format to check "overview": [20, 31, "192.168.0.201", "20260324 155506"]

     * 
     * @param IPv4
     * @param startPort
     * @param endPort
     * @param timeout In seconds
     */
    public boolean containedInHistory(String IPv4, int startPort, int endPort, int timeout) {
        // Iterate through file, and if it starts with overview, strip all that is not a array, then check. 
        return true; 
    }

}