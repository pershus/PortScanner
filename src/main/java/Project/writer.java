package Project;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;

public class writer {


    /**
     * * Writes data found in surface and depthscanner to file in a json format (without GSON:( )
     * 
    "192.168.1.1": {
        "timestamp": "2026-03-20T13:25:21.1234",
        "ports": {
            "80": ["open", "220 ProFTPD 1.3.5e Server (Debian)\r\n"],
            "81": ["closed", null]
        }
    }
     * 
     * @param ArrayOpenPorts
     * @param BannersOpenPorts
     * @param IPv4
     * @param portRange
     */

    public writer () {
      
    }

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
                String portInfo = '"' + String.valueOf(i) + '"' +": [\"open\", " + depth_scan_results.get(banner_number) + "],\n" ;
                banner_number++; 
                stringifiedInformation += portInfo;
            } else if (surface_scan_results.get(1).contains(i)) { // Closed
                String portInfo = '"' + String.valueOf(i) + '"' +": [\"open\", null],\n";
                stringifiedInformation += portInfo;
            } else { // Filtered 
                String portInfo = '"' + String.valueOf(i) + '"' + ": [\"filtered\", null],\n";
                stringifiedInformation += portInfo;
            }
        }

        String logger = """
                        {
                            "%s": {
                                "timestamp": %s
                                "ports": {
                                    %s
                                }
                            }
                        }
                        """.formatted(IPv4, timeStamp, stringifiedInformation);
        try {
            Path path = Path.of("home", "wellerman", "Projects", "history.json");
            Files.createDirectories(path.getParent());
            try (BufferedWriter fw = Files.newBufferedWriter(path,StandardCharsets.UTF_8, StandardOpenOption.APPEND)) {
                fw.write(logger);
                fw.newLine();
            }    
        } catch (IOException e) {
            System.err.println("test");
        }

    }
    public boolean containedInHistory() {
        
        return true; 
    }

}