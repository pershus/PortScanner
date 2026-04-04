package Project;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class HistoryService {
    /**
     * * Will check if entry is already logged in history.json
     * 
     * ! Checks that path exists
     * @param IP_address
     * @param minPortNumber
     * @param maxPortNumber
     * @return boolean
     */
    public boolean checkIfAlreadyLogged(String IP_address, int minPortNumber, int maxPortNumber){
        // If the file does not exist, we guarantee that nothing is logged. 
        Path path = Paths.get("history.json");
        if (!Files.exists(path)) return false;
        
        String complete_file;

        try {
            // Reads the entire file into a single String
            complete_file = new String(Files.readAllBytes(path));
        } catch (IOException e) {
            return false;
        }
        
        List<String> alreadySearchedList = new ArrayList<>();
        Pattern pattern = Pattern.compile("\"overview\":\\s*(\\[.*?\\])");
        Matcher matcher = pattern.matcher(complete_file);

        
        while(matcher.find()) {
            alreadySearchedList.add(matcher.group(1));
        }
        String currentMatchString = "\"" + minPortNumber + "\", \"" + maxPortNumber + "\", \"" + IP_address + "\"";
        for(String entry : alreadySearchedList) {
            if(entry.contains(currentMatchString)) return true; 
        }
        
        return false; 
    }


}
