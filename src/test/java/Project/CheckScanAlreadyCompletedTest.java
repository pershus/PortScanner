package Project;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class CheckScanAlreadyCompletedTest {
    @Test
    @DisplayName("Ensure check returns true upon succsessful storing")
    void checkLookThroughFileTrue() throws IOException {
      Path history = Path.of("history.json");
        String fixture = """
            {
                "10.10.10.10": {
                    "timestamp": "20260404 120000",
                    "ports": {
                        "5": ["open", "banner"],
                        "6": ["filtered", null],
                        "7": ["closed", null],
                        "8": ["filtered", null],
                        "9": ["filtered", null],
                        "10": ["open", "banner2"]
                    }
                },
                "overview": ["5", "10", "10.10.10.10", "20260404 120000"]
            }
            """;

        Files.writeString(history, fixture);

        HistoryService historyService = new HistoryService();
        assertTrue(historyService.checkIfAlreadyLogged("10.10.10.10", 5, 10));
   }

    @Test
    @DisplayName("Ensure check returns false upon unsuccsessful storing")
    void checkLookThroughFileFalse() throws IOException {
        
        HistoryService historyService = new HistoryService();
        assertFalse(historyService.checkIfAlreadyLogged("10.10.10.10", 299, 320));
    }

    @Test
    @DisplayName("Missing file test")
    void CheckIfFileExistsTrue () throws Exception {
        // Write to history so we are certain it exists
        writer writeObj = new writer();
        // (String IPv4, ArrayList<String> depth_scan_results, ArrayList<ArrayList<Integer>> surface_scan_results)
        ArrayList<String> depth_scan_results = new ArrayList<>();
        depth_scan_results.add("banner");
        depth_scan_results.add("banner");

        ArrayList<ArrayList<Integer>> surface_scan_results = new ArrayList<>();
        ArrayList<Integer> depth = new ArrayList<>();
        depth.add(10);
        depth.add(11);
        surface_scan_results.add(depth);
        ArrayList<Integer> surface = new ArrayList<>();
        surface.add(12);
        surface.add(13);
        surface_scan_results.add(surface);
        ArrayList<Integer> filtered = new ArrayList<>();
        surface_scan_results.add(filtered);

        writeObj.write("10.10.10.10", depth_scan_results, surface_scan_results);


        Path path = Paths.get("history.json");
        boolean exists = false; 
        if (Files.exists(path)) exists = true; 

        assertTrue(exists);
    }
    @Test
    @DisplayName("Missing file test")
    void CheckIfFileExistsFalse () throws Exception {
        

        Path path = Paths.get("history.json");
        Files.deleteIfExists(Path.of("history.json"));

        boolean exists = false; 
        if (Files.exists(path)) exists = true; 

        assertFalse(exists);
    }
}
