package Project;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class CheckScanAlreadyCompletedTest {
    private GUI instance; 

    @BeforeEach
    void setUp() {
        try {
        // Starter JavaFX-motoren i bakgrunnen
            javafx.application.Platform.startup(() -> {});
        } catch (IllegalStateException e) {
            // Motoren er allerede startet, så vi ignorerer feilen
        }
        instance = new GUI();
    }

    @Test
    @DisplayName("Ensure check returns correct value")
    void checkLookThroughFile () {
        ArrayList<String> depthScan = new ArrayList<>(List.of("10", "5"));
        ArrayList<ArrayList<Integer>> surface_scan_results = new ArrayList<>();

        // You must add the inner lists before you can use .get()
        surface_scan_results.add(new ArrayList<>()); // Index 0 (Open)
        surface_scan_results.add(new ArrayList<>()); // Index 1 (Closed)
        surface_scan_results.add(new ArrayList<>()); // Index 2 (Filtered)

        // Now these calls will work
        surface_scan_results.get(0).add(10); 
        surface_scan_results.get(0).add(5); 
        surface_scan_results.get(1).add(7);
        try {
            writer appendtext = new writer();
            appendtext.write("10.10.10.10", depthScan, surface_scan_results);
        } catch (Exception e) {
            System.err.println("Could not write to file to file.");
        }

        assertTrue(instance.checkIfAlreadyLogged("192.168.0.200", 5, 10));

    }
}