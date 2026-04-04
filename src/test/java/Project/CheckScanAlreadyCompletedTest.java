package Project;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;



public class CheckScanAlreadyCompletedTest {
    private GUI instance;
    @BeforeEach
    void setUp() {
        assumeTrue(hasDisplay(), "Skipping JavaFX-dependent test on headless server");

        try {
            javafx.application.Platform.startup(() -> {});
        } catch (IllegalStateException e) {
            // JavaFX toolkit already started
        }
        instance = new GUI();
    }


    private boolean hasDisplay() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win") || os.contains("mac")) return true;
        return System.getenv("DISPLAY") != null ||
        System.getenv("WAYLAND_DISPLAY") != null;
    }


    @Test
    @DisplayName("Ensure check returns correct value")
    void checkLookThroughFile() {
        ArrayList<String> depthScan = new ArrayList<>(List.of("10", "5"));
        ArrayList<ArrayList<Integer>> surface_scan_results = new ArrayList<>();

        surface_scan_results.add(new ArrayList<>()); // Open
        surface_scan_results.add(new ArrayList<>()); // Closed
        surface_scan_results.add(new ArrayList<>()); // Filtered

        surface_scan_results.get(0).add(10);
        surface_scan_results.get(0).add(5);
        surface_scan_results.get(1).add(7);
        try {
            writer appendtext = new writer();
            appendtext.write("10.10.10.10", depthScan, surface_scan_results);
         } catch (Exception e) {
            fail("Could not write test fixture to history.json: " + e.getMessage());
        }

        assertTrue(instance.checkIfAlreadyLogged("10.10.10.10", 5, 10));
    }
}