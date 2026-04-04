package Project;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class CheckWriterWritesCorrectFormat {

    @BeforeEach
    void setUp() {
        assumeTrue(hasDisplay(), "Skipping JavaFX-dependent test on headless server");
        try {
            javafx.application.Platform.startup(() -> {});
        } catch (IllegalStateException ignored) {
            // toolkit already started
        }
    }

    private boolean hasDisplay() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win") || os.contains("mac")) return true;
        return System.getenv("DISPLAY") != null || System.getenv("WAYLAND_DISPLAY") != null;
    }



    @Test
    @DisplayName("Ensure that writer writes info to history file in correct format")

    void checkHistory() throws Exception {
        writer writeObj = new writer();
        // (String IPv4, ArrayList<String> depth_scan_results, ArrayList<ArrayList<Integer>> surface_scan_results)
        ArrayList<String> depth_scan_results = new ArrayList<>();
        depth_scan_results.add("banner");
        depth_scan_results.add("banner");

        ArrayList<ArrayList<Integer>> surface_scan_results = new ArrayList<ArrayList<Integer>>();
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

        String history = Files.readString(Path.of("history.json"));

        // deterministic checks (ignore timestamp variability)
        assertTrue(history.contains("\"10.10.10.10\""));
        assertTrue(history.contains("\"overview\": [\"10\", \"13\", \"10.10.10.10\""));
        assertTrue(history.contains("\"10\": [\"open\", \"banner\"]"));
        assertTrue(history.contains("\"11\": [\"open\", \"banner\"]"));
        assertTrue(history.contains("\"12\": [\"closed\", null]"));
        assertTrue(history.contains("\"13\": [\"closed\", null]"));

    }
}