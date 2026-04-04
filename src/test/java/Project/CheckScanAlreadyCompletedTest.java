package Project;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

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
   
}
