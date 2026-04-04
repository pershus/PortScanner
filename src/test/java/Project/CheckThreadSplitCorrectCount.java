package Project;


import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;


public class CheckThreadSplitCorrectCount {

    @Test
    void ThreadSplitCorrect () {
        // Make scanner object
        scanner scan1 = new scanner("10.10.10.10", 250, 300, 2);
        // String address, int startPort, int endPort, int threads)
        ArrayList<ArrayList<Integer>> vals1 = scan1.ThreadSplit();

        assertEquals(26, vals1.get(0).size()); // include 250 and up to 275 = 25 + 1 = 26 

        scanner scan2 = new scanner("10.10.10.10", 250, 253, 2);
        // String address, int startPort, int endPort, int threads)
        ArrayList<ArrayList<Integer>> vals2 = scan2.ThreadSplit();

        assertEquals(2, vals2.get(0).size()); 

    }
}