package Project;

import java.util.ArrayList;

interface control {
    public String getHostAddress();
    public String getTargetAddress();

    public ArrayList<Integer> avaliablePorts();
}