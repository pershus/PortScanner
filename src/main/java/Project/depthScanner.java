package Project; 


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.ArrayList;

/** Comment convention
 * ! what the code checks and when it throws errors (expected)
 * ? unsolved questions (not necessarily problems but when code is unclear)
* * Overall architecture of code
* TODO quite obvious
* @param name description
* @return description
*/

/**
 * * Will inititate a tcp three way handshake, and upon recieving banner from server, will log the version assosiate with each port. 
 * ! NOTE: This function assumes that the server posts a banner when a succsessful 3-way handshake has been performed. This is not 
 * ! neccecarily the case, but it is how the target is configured in my enviroment. 
 * 
 * @return versionInformation
 */
public class depthScanner implements control{

    private final ArrayList<Integer> portNumber;
    private final String target; 
    /**
     * @param portnumber[int]
     * @param target[String] (IPv4 address of target)
     */
    public depthScanner(ArrayList<Integer> portNumber, String target) {
        this.portNumber = portNumber;
        this.target = target; 
    }

    /**
     * 
     * @param global
     */
    public ArrayList<String> handshake () {
        ArrayList<String> banners = new ArrayList<>();
        for (int port : portNumber) {
            System.out.println("============ Initiating connection to open ports =================");

            try  (Socket socket = new Socket(this.target, port)) { // Try to initate connection
                socket.setSoTimeout(5000); //2.5s

                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String banner = reader.readLine();
                banners.add(banner);
                System.out.println(banner);
                
            } catch (IOException e) {
                throw new IllegalStateException("IO exeption thrown when during 3-way handshake" + e);
            }
        }
        return banners; 

    }

    public String getHostAddress(){
        return "192.168.0.200";
    }

    public String getTargetAddress(){
        return this.target;
    }

    public ArrayList<Integer> avaliablePorts(){
        return this.portNumber;
    }
    
}