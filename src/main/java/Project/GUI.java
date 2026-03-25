package Project;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.Stage;


/*
VS Code — connected via SSH to the scanner VM, edit code there directly
Terminal on your personal machine — ssh -X wellerman@<tailscale-ip> to get a session with display forwarding
In that terminal — run sudo -E mvn exec:java -Dexec.mainClass="Project.GUI" and the GUI appears on your personal machine's screen
*/
public class GUI extends Application {
    
    /** Comment convention
     * ! what the code checks and when it throws errors (expected)
     * ? unsolved questions (not necessarily problems but when code is unclear)
     * * Overall architecture of code
     * TODO quite obvious
     * @param name description
     * @return description
     */

    public static void main(String[] args) {
        launch(args);
    }


    /**
     * ! This code checks that port numbers are integers
     * ! Checks that port range is <= 100
     * 
     * * This code generates the GUI the user will interact with, it is intentionally kept minimal. 
     * * the GUI is generated with the javafx library, see comments on how exatly this is done
     * * returns nothing, as it just keeps the GUI open at all times.
     * 
     * TODO Implement scanner 
     * TODO Implement multithreading, so limit on port count can be increased. 
     */
    TextArea results = new TextArea();

    @Override
    public void start(Stage stage) throws Exception {
        // Add scene to stage
        Group root = new Group();
        Scene scene = new Scene(root);
        
        //set title of window
        stage.setTitle("Nmap mini");

        //Set width and height of scene 
        stage.setWidth(750);
        stage.setHeight(800);
        stage.setResizable(true);

       // IPv4 label and input
        Label IPv4_target_label = new Label("IPv4 address of target");
        IPv4_target_label.setLayoutX(50);
        IPv4_target_label.setLayoutY(30);
        root.getChildren().add(IPv4_target_label);

        TextField IPv4_address = new TextField();
        IPv4_address.setPromptText("e.g. 127.0.0.1");
        IPv4_address.setLayoutX(50);
        IPv4_address.setLayoutY(55);
        root.getChildren().add(IPv4_address);
        
        // Start port label and input
        Label startPort_number_label = new Label("Starting port:");
        startPort_number_label.setLayoutX(275);
        startPort_number_label.setLayoutY(30);
        root.getChildren().add(startPort_number_label);

        TextField startPort_field = new TextField();
        startPort_field.setPromptText("e.g. 100");
        startPort_field.setLayoutX(275);
        startPort_field.setLayoutY(55);
        startPort_field.setPrefWidth(100);
        root.getChildren().add(startPort_field);

        // End port label and input
        Label endPort_number_label = new Label("Ending port:");
        endPort_number_label.setLayoutX(400);
        endPort_number_label.setLayoutY(30);
        root.getChildren().add(endPort_number_label);

        TextField endPort_field = new TextField();
        endPort_field.setPromptText("e.g. 200");
        endPort_field.setLayoutX(400);
        endPort_field.setLayoutY(55);
        endPort_field.setPrefWidth(100);
        root.getChildren().add(endPort_field);

        //Add submit button
        Button submit_targetInformation = new Button("Submit");
        submit_targetInformation.setLayoutX(500);
        submit_targetInformation.setLayoutY(55);
        // * Add action on event 
        submit_targetInformation.setOnAction(event -> {
            try {
                // TODO Remove hardcoded addresses, only used for testing 
                String address = "192.168.0.201"; //IPv4_address.getText();
                int startPort = Integer.parseInt(startPort_field.getText());
                int endPort = Integer.parseInt(endPort_field.getText());

                // ! Check that address consists of valid IP address
                String[] address_split = address.split("\\.");
                //all values of the ip address must be nums between 0 and 256. there must also be 4 vals
                
                if (address_split.length != 4) {
                    showError("IP address must contain 4 bytes");
                    return;
                }
                for (int i = 0; i < 4; i++) {
                    try {
                        int temp_val = Integer.parseInt(address_split[i]);
                        if (temp_val < 0 || temp_val > 256) {
                            showError("nums in IP must be between 0 and 256");
                            return;
                        }
                    } catch (NumberFormatException ex) {
                        showError("values in IP address must be nums");
                        return;
                    }
                }


                // ! Check that port range is < 100
                if (endPort-startPort > 100) {
                    showError("Ports must be in a 100 port range");
                    return;
                }
                // make a writer obj, establish a boolean value if searched before x time or no

                // Check if range and ip already scanned.
                boolean scanExists = this.updateResultsPage(address, startPort, endPort);
                if (!scanExists) { // If scan doesn't exist, start scanner
                    System.out.println("============Scanner class started============");
                    scanner scanObj = new scanner(address, startPort, endPort, 1);
                    ArrayList<ArrayList<Integer>> portChunks = scanObj.ThreadSplit();

                    Thread scanThread = new Thread(() -> {
                        for (int i = 0; i < portChunks.size(); i++) {
                            scanObj.scan(portChunks.get(i));
                        }
                        // update UI when done
                        Platform.runLater(() -> {
                            System.out.println("Scan complete");
                            try {
                                String lastContent = Files.readString(Path.of("history.json"));
                                String[] allScans = lastContent.split("(?<=\\})(?=\\s*\\{)");
                                results.appendText(allScans[allScans.length-1]);
                            } catch (IOException e) {
                                System.out.println("error reading history" + e);
                            }

                        });
                    });
                    scanThread.setDaemon(true);
                    scanThread.start();
                    
                } else {
                    System.out.println("Scan already exists, displaying previous results");
                } 


               


            } catch (NumberFormatException ex){
                showError("Ports must be integers");
            }
        });
        root.getChildren().add(submit_targetInformation);

        // Add textarea to show results.
        
        results.setEditable(false);
        results.setPrefWidth(650);
        results.setPrefHeight(500);

        ScrollPane scrollPane = new ScrollPane(results);
        scrollPane.setLayoutX(50);
        scrollPane.setLayoutY(120);
        scrollPane.setPrefWidth(650);
        scrollPane.setPrefHeight(500);

        root.getChildren().add(scrollPane);

        stage.setScene(scene);
        stage.show();
    }

    private boolean updateResultsPage(String IP_address, int minPortNumber, int maxPortNumber) {
        String complete_file = null;
        String[] scanArray;
        try {
            // Reads the entire file into a single String
            Path path = Paths.get("history.json");
            complete_file = new String(Files.readAllBytes(path));
            scanArray = complete_file.split("(?<=\\})(?=\\s*\\{)");
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        List<String> allScans = new ArrayList<>();
        for (String s : scanArray) {
            if (!s.trim().isEmpty()) {
                allScans.add(s.trim());
            }
        }
        

        // read from file
        // We know that the IP address must start with 192.168. 
        // This is a rule we made early on to ensure that no unintended attacks happen, this also means that we can find the line with this 
        // String, then paste it out as IP address
        List<String> overview = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader("history.json"))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("overview")) overview.add(line.substring(16));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(overview); // [[20, 31, 192.168.0.201, 20260324 155402], [20, 31, "192.168.0.201", "20260324 155506"], ["20", "31", "192.168.0.201", "20260324 180143"], ["20", "31", "192.168.0.201", "20260324 180648"], ["20", "31", "192.168.0.201", "20260324 180756"]]

        
        List<String> current = new ArrayList<>();
        current.add(String.valueOf(minPortNumber));
        current.add(String.valueOf(maxPortNumber));     
        current.add(IP_address);
        LocalDateTime currentTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd HHmmss");
        String timeStamp = currentTime.format(formatter);
        current.add(timeStamp);
     
        for (int i = 0; i < overview.size(); i++) {
            String entry = overview.get(i);
            
            // Clean up the string as you were doing
            String clean = entry.replace("[", "").replace("]", "").replace("\"", "");
            String[] parts = clean.split(",");

            if (parts.length >= 3) {
                String histStart = parts[0].trim();
                String histEnd = parts[1].trim();
                String histIp = parts[2].trim();

                // Exact equality check
                if (histStart.equals(String.valueOf(minPortNumber)) && 
                    histEnd.equals(String.valueOf(maxPortNumber)) && 
                    histIp.equals(IP_address)) {
                        
                    results.appendText("Exact match found in history at index " + i + ". Skipping scan.\n");
                    
                    // KEY CHANGE: Use index 'i' to get the CORRECT scan, not the last one
                    if (i < allScans.size()) {
                        String matchedScan = allScans.get(i);
                        results.appendText(matchedScan);
                    }

                    return true; // Match found, stop looking
                }
            }
        }

        return false;
    }

    public void writeNewScan(String logger) {
        results.appendText(logger);
    }

    private void showError(String message) {
        new Alert(Alert.AlertType.ERROR, message).showAndWait();
    }

}
