package Project;

import java.util.ArrayList;

import javafx.application.Application;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

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

    @Override
    public void start(Stage stage) throws Exception {
        // Add scene to stage
        Group root = new Group();
        Scene scene = new Scene(root);
        
        //set title of window
        stage.setTitle("Nmap mini");

        //Set width and height of scene 
        stage.setWidth(750);
        stage.setHeight(500);
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
                String address = "172.20.0.1"; //IPv4_address.getText();
                int startPort = 100; //Integer.parseInt(startPort_field.getText());
                int endPort = 199; //Integer.parseInt(endPort_field.getText());

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
                System.out.println("============Scanner class started============");
                scanner scanObj = new scanner(address, startPort, endPort);
                ArrayList<ArrayList<Integer>> portChunks = scanObj.ThreadSplit();
                for (int i = 0; i < portChunks.size(); i++) {
                    scanObj.scan(portChunks.get(i));
                }

            } catch (NumberFormatException ex){
                showError("Ports must be integers");
            }
        });
        root.getChildren().add(submit_targetInformation);

        // Add textarea to show results.
        TextArea results = new TextArea();
        results.setEditable(false);
        results.setPrefWidth(650);
        results.setPrefHeight(300);

        ScrollPane scrollPane = new ScrollPane(results);
        scrollPane.setLayoutX(50);
        scrollPane.setLayoutY(120);
        scrollPane.setPrefWidth(650);
        scrollPane.setPrefHeight(300);

        root.getChildren().add(scrollPane);

        stage.setScene(scene);
        stage.show();
    }

    private void showError(String message) {
        new Alert(Alert.AlertType.ERROR, message).showAndWait();
    }

}
