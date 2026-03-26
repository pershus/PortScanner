/*open module TDT4100_project {
    requires javafx.base;
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.graphics;
    requires org.pcap4j.core;
    requires org.pcap4j.packetfactory.statik;

    requires com.sun.jna;
    requires org.slf4j.simple;

    requires org.junit.jupiter.api;
}*/

open module TDT4100_project {
    // JavaFX Modules
    requires javafx.base;
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.graphics;

    // Networking & Utilities
    requires org.pcap4j.core;
    requires org.pcap4j.packetfactory.statik;
    requires com.sun.jna;
    requires org.slf4j.simple;

    // Testing Modules
    requires org.junit.jupiter.api;
    requires org.junit.platform.commons;

        
    exports Project;
}