module com.example.securedocumentexchange {
    requires javafx.controls;
    requires javafx.fxml;
    requires maverick.base;

    requires org.kordamp.bootstrapfx.core;

    opens com.example.securedocumentexchange to javafx.fxml;
    exports com.example.securedocumentexchange;
    exports com.example.securedocumentexchange.controller;
    opens com.example.securedocumentexchange.controller to javafx.fxml;
}