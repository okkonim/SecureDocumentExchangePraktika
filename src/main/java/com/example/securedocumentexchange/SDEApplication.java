package com.example.securedocumentexchange;

import com.example.securedocumentexchange.controller.MainController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class SDEApplication extends Application {

    static MainController mainController;

    @Override
    public void start(Stage stage) throws IOException {

        FXMLLoader fxmlLoader = new FXMLLoader(SDEApplication.class.getResource("sde-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load());
        stage.setTitle("Secure Document Exchange");
        stage.setScene(scene);
        mainController = new MainController(scene.getWindow());
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}