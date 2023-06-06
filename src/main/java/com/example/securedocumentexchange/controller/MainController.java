package com.example.securedocumentexchange.controller;

import com.example.securedocumentexchange.security.SecurityService;
import com.sshtools.common.publickey.InvalidPassphraseException;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.DataFormat;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ResourceBundle;

public class MainController implements Initializable {

    Window currentWindow;

    SecurityService securityService;

    @FXML
    private Button cryptDocumentBtn;

    @FXML
    private Label cryptStatus;

    @FXML
    private Button decryptDocumentBtn;

    @FXML
    private Label decryptStatus;

    @FXML
    private TextArea decryptedText;

    @FXML
    private TextField docFilePath;

    @FXML
    private Button docToVerifyBtn;

    @FXML
    private TextField documentToCryptPath;

    @FXML
    private TextField documentToDecryptPath;

    @FXML
    private Button documentToSignBtn;

    @FXML
    private TextField doumentToSignPath;

    @FXML
    private TextField encryptedBase64Text;

    @FXML
    private TextField encryptedTextField;

    @FXML
    private Button openkeyFileBtn;

    @FXML
    private TextField openkeyPath;

    @FXML
    private Button privateKeyBtn;

    @FXML
    private Button privateKeyForSignBtn;

    @FXML
    private TextField privateKeyForSignPath;

    @FXML
    private TextField privateKeyPath;

    @FXML
    private TextField pubKeyPath;

    @FXML
    private Button publicKeyFileBtn;

    @FXML
    private Button publicKeyForVerifyBtn;

    @FXML
    private TextField publicKeyPath;

    @FXML
    private Button secretKeyBtn;

    @FXML
    private TextField secretkeyPath;

    @FXML
    private Button sigFileBtn;

    @FXML
    private TextField sigFilePath;

    @FXML
    private Label singStatus;

    @FXML
    private TextArea textToEncryptField;

    @FXML
    private Label verifyStatus;

    @FXML
    private Label clipboardStatus;


    @FXML
    void chooseFile(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();

        File file = fileChooser.showOpenDialog(currentWindow);

        if(file == null){
            return;
        }

        Button btn = (Button) event.getSource();

        switch (btn.getId()){
            case "openkeyFileBtn" -> openkeyPath.setText(file.getAbsolutePath());
            case "secretKeyBtn" -> secretkeyPath.setText(file.getAbsolutePath());
            case "cryptDocumentBtn" -> documentToCryptPath.setText(file.getAbsolutePath());
            case "decryptDocumentBtn" -> documentToDecryptPath.setText(file.getAbsolutePath());
            case "publicKeyFileBtn" -> publicKeyPath.setText(file.getAbsolutePath());
            case "privateKeyBtn" -> privateKeyPath.setText(file.getAbsolutePath());
            case "documentToSignBtn" -> doumentToSignPath.setText(file.getAbsolutePath());
            case "privateKeyForSignBtn" -> privateKeyForSignPath.setText(file.getAbsolutePath());
            case "sigFileBtn" -> sigFilePath.setText(file.getAbsolutePath());
            case "docToVerifyBtn" -> docFilePath.setText(file.getAbsolutePath());
            case "publicKeyForVerifyBtn" -> pubKeyPath.setText(file.getAbsolutePath());
        }
    }

    @FXML
    void encryptText(ActionEvent event) throws GeneralSecurityException, IOException {
        if(publicKeyPath.getText().isEmpty()){
            encryptedTextField.setText("Отсутствует публичный ключ для шифрования");
            return;
        }

        if(textToEncryptField.getText().isEmpty()){
            encryptedTextField.setText("Отсутствует текст для шифрования");
            return;
        }

        File publicKey = new File(publicKeyPath.getText());

        String message = textToEncryptField.getText();

        String encryptedMessage = securityService.encryptMessage(message, publicKey);

        encryptedTextField.setText(encryptedMessage);
    }

    @FXML
    void decryptMessage(ActionEvent event) throws InvalidPassphraseException, GeneralSecurityException, IOException {
        if(privateKeyPath.getText().isEmpty()){
            decryptedText.setText("Отсутствует приватный ключ для дешифровки");
            return;
        }

        if(encryptedBase64Text.getText().isEmpty()){
            decryptedText.setText("Отсутствует Base64 для дешифровки");
            return;
        }

        File privateKey = new File(privateKeyPath.getText());

        String base64Message = encryptedBase64Text.getText();

        String decryptedMessage = securityService.decryptMessage(base64Message, privateKey);

        decryptedText.setText(decryptedMessage);
    }

    @FXML
    void cryptDocument(ActionEvent event) throws IOException, GeneralSecurityException {
        if(openkeyPath.getText().isEmpty()){
            cryptStatus.setText("Отсутствует файл открытого ключа!");
            return;
        }

        if(documentToCryptPath.getText().isEmpty()){
            cryptStatus.setText("Выберите файл для шифрования");
            return;
        }

        File documentToEncrypt = new File(documentToCryptPath.getText());
        File openKey = new File(openkeyPath.getText());

        securityService.encryptDocument(documentToEncrypt, openKey);

        cryptStatus.setText("Документ успешно зашифрован");
    }

    @FXML
    void decryptDocument(ActionEvent event) throws GeneralSecurityException, IOException, InvalidPassphraseException {
        if(secretkeyPath.getText().isEmpty()){
            decryptStatus.setText("Отсутствует файл закрытого ключа!");
            return;
        }

        if(documentToDecryptPath.getText().isEmpty()){
            decryptStatus.setText("Выберите файл для шифрования");
            return;
        }

        File documentToDecrypt = new File(documentToDecryptPath.getText());
        File privateKey = new File(secretkeyPath.getText());

        securityService.decryptDocument(documentToDecrypt, privateKey);

        decryptStatus.setText("Документ успешно расшифрован");
    }

    @FXML
    public void sign(ActionEvent event) throws InvalidPassphraseException, GeneralSecurityException, IOException {
        if(doumentToSignPath.getText().isEmpty()){
            singStatus.setText("Отсутствует документ для подписи");
            return;
        }

        if(privateKeyForSignPath.getText().isEmpty()){
            singStatus.setText("Отсутствует приватный ключ для подписи");
            return;
        }

        File documentForSign = new File(doumentToSignPath.getText());

        File privateKeyFile = new File(privateKeyForSignPath.getText());

        securityService.signDocument(documentForSign, privateKeyFile);

        singStatus.setText("Документ успешно подписан");
    }

    @FXML
    public void verify(ActionEvent event) throws GeneralSecurityException, IOException {
        if(pubKeyPath.getText().isEmpty()){
            verifyStatus.setText("Отсутствует публичный ключ");
            return;
        }

        if(sigFilePath.getText().isEmpty()){
            verifyStatus.setText("Отсутствует файл цифровой подписи");
            return;
        }

        if(docFilePath.getText().isEmpty()){
            verifyStatus.setText("Отсутствует документ для проверки");
            return;
        }

        File sigFile = new File(sigFilePath.getText());

        File docFile = new File(docFilePath.getText());

        File pubKeyFile = new File(pubKeyPath.getText());

        if(securityService.verifyDocument(docFile, sigFile, pubKeyFile)){
            verifyStatus.setText("Подлинность подтверждена");
        } else {
            verifyStatus.setText("Подпись невалидна");
        }
    }

    @FXML
    public void copyToClipboard(ActionEvent event) {
        if (encryptedTextField.getText().isEmpty()){
            clipboardStatus.setText("Вывод пуст");
            return;
        }

        Clipboard clipboard = Clipboard.getSystemClipboard();

        ClipboardContent clipboardContent = new ClipboardContent();

        clipboardContent.put(DataFormat.PLAIN_TEXT, encryptedTextField.getText());

        clipboard.setContent(clipboardContent);

        clipboardStatus.setText("Сообщение скопировано в буфер обмена");
    }

    public MainController(Window window){
        this.currentWindow = window;
    }

    public MainController(){}


    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        securityService = new SecurityService();
    }
}
