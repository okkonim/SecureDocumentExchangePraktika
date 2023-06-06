package com.example.securedocumentexchange.security;

import com.sshtools.common.publickey.InvalidPassphraseException;
import com.sshtools.common.publickey.SshKeyUtils;
import com.sshtools.common.ssh.components.SshPublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class SecurityService {
    PublicKey publicKey;

    PrivateKey privateKey;

    public String encryptMessage(String message, File publicKeyFile) throws IOException, GeneralSecurityException {
        SshPublicKey sshPublicKey = SshKeyUtils.getPublicKey(publicKeyFile);
        PublicKey publicKey = sshPublicKey.getJCEPublicKey();

        Key aesKey = generateAes(128);

        IvParameterSpec iv = generateIv(aesKey.getEncoded().length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv.getIV()));

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedAesKey = cipher.doFinal(aesKey.getEncoded());

        byte[] outputMessageWithKey = new byte[encryptedBytes.length + encryptedAesKey.length + iv.getIV().length];

        System.arraycopy(iv.getIV(), 0, outputMessageWithKey, 0, iv.getIV().length);
        System.arraycopy(encryptedAesKey, 0, outputMessageWithKey, iv.getIV().length, encryptedAesKey.length);
        System.arraycopy(encryptedBytes, 0, outputMessageWithKey, iv.getIV().length + encryptedAesKey.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(outputMessageWithKey);
    }


    private SecretKeySpec generateAes(int keySize) {
        byte[] aesByte = new byte[keySize / 8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(aesByte);
        return new SecretKeySpec(aesByte, "AES");
    }

    private IvParameterSpec generateIv(int keySize) {
        byte[] ivByte = new byte[keySize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivByte);
        return new IvParameterSpec(ivByte);
    }

    public String decryptMessage(String message, File privateKeyFile) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        byte[] encodedBytes = Base64.getDecoder().decode(message);
        byte[] iv = Arrays.copyOfRange(encodedBytes, 0, 16);
        byte[] aesKeyEnc = Arrays.copyOfRange(encodedBytes, 16, 512 + 16);
        byte[] dataEnc = Arrays.copyOfRange(encodedBytes, 512 + 16, encodedBytes.length);

        PrivateKey privateKey = SshKeyUtils.getPrivateKey(privateKeyFile, "").getPrivateKey().getJCEPrivateKey();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedAesKey = cipher.doFinal(aesKeyEnc);
        SecretKey aesKey = new SecretKeySpec(decodedAesKey, "AES");

        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] decodedData = cipher.doFinal(dataEnc);
        String data = new String(decodedData, StandardCharsets.UTF_8);
        return data;
    }

    public void encryptDocument(File document, File publicKeyFile) throws IOException, GeneralSecurityException {
        // Получаем имя файла
        String filename = document.getName();
        // Создаем имя зашифрованного файла
        String encryptedFilename = filename + ".sde";
        // Создаем файл зашифрованного документа в той же директории, где и оригинальный документ
        File encryptedFile = new File(document.getParent(), encryptedFilename);

        // Получаем данные из файла
        StringBuilder stringBuilder = new StringBuilder();
        String line;

        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(document))) {
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
        }

        String data = stringBuilder.toString();

        // Получаем открытый ключ из файла
        SshPublicKey sshPublicKey = SshKeyUtils.getPublicKey(publicKeyFile);
        PublicKey publicKey = sshPublicKey.getJCEPublicKey();

        // Инициализируем шифрование с помощью алгоритмов
        Key aesKey = generateAes(128);
        IvParameterSpec iv = generateIv(aesKey.getEncoded().length);

        Cipher cipherAES = Cipher.getInstance("AES/GCM/NoPadding");
        cipherAES.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv.getIV()));
        byte[] encryptedBytes = cipherAES.doFinal(data.getBytes());

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = cipherRSA.doFinal(aesKey.getEncoded());

        byte[] outputDataWithKey = new byte[encryptedBytes.length + encryptedAesKey.length + iv.getIV().length];
        System.arraycopy(iv.getIV(), 0, outputDataWithKey, 0, iv.getIV().length);
        System.arraycopy(encryptedAesKey, 0, outputDataWithKey, iv.getIV().length, encryptedAesKey.length);
        System.arraycopy(encryptedBytes, 0, outputDataWithKey, iv.getIV().length + encryptedAesKey.length, encryptedBytes.length);

        try (FileOutputStream outputStream = new FileOutputStream(encryptedFile)) {
            outputStream.write(outputDataWithKey);
            outputStream.flush();
        }
    }


    public void decryptDocument(File document, File privateKeyFile) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        // Получаем имя файла
        String filename = document.getName();
        // Создаем имя расшифрованного файла
        String decryptedFilename = filename + ".txt";
        // Создаем файл расшифрованного документа в той же директории, где и оригинальный документ
        File decryptedFile = new File(document.getParent(), decryptedFilename);

        // Получаем данные из зашифрованного файла
        byte[] encodedBytes;

        try (FileInputStream inputStream = new FileInputStream(document)) {
            int fileSize = (int) document.length();
            encodedBytes = new byte[fileSize];
            inputStream.read(encodedBytes);
        }

        // Извлекаем параметры из зашифрованного файла
        byte[] iv = Arrays.copyOfRange(encodedBytes, 0, 16);
        byte[] aesKeyEnc = Arrays.copyOfRange(encodedBytes, 16, 512 + 16);
        byte[] dataEnc = Arrays.copyOfRange(encodedBytes, 512 + 16, encodedBytes.length);

        // Проверяем, что файл с зашифрованным документом существует и является файлом
        if (!document.exists() || !document.isFile()) {
            throw new IOException("Invalid input file");
        }

        // Проверяем, что файл закрытого ключа существует и является файлом
        if (!privateKeyFile.exists() || !privateKeyFile.isFile()) {
            throw new IOException("Invalid secret key file");
        }

        // Получаем закрытый ключ
        PrivateKey privateKey = SshKeyUtils.getPrivateKey(privateKeyFile, "").getPrivateKey().getJCEPrivateKey();

        // Расшифровываем симметричный ключ с помощью закрытого ключа
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyDec = cipher.doFinal(aesKeyEnc);

        // Расшифровываем данные с помощью симметричного ключа
        Key aesKey = new SecretKeySpec(aesKeyDec, "AES");
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] dataDec = cipher.doFinal(dataEnc);
        String data = new String(dataDec, "UTF-8");

        // Записываем расшифрованные данные в файл
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(decryptedFile))) {
            writer.write(data);
        }
    }



    public void signDocument(File document, File privateKeyFile) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        // Проверяем, что файл документа существует и является файлом
        if (!document.exists() || !document.isFile()) {
            throw new IOException("Invalid input file");
        }

        // Получаем закрытый ключ
        PrivateKey privateKey = SshKeyUtils.getPrivateKey(privateKeyFile, "").getPrivateKey().getJCEPrivateKey();

        // Получаем данные из файла документа
        byte[] data = Files.readAllBytes(document.toPath());

        // Создаем объект для подписи данных
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);

        // Получаем цифровую подпись
        byte[] signatureBytes = signature.sign();

        // Создаем файл цифровой подписи с тем же названием, но с расширением ".sig"
        String signatureFileName = document.getName() + ".sig";
        File signatureFile = new File(document.getParentFile(), signatureFileName);

        // Записываем цифровую подпись в файл
        try (FileOutputStream fos = new FileOutputStream(signatureFile)) {
            fos.write(signatureBytes);
        }
    }


    public boolean verifyDocument(File document, File signFile, File publicKeyFile) throws IOException, GeneralSecurityException {
        // Проверяем, что файл документа и файл подписи существуют и являются файлами
        if (!document.exists() || !document.isFile() || !signFile.exists() || !signFile.isFile()) {
            throw new IOException("Invalid input files");
        }

        // Получаем открытый ключ из файла
        PublicKey publicKey = SshKeyUtils.getPublicKey(publicKeyFile).getJCEPublicKey();

        // Получаем данные из документа
        byte[] data = Files.readAllBytes(document.toPath());

        // Получаем подпись из файла
        byte[] signatureBytes = Files.readAllBytes(signFile.toPath());

        // Создаем объект для верификации подписи и инициализируем его открытым ключом
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);

        // Добавляем данные для проверки подписи
        signature.update(data);

        // Проверяем подпись
        return signature.verify(signatureBytes);
    }

}
