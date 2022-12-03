package com.none.java.security;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAUtils {

    public static void generateKeyPair(String savePath) {
        try {
            // Get an instance of the RSA key generator
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);

            // Generate the KeyPair
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Get the public and private key
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Get the RSAPublicKeySpec and RSAPrivateKeySpec
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);

            // Saving the Key to the file
            saveKeyToFile(savePath + "/public.key", publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
            saveKeyToFile(savePath + "/private.key", privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void saveKeyToFile(String fileName, BigInteger modulus, BigInteger exponent) {

        try {
            ObjectOutputStream ObjOutputStream = new ObjectOutputStream(
                    new BufferedOutputStream(new FileOutputStream(fileName)));
            try {
                ObjOutputStream.writeObject(modulus);
                ObjOutputStream.writeObject(exponent);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                ObjOutputStream.close();
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }

    public static Key readPrivateKeyFromFile(InputStream inputStream) {
        try {

            Key key = null;
            ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream));
            try {
                BigInteger modulus = (BigInteger) objectInputStream.readObject();
                BigInteger exponent = (BigInteger) objectInputStream.readObject();
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                key = keyFactory.generatePrivate(new RSAPrivateKeySpec(modulus, exponent));

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                objectInputStream.close();
            }
            return key;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }

    public static Key readPublicKeyFromFile(InputStream inputStream) {
        try {

            Key key = null;
            ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream));
            try {
                BigInteger modulus = (BigInteger) objectInputStream.readObject();
                BigInteger exponent = (BigInteger) objectInputStream.readObject();
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                key = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                objectInputStream.close();
            }
            return key;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static String encryptWithBase64(String plainText, InputStream inputStream) {
        return Base64.getEncoder().encodeToString(encrypt(plainText, inputStream));
    }

    public static byte[] encrypt(String plainText, InputStream inputStream) {
        try {

            Key publicKey = readPublicKeyFromFile(inputStream);

            // Get Cipher Instance
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

            // Initialize Cipher for ENCRYPT_MODE
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Perform Encryption
            byte[] cipherText = cipher.doFinal(plainText.getBytes());

            return cipherText;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String decryptWithBase64(String base64Encrypt, InputStream inputStream) {
        return decrypt(Base64.getDecoder().decode(base64Encrypt), inputStream);
    }

    public static String decrypt(byte[] cipherTextArray, InputStream inputStream) {
        try {

            Key privateKey = readPrivateKeyFromFile(inputStream);

            // Get Cipher Instance
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

            // Initialize Cipher for DECRYPT_MODE
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Perform Decryption
            byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

            return new String(decryptedTextArray);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * @param keyFilePath 密钥路径
     */
    public static String decryptWithBase64(String base64, String keyFilePath) {
        try {

            Key privateKey = null;
            InputStream inputStream = new FileInputStream(keyFilePath);
            ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream));
            try {
                BigInteger modulus = (BigInteger) objectInputStream.readObject();
                BigInteger exponent = (BigInteger) objectInputStream.readObject();
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                privateKey = keyFactory.generatePrivate(new RSAPrivateKeySpec(modulus, exponent));

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                objectInputStream.close();
            }

            // Get Cipher Instance
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

            // Initialize Cipher for DECRYPT_MODE
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Perform Decryption
            byte[] decryptedTextArray = cipher.doFinal(Base64.getDecoder().decode(base64));

            return new String(decryptedTextArray);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}

