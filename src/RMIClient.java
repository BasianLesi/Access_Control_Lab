import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import static java.lang.System.in;
import static java.lang.System.out;

public class RMIClient {

    static SecretKey DESkey;
    private Printer server;
    private Cipher c1;
    private Cipher c2;
    private byte[] encryptedDESkey;
    private byte[] signedKey;

    public RMIClient() throws RemoteException {

    }

    public void startClient() throws IOException, NotBoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        keyPairGenerator();
        generateDESkey();
        encryptedDESkey = encryptDESkey();
        signKey(encryptedDESkey);

        Registry registry = LocateRegistry.getRegistry("localhost", 1099);
        server = (Printer) registry.lookup("Server");
        if(server.keyExchange(encryptedDESkey, 0)) {
            System.out.println("DESkey exchange successfully");
//         System.out.println(DESkey.hashCode());
        }
    }

    public boolean authenticateUser(String user, String password) throws IOException, NoSuchAlgorithmException {
        if(server.authenticateUser(user, password))
        {
            System.out.println("Welcome " + "\u001B[32m" +user+ "\u001B[0m" + " you are Authenticated!");
            return true;
        }
        System.out.println("Access Denied, Connection terminated");
        return false;
    }

    public String print(String filename, String printer, int i) {
        String result;
        try {
            result = server.print(filename, printer, encrypt("print" + i));
        } catch (RemoteException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Could not contact server");
        }
        return result;
    }

    public String queue(String printer, int i) {
        String result;
        try {
            result = server.queue(printer, encrypt("queue" + i));
        } catch (RemoteException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Could not contact server");
        }
        return result;
    }

    public String topQueue(String printer, int job, int i) {
        String result;
        try {
            int a = server.topQueue(printer, job, encrypt("topQueue" + i));
            if(a==1) result = "TopQueue() function executed";
            else if (a==0) result = "Message security authentication FAILED";
            else result = "You don't have permission to user this function";
        } catch (RemoteException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Could not contact server");
        }
        return result;
    }

    public String start(int i) {
        String result;
        try {
            result = server.start(encrypt("start" + i));
        } catch (RemoteException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Could not contact server");
        }
        return result;
    }

    public String stop(int i) {
        String result;
        try {
            result = server.stop(encrypt("stop" + i));
        } catch (RemoteException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Could not contact server");
        }
        return result;
    }

    public String restart(int i) {
        String result;
        try {
            result = server.restart(encrypt("restart" + i));
        } catch (RemoteException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Could not contact server");
        }
        return result;
    }

    public String status(String printer, int i) {
        String result;
        try {
            result = server.status(printer, encrypt("status" + i));
        } catch (RemoteException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Could not contact server");
        }
        return result;
    }

    public String readConfig(String parameter, int i) {
        String result;
        try {
            result = server.readConfig(parameter, encrypt("readConfig" + i));
        } catch (RemoteException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Could not contact server");
        }
        return result;
    }

    public String setConfig(String parameter, String value, int i) {
        String result;
        try {
            result = server.setConfig(parameter, value, encrypt("setConfig" + i));
        } catch (RemoteException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Could not contact server");
        }
        return result;
    }

    private static void keyPairGenerator() throws NoSuchAlgorithmException, IOException {
        //Generates Private and Public key URL: https://www.novixys.com/blog/how-to-generate-rsa-keys-java/
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        //Get public and private keys
        Key publicKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();

        String outFile = "../server_files/Client_public";
        PrintStream out = null;
        out = new PrintStream(new FileOutputStream(outFile + ".key"));
        out.write(publicKey.getEncoded());
        out.close();

        outFile = "../server_files/Client_private";
        out = new PrintStream(new FileOutputStream(outFile + ".key"));
        out.write(privateKey.getEncoded());
        out.close();

        System.err.println("Private key format: " + privateKey.getFormat());
        // prints "Private key format: PKCS#8" on my machine

        System.err.println("Public key format: " + publicKey.getFormat());
        // prints "Public key format: X.509" on my machine

    }

    private static void generateDESkey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        KeyGenerator generator = KeyGenerator.getInstance("DES");
        generator.init(new SecureRandom());
        DESkey = generator.generateKey();
        //Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    private PrivateKey loadPrivateKeyFromFile(Path path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = Files.readAllBytes(path);

        //generate private key
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvt = kf.generatePrivate(ks);
        return pvt;
    }

    private PublicKey loadPublicKeyFromFile(Path path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = Files.readAllBytes(path);

        /* Generate public key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(ks);
        return pub;
    }

    private byte[] encryptDESkey(){
        c1 = null;
        byte[] key = null;
        try{
            PublicKey server_pub = loadPublicKeyFromFile(Paths.get("../server_files/Server_public.key"));
            c1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c1.init(Cipher.ENCRYPT_MODE, server_pub);
            key = c1.doFinal(DESkey.getEncoded());

        }catch (Exception e){
            System.out.println(e.getMessage());
        }
        return key;
    }

    private void signKey(byte[] encryptedDESkey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        PrivateKey client_pvt = loadPrivateKeyFromFile(Paths.get("../server_files/Client_private.key"));
        sign.initSign(client_pvt);
        sign.update(encryptedDESkey);
        OutputStream out = null;
        try {
            String outFile = "../server_files/signedKey";
            out = new PrintStream(new FileOutputStream(outFile));
            byte[] signature = sign.sign();
            out.write(signature);
        }finally{
            if ( out != null ) out.close();
        }

    }

    private byte[] encrypt(String string) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] text = string.getBytes();
        c2 = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c2.init(Cipher.ENCRYPT_MODE, DESkey);
        byte [] token = c2.doFinal(text);
        return token;
    }

}