
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.jetbrains.annotations.Nullable;


import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;


public class ServerImpl implements Printer {

    private Cipher keyDecipher;
    private Cipher c1;
    SecretKey DESkey;
    int i = 0;
    String logUser;
    String logRole;
    String roleAccess;
    String files_path = "../server_files";
    String noPermissionMessage;
    String authFailed = "Client message security authentication \u001B[31m FAILED \u001B[0m";
    boolean acl = false;

    enum Function
    {
        print, queue, topQueue, start, stop, restart, status, readConfig, setConfig
    }

    public ServerImpl() throws IOException {
        getAccessMethod();
        UnicastRemoteObject.exportObject(this, 0);
    }



    @Override
    public boolean keyExchange(byte[] encryptedDESkey, int client_i) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {

        SecretKey key = null;
        PrivateKey privateKey = null;
        keyDecipher = null;
        i = client_i;

        if(signatureVerify(encryptedDESkey)) {
            try{
                privateKey = loadPrivateKeyFromFile(Paths.get(files_path+"/Server_private.key"));
                keyDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                keyDecipher.init(Cipher.DECRYPT_MODE, privateKey);
                key = new SecretKeySpec(keyDecipher.doFinal(encryptedDESkey), "DES");
                DESkey = key;
                //System.out.println(DESkey.hashCode());
                return true;
            }catch (Exception e){
                System.err.println("Exception decrypting des key: " + e.getMessage());
            }
        }
        return false;
    }

    @Override
    public boolean authenticateUser(String user, String password) throws IOException, NoSuchAlgorithmException {
        if(passwordCheck(user, password)){
            logUser = user;
            noPermissionMessage = "User: \u001B[32m" + logUser + "\u001B[0m has \u001B[31m no permission \u001B[0m to execute function";
            if(acl) {
                roleAccess = getUserAccess(logUser);
            }
            else {
                logRole = getUserRole(logUser);
                roleAccess = getRoleAccess(logRole);
            }
            return true;
        }
        return false;
    }

    @Override
    public String print(String filename, String printer, byte[] token) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        char c = roleAccess.charAt(Function.print.ordinal());
        int a = Character.getNumericValue(c);
        if(a==1){
            if(checkToken(token, "print", i)){
                i++;
                return "print() function executed";
            }
            System.err.println(authFailed);
            return "Message security authentication FAILED";
        }
        System.out.println(noPermissionMessage);
        return "You don't have permission to user this function";


    }

    @Override
    public String queue(String printer, byte[] token) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        char c = roleAccess.charAt(Function.queue.ordinal());
        int a = Character.getNumericValue(c);
        if(a==1){
            if(checkToken(token, "queue", i)){
                i++;
                return "queue() function executed";
            }
            System.err.println(authFailed);
            return "Message security authentication FAILED";
        }
        System.out.println(noPermissionMessage);
        return "You don't have permission to user this function";
    }

    @Override
    public int topQueue(String printer, int job, byte[] token) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        char c = roleAccess.charAt(Function.topQueue.ordinal());
        int a = Character.getNumericValue(c);
        if(a==1){
            if(checkToken(token, "topQueue", i)){
                i++;
                return 1;
            }
            System.err.println(authFailed);
            return 0;
        }
        System.out.println(noPermissionMessage);
        return 2;
    }

    @Override
    public String start(byte[] token) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        char c = roleAccess.charAt(Function.start.ordinal());
        int a = Character.getNumericValue(c);
        if(a==1){
            if(checkToken(token, "start", i)){
                i++;
                return "start() function executed";
            }
            System.err.println(authFailed);
            return "Message security authentication FAILED";
        }
        System.out.println(noPermissionMessage);
        return "You don't have permission to user this function";

    }

    @Override
    public String stop(byte[] token) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        char c = roleAccess.charAt(Function.stop.ordinal());
        int a = Character.getNumericValue(c);
        if(a==1){
            if(checkToken(token, "stop", i)){
                i++;
                return "stop() function executed";
            }
            System.err.println(authFailed);
            return "Message security authentication FAILED";
        }
        System.out.println(noPermissionMessage);
        return "You don't have permission to user this function";

    }

    @Override
    public String restart(byte[] token) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        char c = roleAccess.charAt(Function.restart.ordinal());
        int a = Character.getNumericValue(c);
        if(a==1){
            if(checkToken(token, "restart", i)){
                i++;
                return "restart() function executed";
            }
            System.err.println(authFailed);
            return "Message security authentication FAILED";
        }
        System.out.println(noPermissionMessage);
        return "You don't have permission to user this function";
    }

    @Override
    public String status(String printer, byte[] token) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        char c = roleAccess.charAt(Function.status.ordinal());
        int a = Character.getNumericValue(c);
        if(a==1){
            if(checkToken(token, "status", i)){
                i++;
                return "status() function executed";
            }
            System.err.println(authFailed);
            return "Message security authentication FAILED";
        }
        System.err.println(noPermissionMessage);
        return "You don't have permission to user this function";

    }

    @Override
    public String readConfig(String parameter, byte[] token) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        char c = roleAccess.charAt(Function.readConfig.ordinal());
        int a = Character.getNumericValue(c);
        if(a==1){
            if(checkToken(token, "readConfig", i)){
                i++;
                return "readConfig function executed";
            }
            System.err.println(authFailed);
            return "Message security authentication FAILED";
        }
        System.err.println(noPermissionMessage);
        return "You don't have permission to user this function";

    }

    @Override
    public String setConfig (String parameter, String value, byte[] token) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        char c = roleAccess.charAt(Function.setConfig.ordinal());
        int a = Character.getNumericValue(c);
        if(a==1){
            if(checkToken(token, "setConfig", i)){
                i++;
                return "setConfig function executed";
            }
            System.err.println(authFailed);
            return "Message security authentication FAILED";
        }
        System.err.println(noPermissionMessage);
        return "You don't have permission to user this function";
    }

    private String getUserPassword(String user) throws IOException {
        Reader in  = new FileReader(files_path + "/Passwords.csv");
        Iterable<CSVRecord> records = CSVFormat.DEFAULT
                .withHeader("username", "password").parse(in);
        for (CSVRecord record : records) {
            String username = record.get("username");
            String password = record.get("password");
//            System.out.println("author = " + username + "\ntitle = " + password);
            if (username.equals(user))
            {
//                System.out.println("author = " + username + "\ntitle = " + password);
                return password;
            }
        }
        System.out.println("User: <<" + user + ">> Was not found");
        return "UserNotFound";
    }

    private @Nullable String getUserRole(String user) throws IOException {
        Reader in  = new FileReader(files_path + "/User_Roles.csv");
        Iterable<CSVRecord> records = CSVFormat.DEFAULT
                .withHeader("username", "role").parse(in);
        for (CSVRecord record : records) {
            String username = record.get("username");
            String role = record.get("role");
//            System.out.println("author = " + username + "\ntitle = " + password);
            if (username.equals(user))
            {
                return role;
            }
        }
        System.out.println("User role Was not found");
        return null;
    }

    private @Nullable String getRoleAccess(String role) throws IOException {
        Reader in  = new FileReader(files_path + "/RBAC.csv");
        Iterable<CSVRecord> records = CSVFormat.DEFAULT
                .withHeader("role", "accessString").parse(in);
        for (CSVRecord record : records) {
            String roles = record.get("role");
            String accessString = record.get("accessString");
//            System.out.println("author = " + username + "\ntitle = " + password);
            if (role.equals(roles))
            {
                return accessString;
            }
        }
        System.out.println("Role accessString was not found");
        return null;
    }

    private @Nullable String getUserAccess(String user) throws IOException {
        Reader in  = new FileReader(files_path + "/ACL.csv");
        Iterable<CSVRecord> records = CSVFormat.DEFAULT
                .withHeader("name", "accessString").parse(in);
        for (CSVRecord record : records) {
            String username = record.get("name");
            String accessString = record.get("accessString");
            if (username.equals(user))
            {
                return accessString;
            }
        }
        System.out.println("User name Was not found");
        return null;
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

    private boolean signatureVerify(byte[] key) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        PublicKey client_pub = loadPublicKeyFromFile(Paths.get(files_path + "/Client_public.key"));
        sign.initVerify(client_pub);
        sign.update(key);
        byte[] bytes = Files.readAllBytes(Paths.get(files_path + "/signedKey"));
        if (sign.verify(bytes)) {
            System.out.println("Key verified");
            return true;
        }
        return false;
    }


    private boolean checkToken(byte [] token, String string, int i) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        c1 = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c1.init(Cipher.DECRYPT_MODE, DESkey);
        byte[] bytesDecrypted = c1.doFinal(token);
        String s = new String(bytesDecrypted, StandardCharsets.UTF_8);
        String compare = string + i;

        if (s.equals(compare)){
            System.out.println("\u001B[32m" + string+"() \u001B[0m function was executed by " + "\u001B[32m" +logUser+ "\u001B[0m");
            return true;
        }
        return false;
    }

    private void getAccessMethod(){
        Scanner in = new Scanner(System.in);
        System.out.println("Choose access control method: \n Press 1: Access Control List \n Default: Role Based Access Control");
        int choice = in.nextInt();
        if (choice == 2) acl = false;
        in.close();
    }

    private String hash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[]hashInBytes = md.digest(password.getBytes(StandardCharsets.US_ASCII));
        return new String(hashInBytes);
    }

    private boolean passwordCheck(String user, String pass) throws IOException, NoSuchAlgorithmException {

        while (true) {
            if (getUserPassword(user).equals(hash(pass))) {
                System.out.println("Welcome " + "\u001B[32m" +user+ "\u001B[0m" + " you are Authenticated!");
//                System.out.println("\nUser Password hashed = " + hash(pass) +"\n userPasswordFromfile = " + getUserPassword(user) );
                return true;
            } else {
//                System.out.println("Access Denied: \nUser Password hashed = " + hash(pass) +"\n userPasswordFromfile = " + getUserPassword(user) );
                return false;
            }
        }
    }
}

