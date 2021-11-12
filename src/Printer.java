
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public interface Printer extends Remote {
    boolean keyExchange(byte[] encryptedDESkey, int i) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException;
    boolean authenticateUser(String user, String password) throws IOException, NoSuchAlgorithmException;
    String print(String fileName, String printer, byte[] token) throws RemoteException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException;
    String queue(String printer, byte[] token) throws RemoteException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException;
    int topQueue(String printer, int job, byte[] token) throws RemoteException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException;
    String start(byte[] token) throws RemoteException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException;
    String stop(byte[] token) throws RemoteException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException;
    String restart(byte[] token) throws RemoteException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException;
    String status(String printer, byte[] token) throws RemoteException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException;
    String readConfig (String parameter, byte[] token) throws RemoteException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException;
    String setConfig (String parameter, String value, byte[] token) throws RemoteException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException;
}