
import java.io.*;
import java.nio.file.Paths;
import java.rmi.AlreadyBoundException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;


public class Server {

    private static final int PORT = 1099;

    public static void main(String[] args) throws AlreadyBoundException, IOException, NoSuchAlgorithmException {


        Printer server = new ServerImpl();
        Registry registry = LocateRegistry.createRegistry(PORT);
        registry.bind("Server", server);
        System.out.println("Server started");

    }
}