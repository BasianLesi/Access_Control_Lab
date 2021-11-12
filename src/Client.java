
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.rmi.NotBoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class Client {

    public static void main(String[] args) throws IOException, NotBoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, SignatureException {

        Client client = new Client();
        client.Start();
    }

    public void Start() throws IOException, NotBoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, SignatureException {

        RMIClient client = new RMIClient();
        client.startClient();
        int i = 0;

        Scanner in = new Scanner(System.in);

        System.out.println("Enter Username: ");
        String user = in.nextLine();

        System.out.println("Enter Password: ");
        String pass = in.nextLine();

        boolean b = client.authenticateUser(user, pass);

        if(b) PrinterMenu();

        while(b) {
            String result = null;
            int c = in.nextInt();
            switch (c) {
                case 1 -> result = client.print("filename", "printer1", i);
                case 2 -> result = client.queue("printer2", i);
                case 3 -> result = client.topQueue("printer3", 3, i);
                case 4 -> result = client.start(i);
                case 5 -> result = client.stop(i);
                case 6 -> result = client.restart(i);
                case 7 -> result = client.status("printer7",i);
                case 8 -> result = client.readConfig("readConfig_Parameter",i);
                case 9 -> result = client.setConfig("printer9", "Value = 10",i);
                default -> {
                    System.out.println("Session Terminated, exiting");
                    in.close();
                    b = false;
                }
            }
            if(!b) break;
            if (result.equals("You don't have permission to user this function")) i--;
            i++;
            try {
                System.out.println("Result > " + result);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }


    public void PrinterMenu() {
        System.out.println("Enter a number to choose a Printer function");
        System.out.println( "1 -> Print\n" +
                "2 -> Queue\n"  +
                "3 -> topQueue\n" +
                "4 -> Start\n" +
                "5 -> Stop\n" +
                "6 -> Restart\n" +
                "7 -> Status\n" +
                "8 -> ReadConfig\n" +
                "9 -> SetConfig\n" +
                "else -> Terminate");
    }
}


