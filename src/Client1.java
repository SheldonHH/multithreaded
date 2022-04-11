import java.io.DataOutputStream;
import java.io.ObjectInputStream;
import java.net.Socket;


public class Client1 {
    public static void main(String[] arg) {
        try {

            Socket socketConnection = new Socket("127.0.0.1", 11111);


            //QUERY PASSING
            DataOutputStream outToServer = new DataOutputStream(socketConnection.getOutputStream());

            String SQL="I  am  client 1";
            outToServer.writeUTF(SQL);


        } catch (Exception e) {System.out.println(e); }
    }
}