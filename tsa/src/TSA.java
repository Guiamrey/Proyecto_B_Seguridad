import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class TSA {

    public static void main(String[] args){

        int puerto = 9060;
        definirKeystore();
        try {

            SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            ServerSocket serverSocket = serverSocketFactory.createServerSocket(puerto);
            System.out.println("\n**** TSA en funcionamiento ****\n");

            try {
                while (true) {
                    Socket server = serverSocket.accept();
                    TSAConnection tsaConnection = new TSAConnection(server);
                    tsaConnection.start();
                }
            } catch (IOException e) {
                System.out.println("*** ERROR ***  El TSA ha caído --> " + e.getMessage());
            }

        } catch (IOException e) {
            System.out.println("\n ********* Error al introducir las contraseñas o error en el Handshake");
        }
    }

    private static void definirKeystore() {

        String passwKS = "tsatsa";
        String passwTS = "tsatsa";
        String pathkeystore = "keystores/tsakeystore.jce";
        String pathtruststore = "keystores/tsatruststore.jce";

        // Contraseña del keystore del cliente
        System.setProperty("javax.net.ssl.keyStorePassword", passwKS);
        // Tipo de KeyStore usados
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        // Path al keystore del cliente
        System.setProperty("javax.net.ssl.keyStore", pathkeystore);

        // Contraseña del trustore del cliente
        System.setProperty("javax.net.ssl.trustStorePassword", passwTS);
        // Tipo de TrustStore usado
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        // Path al Trustore del cliente
        System.setProperty("javax.net.ssl.trustStore", pathtruststore);


    }
}
