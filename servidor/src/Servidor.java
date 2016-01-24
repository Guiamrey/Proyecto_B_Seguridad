import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Scanner;

public class Servidor {
    static String algCifrado;

    public static void main(String[] args) {

        int puerto = 9050;
        definirKeystore();
        SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        try {

            //TLS
            /***********************/
            ServerSocket serverSocket = serverSocketFactory.createServerSocket(puerto);
            System.out.println("\n**** Servidor en funcionamiento ****\n");
            ((SSLServerSocket) serverSocket).setNeedClientAuth(true);

            try {
                while (true) {
                    Socket cliente = serverSocket.accept();
                    ServerConnection serverConnection = new ServerConnection(cliente, algCifrado);
                    serverConnection.start();
                }
            } catch (IOException e) {
                System.out.println("*** ERROR ***  El servidor ha caído --> " + e.getMessage());
                return;
            }

        } catch (IOException e) {
            System.out.println("\n ********* Error al introducir las contraseñas");
        }
    }

    private static void definirKeystore() {
        System.out.println("Valores de las contraseñas de los stores (Servidor): \n(keyStoreFile) contraseñaKeystore (trustStoreFile) contraseñaTruststore) algoritmoCifrado (AES-128/ARCFOUR)\n");
        Scanner consola = new Scanner(System.in);
        String cadena = consola.nextLine();
        String[] aux = cadena.split(" ");
        //String keystrore = "keystores/" + aux[0];
        //String truststore = "keystores/" + aux[2];
        String passwKS = aux[0];
        String passwTS = aux[1];
        String pathkeystore = "keystores/servidorkeystore.jce";
        String pathtruststore = "keystores/servidortruststore.jce";
        algCifrado = aux[2];

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
