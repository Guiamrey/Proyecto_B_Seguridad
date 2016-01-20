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

   /* static String pathkeystore = "keystores/servidorkeystore.jce";
    static String pathtruststore = "keystores/servidortruststore.jce";*/
   static String pathkeystore = "KEYS/SERVIDOR/ksServidor.jce";
    static String pathtruststore = "KEYS/SERVIDOR/tsServidor.jce";
/*    static String pathkeystore = "servidor.jce";
    static String pathtruststore = "servidor_cacerts.jce";*/

    public static void main(String[] args){

        int puerto = 9050;
        definirKeystore();
        //ServerSocket serverSocket = null;
        SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
       try {


            //TLS
            /***********************/
            ServerSocket serverSocket = serverSocketFactory.createServerSocket(puerto);
            System.out.println("\n**** Servidor en funcionamiento ****\n");
           ((SSLServerSocket) serverSocket).setNeedClientAuth(true);

            try {
                while(true){
                    Socket cliente = serverSocket.accept();
                    ServerConnection serverConnection = new ServerConnection(cliente);
                    serverConnection.run();
                }
            } catch (IOException e) {
                System.out.println("*** ERROR ***  El servidor ha caído --> " + e.getMessage());
               // e.printStackTrace();
                return;
            }

        } catch (IOException e) {
            System.out.println("\n ********* Error al introducir las contraseñas");
            //e.printStackTrace();
        }


    }

    private static void definirKeystore() {
        System.out.println("Valores de las contraseñas de los stores: \n(keyStoreFile) contraseñaKeystore (trustStoreFile) contraseñaTruststore)\n");
        Scanner consola = new Scanner(System.in);
        String cadena = consola.nextLine();
        String[] aux = cadena.split(" ");
        String passwKS = aux[0];
        String passwTS = aux[1];

        // Contraseña del keystore del cliente
        System.setProperty("javax.net.ssl.keyStorePassword", passwKS);
        // Tipo de KeyStore usados
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        // Path al keystore del cliente
        System.setProperty("javax.net.ssl.keyStore",pathkeystore);

        // Contraseña del trustore del cliente
        System.setProperty("javax.net.ssl.trustStorePassword", passwTS);
        // Tipo de TrustStore usado
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        // Path al Trustore del cliente
        System.setProperty("javax.net.ssl.trustStore", pathtruststore);


    }
}
