import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.sql.Timestamp;

public class TSAConnection extends Thread {

    private Socket server;
    private static byte[] firma;

    public TSAConnection(Socket server){
        this.server = server;
    }

    public void run(){

        try {

            System.out.println("***************************** Connection established ********************************\n");
            ObjectOutputStream sendObject = new ObjectOutputStream(server.getOutputStream());
            ObjectInputStream receivedObject = new ObjectInputStream(server.getInputStream());
            PeticionTimestamp peticion = (PeticionTimestamp) receivedObject.readObject();
            String selloTemporalTSA = new Timestamp(System.currentTimeMillis()).toString();
            System.out.println("Sello ---> "+ selloTemporalTSA);
            /**********Firma TSA***********/
            ByteArrayOutputStream escribirfirma = new ByteArrayOutputStream();
            DataOutputStream write = new DataOutputStream(escribirfirma);
            write.write(peticion.getHashDoc());
            write.writeUTF(selloTemporalTSA);
            byte[] firma = escribirfirma.toByteArray();
            escribirfirma.close();
            byte[] firmaTSA = firmarSelloTemporal(firma);
            RespuestaTimestamp respuesta = new RespuestaTimestamp(selloTemporalTSA, firmaTSA);
            sendObject.writeObject(respuesta);
            System.out.println("Respuesta enviada al servidor...");
        } catch (IOException e) {
            System.out.println("\n************************** El servidor se ha desconectado ****************************\nError: " + e.getMessage());
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public byte[] firmarSelloTemporal(byte[] firmaTSA){

        try {
            String algoritmo = "SHA1withDSA";
            int longbloque;
            byte bloque[] = new byte[1024];

            PrivateKey privateKey = ClavePrivada();
            ByteArrayInputStream mensaje = new ByteArrayInputStream(firmaTSA);

            Signature signer = Signature.getInstance(algoritmo);
            signer.initSign(privateKey);
            while ((longbloque = mensaje.read(bloque)) > 0) {
                signer.update(bloque, 0, longbloque);
            }
            firma = signer.sign();
            System.out.println("Documento firmado. Firma: ");
            for (int i = 0; i < firma.length; i++) {
                System.out.print(firma[i] + " ");
            }
            System.out.println("\n---- Fin de la firma ----\n");
            mensaje.close();


        } catch (InvalidKeyException | SignatureException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return firma;
    }

    private PrivateKey ClavePrivada() {
        KeyStore keyStore;
        char[] passwordKeystore = "tsatsa".toCharArray();
        char[] passwordPrivateKey = "tsatsa".toCharArray();
        String pathkeystore = "keystores/tsakeystore.jce";
        String SKServidor = "tsa_dsa";
        PrivateKey privateKey = null;

        try {
            keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream(pathkeystore), passwordKeystore);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
                    keyStore.getEntry(SKServidor, new KeyStore.PasswordProtection(passwordPrivateKey));
            privateKey = privateKeyEntry.getPrivateKey();
        } catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
        return privateKey;
    }
}
