import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class FirmaClienteVerificarServidor {

   /* private static int longbloque;
    private static byte bloque[] = new byte[1024];
   */ private static byte[] firmacliente;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    public FirmaClienteVerificarServidor() {
    }

    public void FirmarDocumento(byte[] documento) {
        try {
            String algoritmo;
            int longbloque;
            byte bloque[] = new byte[1024];

            ClavePrivada();
            ByteArrayInputStream mensaje = new ByteArrayInputStream(documento);

            if (privateKey.getAlgorithm().equalsIgnoreCase("RSA")) {
                algoritmo = "MD5withRSA";
            } else {
                algoritmo = "SHA1withDSA";
            }
            //Creacion del objeto para firmar y inicializacion del objeto
            Signature object = Signature.getInstance(algoritmo);
            object.initSign(privateKey);
            while ((longbloque = mensaje.read(bloque)) > 0) {
                object.update(bloque, 0, longbloque);
            }
            firmacliente = object.sign();
            System.out.println("Documento firmado. Firma: ");
            for (int i = 0; i < firmacliente.length; i++)
                System.out.print(firmacliente[i] + " ");
            System.out.println("\n---- Fin de la firma ----\n");
            mensaje.close();


        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: algoritmo de encriptacion no válido" + e.getMessage());
            //   e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Error: clave inválida" + e.getMessage());
            //  e.printStackTrace();
        } catch (SignatureException e) {
            System.out.println("Error: firma del cliente no válida" + e.getMessage());
            //   e.printStackTrace();
        } catch (IOException e) {
            System.out.println("ERROR: " + e.getMessage());
            //  e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

    }

   public byte[] getFirma() {
        return firmacliente;
    }

    public boolean verificarServidor(byte[] sigServC, byte[] firmaServ) throws Exception {

        String algoritmo;
        int longbloque;
        byte bloque[] = new byte[1024];

        System.out.println("Inicio de la verificación del servidor...");
        ByteArrayInputStream validar = new ByteArrayInputStream(sigServC);
        ClavePublica();
        if (publicKey.getAlgorithm().equalsIgnoreCase("RSA")) {
            algoritmo = "MD5withRSA";
        } else {
            algoritmo = "SHA1withDSA";
        }
        // Creamos un objeto para verificar
        Signature object = Signature.getInstance(algoritmo);

        // Inicializamos el objeto para verificar
        object.initVerify(publicKey);
        while ((longbloque = validar.read(bloque)) > 0) {
            object.update(bloque, 0, longbloque);
        }
        validar.close();
        if (object.verify(firmaServ)) {
            System.out.println("Firma del servidor correcta");
            return true;
        } else {
            System.out.println("Fallo de firma registrador");
            return false;
        }
    }

    private static PrivateKey ClavePrivada() throws KeyStoreException, IOException, UnrecoverableEntryException, NoSuchAlgorithmException, CertificateException {

        KeyStore keyStore;
       /* char[] passwordKeystore = "cliente".toCharArray();
        char[] passwordPrivateKey = "cliente".toCharArray();
        String pathkeystore = "keystores/clientekeystore.jce";
        String SKCliente = "cliente";*/
        char[] passwordKeystore = "cambiala".toCharArray();
        char[] passwordPrivateKey = "cambiala".toCharArray();
        String pathkeystore = "JCKES/keystore_cliente2014.jce";
        String SKCliente = "cliente_dsa";
       // String SKCliente = "firmadoc";

        keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(new FileInputStream(pathkeystore), passwordKeystore);
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(SKCliente, new KeyStore.PasswordProtection(passwordPrivateKey));
        privateKey = privateKeyEntry.getPrivateKey();
        return privateKey;
    }

    private static void ClavePublica() throws Exception {
        KeyStore keyStore;
        /*char[] passwordKeystore = "servidor".toCharArray();
        String pathkeystore = "keystores/servidorkeystore.jce";
        String SKServidor = "servidorrsa";*/
        char[] passwordKeystore = "cambiala".toCharArray();
        String pathkeystore = "JCKES/keystore_servidor2014.jce";
        String SKServidor = "servidor_dsa";
      /*  char[] passwordKeystore = "cliente".toCharArray();
        String pathkeystore = "cliente_cacerts.jce";
        String SKServidor = "servidor";*/

        keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(new FileInputStream(pathkeystore), passwordKeystore);

        publicKey = keyStore.getCertificate(SKServidor).getPublicKey();
    }
}
