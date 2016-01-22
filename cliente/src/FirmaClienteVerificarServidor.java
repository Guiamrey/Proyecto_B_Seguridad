import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class FirmaClienteVerificarServidor {

    private static byte[] firmacliente;
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
            Signature signer = Signature.getInstance(algoritmo);
            signer.initSign(privateKey);
            while ((longbloque = mensaje.read(bloque)) > 0) {
                signer.update(bloque, 0, longbloque);
            }
            firmacliente = signer.sign();
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
        } catch (CertificateException | KeyStoreException | UnrecoverableEntryException e) {
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
        Signature verifier = Signature.getInstance(algoritmo);

        // Inicializamos el objeto para verificar
        verifier.initVerify(publicKey);
        while ((longbloque = validar.read(bloque)) > 0) {
            verifier.update(bloque, 0, longbloque);
        }
        validar.close();
        if (verifier.verify(firmaServ)) {
            System.out.println("Firma del servidor correcta");
            return true;
        } else {
            System.out.println("Fallo de firma registrador");
            return false;
        }
    }

    private static PrivateKey ClavePrivada() throws KeyStoreException, IOException, UnrecoverableEntryException, NoSuchAlgorithmException, CertificateException {

        KeyStore keyStore;
        char[] passwordKeystore = "cliente".toCharArray();
        char[] passwordPrivateKey = "cliente".toCharArray();
        String pathkeystore = "keystores/clientekeystore.jce";
        // String SKCliente = "client_rsa";
        String SKCliente = "client_dsa";

        keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(new FileInputStream(pathkeystore), passwordKeystore);
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(SKCliente, new KeyStore.PasswordProtection(passwordPrivateKey));
        privateKey = privateKeyEntry.getPrivateKey();
        return privateKey;
    }

    private static void ClavePublica() throws Exception {
        KeyStore keyStore;
        char[] passwordKeystore = "cliente".toCharArray();
        String pathkeystore = "keystores/clientetruststore.jce";
        //String SKServidor = "autenserv_rsa";
        String SKServidor = "autenserv_dsa";

        keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(new FileInputStream(pathkeystore), passwordKeystore);

        publicKey = keyStore.getCertificate(SKServidor).getPublicKey();
    }
}
