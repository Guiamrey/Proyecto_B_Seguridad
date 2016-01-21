import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

public class FirmarServidorValidarCliente {


    private static PrivateKey privateKeyServ;
    private static PublicKey publicKey;
    private static byte[] firma;
    byte [] encoding;

    public FirmarServidorValidarCliente() {
    }

    public void firmarServidor(byte[] doc) {
        try {
            String algoritmo;
            int longbloque;
            byte bloque[] = new byte[1024];

            ClavePrivada();
            ByteArrayInputStream mensaje = new ByteArrayInputStream(doc);
            if (privateKeyServ.getAlgorithm().equalsIgnoreCase("RSA")) {
                algoritmo = "MD5withRSA";
            } else {
                algoritmo = "SHA1withDSA";
            }
            Signature object = null;
            object = Signature.getInstance(algoritmo);
            object.initSign(privateKeyServ);
            while ((longbloque = mensaje.read(bloque)) > 0) {
                object.update(bloque, 0, longbloque);
            }
            firma = object.sign();
            System.out.println("Documento firmado. Firma: ");
            for (int i = 0; i < firma.length; i++) {
                System.out.print(firma[i] + " ");
            }
            System.out.println("\n---- Fin de la firma ----\n");
            mensaje.close();


        } catch (InvalidKeyException | SignatureException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    public byte[] getFirmaServidor() {
        return firma;
    }

    public byte[] cifrarDoc(byte[] doc) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        KeyStore keyStores;
        char[] contraseña = "cliente".toCharArray();
        char[] contraseñaKey = "cliente".toCharArray();

        keyStores = KeyStore.getInstance("JCEKS");
        keyStores.load(new FileInputStream("servidor.jce"), contraseñaKey);
        KeyStore.SecretKeyEntry ksEntry = (KeyStore.SecretKeyEntry) keyStores.getEntry("ksservidor", new KeyStore.PasswordProtection(contraseña));
        SecretKey secretKey = ksEntry.getSecretKey();

        String provider = "SunJCE";
        byte enClaro[] = new byte[2024];
        byte cifrado[];
        String algoritmo = "AES";
        String transformacion = "/CBC/PKCS5Padding";
        int tamañoClave = 128;
        int longbloque;

            System.out.println("Cifrando documento...");
            Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);
            cifrador.init(Cipher.ENCRYPT_MODE, secretKey);
            ByteArrayInputStream docSinCifrar = new ByteArrayInputStream(doc);
            ByteArrayOutputStream yaCifrado = new ByteArrayOutputStream();

            while ((longbloque = docSinCifrar.read(enClaro)) > 0) {
                cifrado = cifrador.update(enClaro, 0, longbloque);
                yaCifrado.write(cifrado);
            }
            cifrado = cifrador.doFinal();
            yaCifrado.write(cifrado);
            System.out.println("Documento cifrado> " + algoritmo + "-" + tamañoClave + " Proveedor: " + provider);
            yaCifrado.close();
            docSinCifrar.close();

        byte[] docCifrado = yaCifrado.toByteArray();
        encoding = cifrador.getParameters().getEncoded();
        return docCifrado;
    }

    public byte[] getEncoding() {
        return encoding;
    }

    public byte[] descifrarDoc(byte[] docCifrado, byte[] encoding) throws Exception {

        System.out.println("Descifrando documento...");

        KeyStore keyStore;
        char[] contraseña = "cliente".toCharArray();
        char[] contraseñaKey = "cliente".toCharArray();

        keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(new FileInputStream("servidor.jce"), contraseñaKey);
        KeyStore.SecretKeyEntry ksEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("ksservidor", new KeyStore.PasswordProtection(contraseña));
        SecretKey key = ksEntry.getSecretKey();

        String provider = "SunJCE";
        byte enClaro[];
        byte cifrado[] = new byte[1024];
        String algoritmo = "AES";
        String transformacion = "/CBC/PKCS5Padding";
        int longbloque;
        AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo, provider);
        params.init(encoding);

        Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);
        descifrador.init(Cipher.DECRYPT_MODE, key, params);

        ByteArrayInputStream textocifrado = new ByteArrayInputStream(docCifrado);
        ByteArrayOutputStream textoclaro = new ByteArrayOutputStream();

        while ((longbloque = textocifrado.read(cifrado)) > 0) {
            enClaro = descifrador.update(cifrado, 0, longbloque);
            textoclaro.write(enClaro);
        }

        enClaro = descifrador.doFinal();

        System.out.println("Documento descifrado.");
        textoclaro.write(enClaro);
        textocifrado.close();
        textoclaro.close();
        byte[] docRec = textoclaro.toByteArray();
        return docRec;

    }

    public boolean verificarFirmaCliente(byte[] sigCliente, byte[] firmacliente) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        String algoritmo;
        int longbloque;
        byte bloque[] = new byte[1024];

        System.out.println("Inicio de la verificación del cliente...");
        ByteArrayInputStream validar = new ByteArrayInputStream(sigCliente);
        ClavePublica();
        if (publicKey.getAlgorithm().equalsIgnoreCase("RSA")) {
            algoritmo = "MD5withRSA";
        } else {
            algoritmo = "SHA1withDSA";
        }
        //Creacion del objeto para firmar y inicializacion del objeto
        Signature object = Signature.getInstance(algoritmo);
        object.initVerify(publicKey);
        while ((longbloque = validar.read(bloque)) > 0) {
            object.update(bloque, 0, longbloque);
        }
        validar.close();

        if (object.verify(firmacliente)) {
            System.out.println("Firma del cliente correcta\n");
            return true;
        } else {
            System.out.println("Firma del cliente no valida\n");
            return false;
        }

    }

    private static void ClavePublica() {

        KeyStore keyStore;
        char[] passwordKeystore = "servidor".toCharArray();
        String pathkeystore = "keystores/servidortruststore.jce";
        String SKCliente = "autencliente";
        PublicKey publickey = null;
        try {
            keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream(pathkeystore), passwordKeystore);
            publickey = keyStore.getCertificate(SKCliente).getPublicKey();
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
        publicKey = publickey;
    }

    private PrivateKey ClavePrivada() {
        KeyStore keyStore;
        char[] passwordKeystore = "servidor".toCharArray();
        char[] passwordPrivateKey = "servidor".toCharArray();
        String pathkeystore = "keystores/servidorkeystore.jce";
        String SKServidor = "servidordsa";
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
        privateKeyServ = privateKey;
        return privateKey;
    }


}
