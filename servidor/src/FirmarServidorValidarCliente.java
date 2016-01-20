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


        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

    }

    public byte[] getFirmaServidor() {
        return firma;
    }

    public byte[] cifrarDoc(byte[] doc) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        KeyStore keyStores;
        char[] password = "cliente".toCharArray();
        char[] passphrase = "cliente".toCharArray();

        keyStores = KeyStore.getInstance("JCEKS");
        keyStores.load(new FileInputStream("servidor.jce"), passphrase);
        KeyStore.SecretKeyEntry ksEntry = (KeyStore.SecretKeyEntry) keyStores.getEntry("ksservidor", new KeyStore.PasswordProtection(password));
        SecretKey key = ksEntry.getSecretKey();

        String provider = "SunJCE";
        byte bloqueclaro[] = new byte[2024];
        byte bloquecifrado[];
        String algoritmo = "AES";
        String transformacion = "/CBC/PKCS5Padding";
        int longclave = 128;
        int longbloque;

            System.out.println("Cifrando documento: " + algoritmo + "-" + longclave);
            Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);
            cifrador.init(Cipher.ENCRYPT_MODE, key);
            ByteArrayInputStream textoclaro = new ByteArrayInputStream(doc);
            ByteArrayOutputStream textocifrado = new ByteArrayOutputStream();

            while ((longbloque = textoclaro.read(bloqueclaro)) > 0) {
                bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
                textocifrado.write(bloquecifrado);
            }
            bloquecifrado = cifrador.doFinal();
            textocifrado.write(bloquecifrado);
            System.out.println("Documento cifrado> " + algoritmo + "-" + longclave + " Proveedor: " + provider);
            textocifrado.close();
            textoclaro.close();

        byte[] cifrado = textocifrado.toByteArray();
        encoding = cifrador.getParameters().getEncoded();
        return cifrado;
    }

    public byte[] getEncoding() {
        return encoding;
    }

    private byte[] descifrarDoc(byte[] docCifrado, byte[] encoding) throws Exception {

        System.out.println("Descifrando documento...");

        KeyStore ks;
        char[] contraseña = "cliente".toCharArray();
        char[] contraseñaKey = "cliente".toCharArray();

        ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream("servidor.jce"), contraseñaKey);
        KeyStore.SecretKeyEntry ksEntry = (KeyStore.SecretKeyEntry) ks.getEntry("ksservidor", new KeyStore.PasswordProtection(contraseña));
        SecretKey key = ksEntry.getSecretKey();

        String provider = "SunJCE";
        byte bloqueclaro[];
        byte bloquecifrado[] = new byte[1024];
        String algoritmo = "AES";
        String transformacion = "/CBC/PKCS5Padding";
        int longclave = 128;
        int longbloque;
        AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo, provider);
        params.init(encoding);

        System.out.println("Descifrando documento: " + algoritmo + "-" + longclave);
        Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);
        descifrador.init(Cipher.DECRYPT_MODE, key, params);

        ByteArrayInputStream textocifrado = new ByteArrayInputStream(docCifrado);
        ByteArrayOutputStream textoclaro = new ByteArrayOutputStream();

        while ((longbloque = textocifrado.read(bloquecifrado)) > 0) {
            bloqueclaro = descifrador.update(bloquecifrado, 0, longbloque);
            textoclaro.write(bloqueclaro);
        }

        bloqueclaro = descifrador.doFinal();

        System.out.println("Documento descifrado.");
        textoclaro.write(bloqueclaro);
        textocifrado.close();
        textoclaro.close();
        byte[] docRec = textoclaro.toByteArray();
        return docRec;

    }

    public boolean verificarFirmaCliente(String nombreFile, byte[] firmacliente, PublicKey publicKey) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        String algoritmo;
        int longbloque;
        byte bloque[] = new byte[1024];

        FileInputStream file = null;
        file = new FileInputStream(nombreFile);

        if (publicKey.getAlgorithm().equalsIgnoreCase("RSA")) {
            algoritmo = "MD5withRSA";
        } else {
            algoritmo = "SHA1withDSA";
        }
        //Creacion del objeto para firmar y inicializacion del objeto
        Signature object = Signature.getInstance(algoritmo);
        System.out.println("** INICIANDO VERIFICACIÓN DEL CLIENTE **");
        object.initVerify(publicKey);
        while ((longbloque = file.read(bloque)) > 0) {
            object.update(bloque, 0, longbloque);
        }
        file.close();
        System.out.println("** FIN DE LA VERIFICACIÓN **");

        if (object.verify(firmacliente)) {
            System.out.println("FIRMA VÁLIDA\n");
            return true;
        } else {
            System.out.println("FIRMA INCORRECTA\n");
            return false;
        }

    }

    private PublicKey ClavePublica() {

        KeyStore keyStore;
        char[] passwordKeystore = "cliente".toCharArray();
        String pathkeystore = "keystores/clientekeystore.jce";
        String SKCliente = "cliente";
      /*  char[] passwordKeystore = "cliente".toCharArray(); //anton
        String pathkeystore = "servidor_cacerts.jce";
        String SKCliente = "firmadoc";*/
        PublicKey publicKey = null;
        try {
            keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream(pathkeystore), passwordKeystore);
            publicKey = keyStore.getCertificate(SKCliente).getPublicKey();
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    private PrivateKey ClavePrivada() {
        KeyStore keyStore;
        char[] passwordKeystore = "servidor".toCharArray();
        char[] passwordPrivateKey = "servidor".toCharArray();
        String pathkeystore = "keystores/servidorkeystore.jce";
        String SKServidor = "servidordsa";
       /* char[] passwordKeystore = "cliente".toCharArray(); //anton
        char[] passwordPrivateKey = "cliente".toCharArray();
        String pathkeystore = "servidor.jce";
        String SKServidor = "servidor";*/
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
