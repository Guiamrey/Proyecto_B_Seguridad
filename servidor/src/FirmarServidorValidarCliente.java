import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

public class FirmarServidorValidarCliente {


    private static PrivateKey privateKeyServ;
    private static PublicKey publicKey;
    private static PublicKey publicKeyTSA;
    private static byte[] firma;
    byte[] encoding;

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
            Signature signer = Signature.getInstance(algoritmo);
            signer.initSign(privateKeyServ);
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

    }

    public byte[] getFirmaServidor() {
        return firma;
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
        Signature verifier = Signature.getInstance(algoritmo);
        verifier.initVerify(publicKey);
        while ((longbloque = validar.read(bloque)) > 0) {
            verifier.update(bloque, 0, longbloque);
        }
        validar.close();

        if (verifier.verify(firmacliente)) {
            System.out.println("Firma del cliente correcta\n");
            return true;
        } else {
            System.out.println("Firma del cliente no valida\n");
            return false;
        }

    }


    public byte[] cifrarDoc(byte[] doc, String algCifrado) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        KeyStore keyStores;
        char[] contraseña = "servidor".toCharArray();
        char[] contraseñaKey = "servidor".toCharArray();
        String algoritmo;

        keyStores = KeyStore.getInstance("JCEKS");
        keyStores.load(new FileInputStream("keystores/servidorkeystore.jce"), contraseñaKey);
        KeyStore.SecretKeyEntry ksEntry;
        if (algCifrado.equalsIgnoreCase("AES-128")) {
            ksEntry = (KeyStore.SecretKeyEntry) keyStores.getEntry("seckeyaes-128", new KeyStore.PasswordProtection(contraseña));
            algoritmo = "AES/CBC/PKCS5Padding";
        } else {
            ksEntry = (KeyStore.SecretKeyEntry) keyStores.getEntry("seckeyarcfour", new KeyStore.PasswordProtection(contraseña));
            algoritmo = "ARCFOUR";
        }
        SecretKey secretKey = ksEntry.getSecretKey();

        String provider = "SunJCE";
        byte bloqueclaro[] = new byte[2024];
        byte bloquecifrado[];
        int longbloque;

        ByteArrayInputStream docSinCifrar = new ByteArrayInputStream(doc);
        ByteArrayOutputStream yaCifrado = new ByteArrayOutputStream();

        System.out.println("Cifrando documento...");
        Cipher cifrador = Cipher.getInstance(algoritmo);
        cifrador.init(Cipher.ENCRYPT_MODE, secretKey);

        while ((longbloque = docSinCifrar.read(bloqueclaro)) > 0) {
            bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
            yaCifrado.write(bloquecifrado);
        }
        bloquecifrado = cifrador.doFinal();
        yaCifrado.write(bloquecifrado);
        System.out.println("Documento cifrado-> " + algCifrado + " Proveedor: " + provider);
        yaCifrado.close();
        docSinCifrar.close();
        if (algCifrado.equals("AES-128")) {

            encoding = cifrador.getParameters().getEncoded();

        }
        byte[] docCifrado = yaCifrado.toByteArray();
        return docCifrado;
    }

    public byte[] getEncoding() {
        return encoding;
    }

    public byte[] descifrarDoc(byte[] docCifrado, byte[] encoding, String algCifrado) throws Exception {

        System.out.println("Descifrando documento...");

        KeyStore keyStore;
        char[] contraseña = "servidor".toCharArray();
        char[] contraseñaKey = "servidor".toCharArray();
        String algoritmo;
        String transformacion = "";

        keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(new FileInputStream("keystores/servidorkeystore.jce"), contraseñaKey);
        KeyStore.SecretKeyEntry ksEntry;
        if (algCifrado.equalsIgnoreCase("AES-128")) {
            ksEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("seckeyaes-128", new KeyStore.PasswordProtection(contraseña));
            algoritmo = "AES";
            transformacion = "/CBC/PKCS5Padding";
        } else {
            ksEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("seckeyarcfour", new KeyStore.PasswordProtection(contraseña));
            algoritmo = "ARCFOUR";
        }
        SecretKey key = ksEntry.getSecretKey();

        String provider = "SunJCE";
        byte bloqueclaro[];
        byte bloquecifrado[] = new byte[1024];
        int longbloque;

        Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);
        if (algCifrado.equals("AES-128")) {
            AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo, provider);
            params.init(encoding);
            descifrador.init(Cipher.DECRYPT_MODE, key, params);
        } else {
            descifrador.init(Cipher.DECRYPT_MODE, key);
        }

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

        return textoclaro.toByteArray();
    }

    private static void ClavePublica() {

        KeyStore keyStore;
        char[] passwordKeystore = "servidor".toCharArray();
        String pathkeystore = "keystores/servidortruststore.jce";
        //String SKCliente = "autenclient_rsa";
        String SKCliente = "autenclient_dsa";
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
        //String SKServidor = "servidor_rsa";
        String SKServidor = "servidor_dsa";
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

    private static void ClavePublicaTSA() {

        KeyStore keyStore;
        char[] passwordKeystore = "servidor".toCharArray();
        String pathkeystore = "keystores/servidortruststore.jce";
        String SKCliente = "autentsa_dsa";
        PublicKey publickey = null;
        try {
            keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream(pathkeystore), passwordKeystore);
            publickey = keyStore.getCertificate(SKCliente).getPublicKey();
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
        publicKeyTSA = publickey;
    }
    public boolean verificarFirmaTSA(byte[] sigTSA, byte[] firmacliente) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        String algoritmo = "SHA1withDSA";;
        int longbloque;
        byte bloque[] = new byte[1024];

        System.out.println("Inicio de la verificación del TSA...");
        ByteArrayInputStream validar = new ByteArrayInputStream(sigTSA);
        ClavePublicaTSA();
        //Creacion del objeto para firmar y inicializacion del objeto
        Signature verifier = Signature.getInstance(algoritmo);
        verifier.initVerify(publicKeyTSA);
        while ((longbloque = validar.read(bloque)) > 0) {
            verifier.update(bloque, 0, longbloque);
        }
        validar.close();

        if (verifier.verify(firmacliente)) {
            System.out.println("Firma del TSA correcta\n");
            return true;
        } else {
            System.out.println("Firma del TSA no valida\n");
            return false;
        }

    }

}
