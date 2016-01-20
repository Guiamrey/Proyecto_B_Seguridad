import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.lang.reflect.Array;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Scanner;


public class Cliente {

    static String SKCliente = "cliente"; //DSA
    static String SKServidor = "servidorrsa"; //DSA
    static String pathkeystore = "keystores/clientekeystore.jce";
    static String pathtruststore = "keystores/clientetruststore.jce";
    /*static String pathkeystore = "cliente.jce";
     static String pathtruststore = "cliente_cacerts.jce";*/
    static BufferedReader receivedData;
    static PrintWriter sendData;
    static DataInputStream receivedBytes;
    static DataOutputStream sendBytes;
    static FirmaClienteVerificarServidor firmaCliente;


    private static ObjectInputStream receivedObject;
    private static ObjectOutputStream sendObject;

    public static void main(String[] args) {

        int puerto = 9050;
        String host = "127.0.0.1";
        definirKeystores();

        try {

            SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

           /* *//**************  Suites SSL  *******************//*
             String[] suites = socketFactory.getSupportedCipherSuites();
            System.out.println("******** CypherSuites Disponibles **********");
            for (int i = 0; i < suites.length; i++) {
                System.out.println(i+1+".- "+suites[i]);
            }*/
            /***************************************************/
            SSLSocket SSLsocket = (SSLSocket) socketFactory.createSocket(host, puerto);
            SSLsocket.startHandshake();
            System.out.println("**** Conexion con el servidor correctamente establecida **** \n");

            receivedData = new BufferedReader(new InputStreamReader(SSLsocket.getInputStream()));
            sendData = new PrintWriter(new BufferedWriter(new OutputStreamWriter(SSLsocket.getOutputStream())), true);
            receivedBytes = new DataInputStream(SSLsocket.getInputStream());
            sendBytes = new DataOutputStream(SSLsocket.getOutputStream());
            firmaCliente = new FirmaClienteVerificarServidor();

            sendObject = new ObjectOutputStream(SSLsocket.getOutputStream());
            receivedObject = new ObjectInputStream(SSLsocket.getInputStream());


        } catch (IOException e) {
            System.out.println("****** Error al introducir las contraseñas o error en el HandShake\n" + e.getMessage());
            return;
        }
        seleccionarOpcion();

    }


    public static void seleccionarOpcion() {
        boolean exit = false;
        File exe = new File("exe.txt");
        String linea;
        Scanner leerExe = null;
        try {
            leerExe = new Scanner(exe);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        while (!exit) {

            System.out.println("\n\n************************************ NUEVA OPERACION **************************************\n\n");
            linea = leerExe.nextLine();

            String orden[] = linea.split(" ");

            int opcion;
            if (orden[0].equalsIgnoreCase("REGISTRAR_DOCUMENTO")) {
                System.out.println("******** REGISTRAR_DOCUMENTO ********");
                opcion = 1;
            } else if (orden[0].equalsIgnoreCase("RECUPERAR_DOCUMENTO")) {
                System.out.println("******** RECUPERAR_DOCUMENTO ********");
                opcion = 2;
            } else if (orden[0].equalsIgnoreCase("LISTAR_DOCUMENTOS")) {
                System.out.println("******** LISTAR_DOCUMENTOS ********");
                opcion = 3;
            } else if (orden[0].equalsIgnoreCase("EXIT")) {
                System.out.println("******** EXIT ********");
                opcion = 0;
            } else {
                opcion = 7;
            }
            switch (opcion) {
                case 0:
                    exit = true;
                    break;
                case 1:
                    registrarDocumento(orden);
                    break;
                case 2:
                    recuperarDocumento(orden);
                    break;
                case 3:
                    listarDocumentos(orden);
                    break;
                default:
                    System.out.println("***** Opción no válida *****");
                    break;
            }
        }

    }

    private static void registrarDocumento(String[] orden) {

        if (orden.length < 4) {
            System.out.println("Error de sintaxis. Faltan parametros.\n REGISTRAR_DOCUMENTO idPropietario nombreDocumento tipoConfidencialidad");
            return;
        }
        String idpropietario = orden[1];
        String nombreDoc = orden[2];
        String tipoConfidencialidad = orden[3];
        sendData.println("1");
        try {
            System.out.println("Leyendo el documento: " + nombreDoc);
            File doc = new File(nombreDoc);
            int tamaño = (int) doc.length();
            DataInputStream leer = new DataInputStream(new FileInputStream(doc));
            byte[] documento = new byte[tamaño];
            leer.readFully(documento);
            leer.close();
            //doc.delete();
            System.out.println("Documento leído");
            firmaCliente.FirmarDocumento(documento);
            boolean privado;
            if (tipoConfidencialidad.equalsIgnoreCase("privado")) {
                privado = true;
            } else {
                privado = false;
            }
            PeticionRegistro peticion = new PeticionRegistro(nombreDoc, idpropietario, documento, firmaCliente.getFirma(), privado);

            sendObject.writeObject(peticion);
            System.out.println("Peticion de registro enviada...");
            System.out.println("Respuesta del servidor...\n");
            RespuestaRegistro respuesta = (RespuestaRegistro) receivedObject.readObject();
            if (respuesta.isCorrecto()) {
                System.out.println(respuesta.getMensaje());
                System.out.println("IdRegistro: " + respuesta.getIdRegistro());
                System.out.println("Sello temporal: " + respuesta.getSelloTemporal());
                System.out.println("Firma del servidor: " + respuesta.getFirmaServidor());
                /************Crear hash(documento)***********/
                String hashD = "hash_" + String.valueOf(respuesta.getIdRegistro()) + idpropietario + ".txt";
                byte[] hashDoc = SHA256(documento);
                Files.write(Paths.get(hashD), hashDoc);
                /**************hash(documento) creado *****************/
            } else {
                System.out.println("ERROR: " + respuesta.getMensaje() + "\n\n");
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }


    }

    private static void recuperarDocumento(String[] orden) {

        if (orden.length < 3) {
            System.out.println("Error de sintaxis. Faltan parametros.\n RECUPERAR_DOCUMENTO idPropietario idRegistro");
            return;
        }
        String idPropietario = orden[1];
        int idRegistro = Integer.parseInt(orden[2]);

        sendData.println("2");
        sendData.flush();

        ByteArrayOutputStream firma = new ByteArrayOutputStream();
        DataOutputStream añadir = new DataOutputStream(firma);
        try {
            /*****************Crear firma**************/
            añadir.writeUTF(idPropietario);
            añadir.writeLong(idRegistro);
            byte[] firmaCliente = firma.toByteArray();
            firma.close();
            FirmaClienteVerificarServidor firmarcliente = new FirmaClienteVerificarServidor();
            firmarcliente.FirmarDocumento(firmaCliente);
            PeticionRecuperar peticion = new PeticionRecuperar(idPropietario, idRegistro, firmarcliente.getFirma());
            sendObject.writeObject(peticion);
            System.out.println("Peticion para recuperar enviada...");
            System.out.println("Respuesta del servidor...\n");
            RespuestaRecuperar respuesta = (RespuestaRecuperar) receivedObject.readObject();
            /******************Comprobar respuesta del servidor**********************/
            if (respuesta.isCorrecto()) {
                /*******Validar firma servidor****/
                ByteArrayOutputStream escribirfirma = new ByteArrayOutputStream();
                DataOutputStream escribir = new DataOutputStream(escribirfirma);
                escribir.writeInt(idRegistro);
                escribir.writeUTF(respuesta.getSelloTemporal());
                escribir.write(respuesta.getDoc());
                escribir.write(respuesta.getFirmaCliente());

                byte[] sigServ = escribirfirma.toByteArray();
                escribirfirma.close();
               // boolean valida = true;
                boolean valida = firmarcliente.verificarServidor(sigServ, respuesta.getFirmaServidor());
                if (valida) {
                    /*******Firma servidor validada****/
                    File recuperado = new File("recuperado_" + respuesta.getIdRegistro() + ".jpg");
                    DataOutputStream nuevofichero = new DataOutputStream(new FileOutputStream(recuperado));
                    nuevofichero.write(respuesta.getDoc());
                    nuevofichero.close();

                    String concat = String.valueOf(idRegistro) + idPropietario;
                    boolean ficherosIguales = ficherosIguales(respuesta.getDoc(), concat);
                    /*********************Comprobar hash del documento almacenado y del recuperado*************************/
                    if (ficherosIguales) {
                        System.out.println(respuesta.getMensaje());
                        System.out.println("IdRegistro: " + respuesta.getIdRegistro());
                        System.out.println("Sello temporal: " + respuesta.getSelloTemporal());
                        System.out.println("Firma del servidor: " + respuesta.getFirmaServidor());
                    } else {
                        System.out.println("Documento alterado por el registrador");
                    }
                }
            } else {
                System.out.println("ERROR: " + respuesta.getMensaje() + "\n\n");
            }


        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean ficherosIguales(byte[] docRecuperado, String concat) {
        String hash = "hash_" + concat + ".txt";
        byte[] hashDoc = null;
        try {
            hashDoc = Files.readAllBytes(Paths.get(hash));
        } catch (IOException e) {
            System.out.println("No se ha encontrado el hash en el sistema");
        }

        byte[] hashDocRec = SHA256(docRecuperado);
        if (hashDoc.length != hashDocRec.length) {
            System.out.println("Hash de diferentes tamaños");
            return false;
        }
        if (Arrays.equals(hashDoc, hashDocRec)) {
            return true;
        } else {
            return false;
        }
    }

    private static byte[] SHA256(byte[] doc) {
        byte[] hash = null;
        try {
            MessageDigest algorit = MessageDigest.getInstance("SHA-256");
            hash = algorit.digest(doc);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return hash;
    }

    private static void listarDocumentos(String[] orden) {

        if (orden.length < 2) {
            System.out.println("Error de sintaxis. Faltan parametros.\n RECUPERAR_DOCUMENTO idPropietario idRegistro");
            return;
        }
        String idPropietario = orden[1];
        sendData.println("3");
        sendData.flush();

        PeticionListar peticion = new PeticionListar(idPropietario);
        try {
            sendObject.writeObject(peticion);
            System.out.println("Peticion para recuperar enviada...");
            System.out.println("Respuesta del servidor...\n");
            RespuestaListar respuesta = (RespuestaListar) receivedObject.readObject();
            LinkedList<String> ListaPublicos = respuesta.getListaDocPublicos();
            LinkedList<String> ListaPrivados = respuesta.getListaDocPrivados();

            System.out.println("\n***Documentos públicos:");
            if (ListaPublicos.isEmpty()) {
                System.out.println("No hay documentos públicos");
            } else {
                for (String doc : ListaPublicos) {
                    System.out.println("- " + doc);
                }
            }

            System.out.println("\n***Documentos privados:");
            if (ListaPrivados.isEmpty()) {
                System.out.println("No hay documentos privados del propietario:" + idPropietario);
            } else {
                for (String doc : ListaPrivados) {
                    System.out.println("- " + doc);
                }
            }


        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }


    }

    public static void definirKeystores() {
        System.out.println("Valores de las contraseñas de los stores: \n(keyStoreFile) contraseñaKeystore (trustStoreFile) contraseñaTruststore)\n");
        Scanner consola = new Scanner(System.in);
        String cadena = consola.nextLine();
        String[] aux = cadena.split(" ");
        String passwKS = aux[0];
        String passwTS = aux[1];

        // Tipo de KeyStore usados
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        // Path al keystore del cliente
        System.setProperty("javax.net.ssl.keyStore", pathkeystore);
        // Contraseña del keystore del cliente
        System.setProperty("javax.net.ssl.keyStorePassword", passwKS);
        // Tipo de TrustStore usado
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        // Path al Trustore del cliente
        System.setProperty("javax.net.ssl.trustStore", pathtruststore);
        // Contraseña del trustore del cliente
        System.setProperty("javax.net.ssl.trustStorePassword", passwTS);

    }
}
