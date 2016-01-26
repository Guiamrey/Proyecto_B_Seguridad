import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class ServerConnection extends Thread {

    private Socket cliente;
    private String algCifrado;
    private FirmarServidorValidarCliente firmarSVerificarC = new FirmarServidorValidarCliente();
    private static ArrayList<Integer> IdsRegistros = new ArrayList<>();
    private static ArrayList<BaseDeDatos> BaseDatos = new ArrayList<>();
    private ObjectInputStream receivedObject;
    private ObjectOutputStream sendObject;

    public ServerConnection(Socket cliente, String algCifrado) {

        this.cliente = cliente;
        this.algCifrado = algCifrado;
    }

    public void run() {

        try {
            System.out.println("***************************** Connection established ********************************\n");
            BufferedReader receivedData = new BufferedReader(new InputStreamReader(cliente.getInputStream()));
            sendObject = new ObjectOutputStream(cliente.getOutputStream());
            receivedObject = new ObjectInputStream(cliente.getInputStream());

            while (true) {
                String opcion = receivedData.readLine();
                int opc = Integer.parseInt(opcion);
                System.out.println("********* NUEVA OPERACION *********\n");
                switch (opc) {
                    case 1:
                        registrarDocumento();
                        break;
                    case 2:
                        recuperarDocumento();
                        break;
                    case 3:
                        listarDocumentos();
                        break;
                    default:
                        System.out.println("Opcion no válida");
                        break;
                }
            }
        } catch (IOException e) {
            System.out.println("\n************************** El cliente se ha desconectado ****************************\nError: " + e.getMessage());
        }
    }

    private void registrarDocumento() {
        int idRegistro = idRegistro();
        try {
            PeticionRegistro peticion = (PeticionRegistro) receivedObject.readObject();
            String idpropietario = peticion.getIdPropietario();
            String nombreDoc = peticion.getNombreDoc();
            String tipoConfidencialidad;
            if (peticion.isPrivado()) {
                tipoConfidencialidad = "privado";
            } else {
                tipoConfidencialidad = "publico";
            }
            System.out.println("Datos de la operación actual: REGISTRO");
            System.out.println("IdRegistro-> " + idRegistro);
            System.out.println("Propietario-> " + idpropietario);
            System.out.println("Nombredoc-> " + nombreDoc);
            System.out.println("Tipo de confidencialidad-> " + tipoConfidencialidad);


            /***********************OBTENCION DEL SELLO TEMPORAL CON EL TSA***************************/
            int puertoTSA = 9060;
            String host = "127.0.0.1";
            SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket SSLsocket = (SSLSocket) socketFactory.createSocket(host, puertoTSA);
            System.out.println(" **** Inicio del handshake con el TSA ***");
            SSLsocket.startHandshake();
            System.out.println("**** Conexion con el TSA correctamente establecida **** \n");
            ObjectOutputStream sendObjectTSA = new ObjectOutputStream(SSLsocket.getOutputStream());
            ObjectInputStream receivedObjectTSA = new ObjectInputStream(SSLsocket.getInputStream());
            byte[] hash = SHA256(peticion.getDocumento());
            PeticionTimestamp request = new PeticionTimestamp(hash);
            sendObjectTSA.writeObject(request);
            System.out.println("Peticion para obtención de timestamp enviada al TSA...");
            System.out.println("Esperando respuesta...");
            RespuestaTimestamp selloTemporalTSA = (RespuestaTimestamp) receivedObjectTSA.readObject();
            /******************Verificacion de la firma del TSA*******************/
            ByteArrayOutputStream writefirma = new ByteArrayOutputStream();
            DataOutputStream esc = new DataOutputStream(writefirma);
            esc.write(hash);
            esc.writeUTF(selloTemporalTSA.getSelloTemporal());
            byte[] firmaTSA = writefirma.toByteArray();
            writefirma.close();
            boolean TSAvalido = firmarSVerificarC.verificarFirmaTSA(firmaTSA, selloTemporalTSA.getFirmaTSA());
            if (TSAvalido) {

                String selloTemporal = selloTemporalTSA.getSelloTemporal();
                /*********************FIN OBTENCION DEL SELLO TEMPORAL CON EL TSA**************************/
                /*************Verifican firma cliente*********************/
                boolean validoFirmaDoc = firmarSVerificarC.verificarFirmaCliente(peticion.getDocumento(), peticion.getFirmaDoc());
                if (validoFirmaDoc) {
                    /*******************Crear firma servidor SigRD************/
                    ByteArrayOutputStream escribirfirma = new ByteArrayOutputStream();
                    DataOutputStream write = new DataOutputStream(escribirfirma);
                    write.writeInt(idRegistro);
                    write.writeUTF(selloTemporal);
                    write.write(peticion.getDocumento());
                    write.write(peticion.getFirmaDoc());

                    byte[] firma = escribirfirma.toByteArray();
                    escribirfirma.close();

                    firmarSVerificarC.firmarServidor(firma);
                    byte[] firmaServidor = firmarSVerificarC.getFirmaServidor();
                    /******* GUARDANDO EL ARCHIVO *******/
                    File guardado;
                    Archivo archivo;
                    String extension = nombreDoc.split("\\.")[1];
                    if (peticion.isPrivado()) {
                        String nombre = String.valueOf(idRegistro) + "_" + idpropietario + ".sig.cif";
                        byte[] docCifrado = firmarSVerificarC.cifrarDoc(peticion.getDocumento(), algCifrado);
                        archivo = new Archivo(idRegistro, nombreDoc, extension, idpropietario, selloTemporal, selloTemporalTSA.getFirmaTSA(),true, docCifrado, peticion.getFirmaDoc(), firmaServidor, firmarSVerificarC.getEncoding());
                        BaseDeDatos nuevoregistro = new BaseDeDatos(idRegistro, nombreDoc, idpropietario, selloTemporal, true);
                        BaseDatos.add(nuevoregistro);
                        guardado = new File(nombre);
                        System.out.println("Documento guardado correctamente\nEnviando respuesta...\n");
                    } else {
                        String nombre = String.valueOf(idRegistro) + "_" + idpropietario + ".sig";
                        archivo = new Archivo(idRegistro, nombreDoc, extension, idpropietario, selloTemporal, selloTemporalTSA.getFirmaTSA(),false, peticion.getDocumento(), peticion.getFirmaDoc(), firmaServidor, null);
                        BaseDeDatos nuevoregistro = new BaseDeDatos(idRegistro, nombreDoc, idpropietario, selloTemporal, false);
                        BaseDatos.add(nuevoregistro);
                        guardado = new File(nombre);
                        System.out.println("Documento guardado correctamente\nEnviando respuesta...");
                    }

                    ObjectOutputStream escribir = new ObjectOutputStream(new FileOutputStream(guardado));
                    escribir.writeObject(archivo);
                    escribir.close();

                    /******ARCHIVO GUARDADO *******/
                    RespuestaRegistro respuesta = new RespuestaRegistro(idRegistro, 1, archivo.getFirmaServidor(), archivo.getSelloTemporal(), true);
                    sendObject.writeObject(respuesta);
                } else {
                    RespuestaRegistro respuesta = new RespuestaRegistro(idRegistro, 0, null, null, false);
                    sendObject.writeObject(respuesta);
                }
            } else {
                RespuestaRegistro respuesta = new RespuestaRegistro(idRegistro, 2, null, null, false);
                sendObject.writeObject(respuesta);
            }
        } catch (IOException | ClassNotFoundException | UnrecoverableEntryException | NoSuchPaddingException | NoSuchAlgorithmException | CertificateException | InvalidKeyException | BadPaddingException | KeyStoreException | IllegalBlockSizeException | SignatureException e) {
            e.printStackTrace();
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

    private int encontrarDoc(String idPropietario, int idRegistro) {
        int ret = -1;
        for (int i = 0; i < BaseDatos.size(); i++) {
            String idP = BaseDatos.get(i).getIdPropietario();
            int idR = BaseDatos.get(i).getIdRegistro();
            if (idP.equals(idPropietario) && (idR == idRegistro)) {
                return i;
            }
        }
        return ret;
    }

    private void recuperarDocumento() {

        try {
            PeticionRecuperar peticion = (PeticionRecuperar) receivedObject.readObject();
            String idpropietario = peticion.getIdPropietario();
            int idRegistro = peticion.getIdRegistro();

            System.out.println("Datos de la operación actual: RECUPERAR");
            System.out.println("IdRegistro-> " + idRegistro);
            System.out.println("Propietario-> " + idpropietario);
            int i = encontrarDoc(idpropietario, idRegistro);
            if (i >= 0) {
                if (BaseDatos.get(i).isPrivado()) { //privado
                    /*******Validar firma cliente****/
                    ByteArrayOutputStream escribirfirma = new ByteArrayOutputStream();
                    DataOutputStream escribir = new DataOutputStream(escribirfirma);
                    escribir.writeUTF(idpropietario);
                    escribir.writeInt(idRegistro);
                    byte[] sigCliente = escribirfirma.toByteArray();
                    escribirfirma.close();
                    boolean validoCliente;
                    validoCliente = firmarSVerificarC.verificarFirmaCliente(sigCliente, peticion.getFirmaCliente());
                    if (!validoCliente) {
                        RespuestaRecuperar respuesta = new RespuestaRecuperar(idRegistro, 2, null, null, null, null, null, "", false);
                        sendObject.writeObject(respuesta);
                        System.out.println("Firma cliente no valida \nEnviando respuesta...\n");
                    } else {
                        String ruta = String.valueOf(idRegistro) + "_" + idpropietario + ".sig.cif";
                        ObjectInputStream leerObjeto = new ObjectInputStream(new FileInputStream(ruta));
                        Archivo provisional = (Archivo) leerObjeto.readObject();
                        leerObjeto.close();
                        byte[] docDescifrado = firmarSVerificarC.descifrarDoc(provisional.getDoc(), provisional.getEncoding(), algCifrado);
                        RespuestaRecuperar respuesta = new RespuestaRecuperar(idRegistro, 0, provisional.getExtension(), docDescifrado, provisional.getFirmaServidor(), provisional.getFirmaCliente(), provisional.getFirmaTSA(), provisional.getSelloTemporal(), true);
                        sendObject.writeObject(respuesta);
                        System.out.println("Documento recuperado correctamente\nEnviando respuesta...\n");
                    }
                } else { //No privado
                    String ruta = String.valueOf(idRegistro) + "_" + idpropietario + ".sig";
                    ObjectInputStream leerObjeto = new ObjectInputStream(new FileInputStream(ruta));
                    Archivo provisional = (Archivo) leerObjeto.readObject();
                    leerObjeto.close();
                    byte[] docRec = provisional.getDoc();
                    RespuestaRecuperar respuesta = new RespuestaRecuperar(idRegistro, 0, provisional.getExtension(), docRec, provisional.getFirmaServidor(), provisional.getFirmaCliente(), provisional.getFirmaTSA(), provisional.getSelloTemporal(), true);
                    sendObject.writeObject(respuesta);
                    System.out.println("Documento recuperado correctamente\nEnviando respuesta...\n");
                }

            } else {
                RespuestaRecuperar respuesta = new RespuestaRecuperar(idRegistro, 1, null, null, null, null, null, "", false);
                System.out.println("Documento no existente " + idRegistro + " " + idpropietario + "\n\n");
                sendObject.writeObject(respuesta);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void listarDocumentos() {
        try {
            PeticionListar peticion = (PeticionListar) receivedObject.readObject();
            String idpropietario = peticion.getIdPropietario();

            System.out.println("Datos de la operación actual: LISTAR");
            System.out.println("Propietario-> " + idpropietario);
            LinkedList<String> ListaPublicos = new LinkedList<>();
            LinkedList<String> ListaPrivados = new LinkedList<>();
            int idRegistro;
            String nombreDoc;
            String selloTemporal;
            for (BaseDeDatos registro : BaseDatos) {
                if (registro.isPrivado()) {
                    if (registro.getIdPropietario().equalsIgnoreCase(idpropietario)) {
                        idRegistro = registro.getIdRegistro();
                        nombreDoc = registro.getNombredoc();
                        selloTemporal = registro.getSelloTemporal();
                        ListaPrivados.add("IdRregistro: " + idRegistro + "| Nombre: " + nombreDoc + "| SelloTemporal: " + selloTemporal);
                    }
                } else {
                    idRegistro = registro.getIdRegistro();
                    nombreDoc = registro.getNombredoc();
                    selloTemporal = registro.getSelloTemporal();
                    ListaPublicos.add("IdRregistro: " + idRegistro + "| Nombre: " + nombreDoc + "| SelloTemporal: " + selloTemporal);
                }
            }
            if (ListaPublicos.isEmpty()) {
                System.out.println("No hay documentos públicos");
            }
            if (ListaPrivados.isEmpty()) {
                System.out.println("No hay documentos privados del propietario: " + idpropietario);
            }
            RespuestaListar respuesta = new RespuestaListar(ListaPublicos, ListaPrivados);
            sendObject.writeObject(respuesta);
            System.out.println("\nEnviando respuesta...\n");

        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
        }
    }

    public int idRegistro() {
        int idRegistro = 1;
        while (IdsRegistros.contains(idRegistro)) {
            idRegistro++;
        }
        IdsRegistros.add(idRegistro);
        return idRegistro;
    }

}
