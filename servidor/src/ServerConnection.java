import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Scanner;

public class ServerConnection extends Thread {

    private Socket cliente;
    /* private static PrintWriter sendData;
    private static DataInputStream receivedBytes;
    private static DataOutputStream sendBytes;*/
    private FirmarServidorValidarCliente firmarSVerificarC = new FirmarServidorValidarCliente();
    private LinkedList<Integer> IdsRegistros = new LinkedList<>();
    private LinkedList<Long> IdsOperacion = new LinkedList<>();
    private LinkedList<Archivo> listaArchivos = new LinkedList<>();

    private static ObjectInputStream receivedObject;
    private static ObjectOutputStream sendObject;


    public ServerConnection(Socket cliente) {
        this.cliente = cliente;
    }

    public void run() {

        try {
            System.out.println("***** Connection established ******\n");
            BufferedReader receivedData = new BufferedReader(new InputStreamReader(cliente.getInputStream()));
           /* sendData = new PrintWriter(new BufferedWriter(new OutputStreamWriter(cliente.getOutputStream())), true);
            receivedBytes = new DataInputStream(cliente.getInputStream());
            sendBytes = new DataOutputStream(cliente.getOutputStream());
*/
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
            System.out.println("**** El cliente se ha desconectado ****\nError: " + e.getMessage());
        }
    }

    private void registrarDocumento() {

        long idOperacion = idOperacion();
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
            System.out.println("IdOperación-> " + idOperacion);
            System.out.println("IdRegistro-> " + idRegistro);
            System.out.println("Propietario-> " + idpropietario);
            System.out.println("Nombredoc-> " + nombreDoc);
            System.out.println("Tipo de confidencialidad-> " + tipoConfidencialidad);

            /*** GUARDANDO EL ARCHIVO ***/

            //DataOutputStream escribir = new DataOutputStream(new ByteArrayOutputStream());

            String selloTemporal = new Date().toString();

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
            File guardado;
            Archivo archivo;
            if (peticion.isPrivado()) {
                String nombre = String.valueOf(idRegistro) + "_" + idpropietario + ".sig.cif";
                byte[] docCifrado = firmarSVerificarC.cifrarDoc(peticion.getDocumento());
                archivo = new Archivo(idRegistro, nombreDoc, idpropietario, selloTemporal, true, docCifrado, peticion.getFirmaDoc(), firmaServidor, firmarSVerificarC.getEncoding());
                listaArchivos.add(archivo);
                guardado = new File(nombre);
                System.out.println("Documento guardado\n");
            } else {
                String nombre = String.valueOf(idRegistro) + "_" + idpropietario + ".sig";
                archivo = new Archivo(idRegistro, nombreDoc, idpropietario, selloTemporal, false, peticion.getDocumento(), peticion.getFirmaDoc(), firmaServidor, null);
                listaArchivos.add(archivo);
                guardado = new File(nombre);
                System.out.println("Documento guardado\n");
            }

            ObjectOutputStream escribir = new ObjectOutputStream(new FileOutputStream(guardado));
            escribir.writeObject(archivo);
            escribir.close();

            /**ARCHIVO GUARDADO ***/
            RespuestaRegistro respuesta;
            respuesta = new RespuestaRegistro(idRegistro, "Documento registrado correctamente", archivo.getFirmaServidor(), archivo.getSelloTemporal(), true);

            sendObject.writeObject(respuesta);

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    private int encontrarDoc(String idPropietario, int idRegistro) {
        int ret = -1;
        for (int i = 0; i < listaArchivos.size(); i++) {
            String idP = listaArchivos.get(i).getIdPropietario();
            int idR = listaArchivos.get(i).getIdRegistro();
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
                if (listaArchivos.get(i).isPrivado()) {
                    /*******Validar firma cliente****/
                    ByteArrayOutputStream escribirfirma = new ByteArrayOutputStream();
                    DataOutputStream escribir = new DataOutputStream(escribirfirma);
                    escribir.writeUTF(idpropietario);
                    escribir.writeInt(idRegistro);
                    byte[] sigCliente = escribirfirma.toByteArray();
                    escribirfirma.close();
                    boolean validoCliente;
                    validoCliente = firmarSVerificarC.verificarFirmaCliente(sigCliente, peticion.getFirmaCliente());
                    if(!validoCliente){
                        RespuestaRecuperar respuesta = new RespuestaRecuperar(idRegistro, "Acceso no permitido", null, null, null, "", false);
                        sendObject.writeObject(respuesta);
                        System.out.println("Firma cliente no valida \nEnviando respuesta...\n");
                    }else{
                        byte[] docDescifrado = firmarSVerificarC.descifrarDoc(listaArchivos.get(i).getDoc(), listaArchivos.get(i).getEncoding());
                        RespuestaRecuperar respuesta = new RespuestaRecuperar(idRegistro, "Documento recuperado correctamente", docDescifrado, listaArchivos.get(i).getFirmaServidor(), listaArchivos.get(i).getFirmaCliente(), listaArchivos.get(i).getSelloTemporal(), true);
                        sendObject.writeObject(respuesta);
                        System.out.println("Documento recuperado correctamente\nEnviando respuesta...\n");
                    }
                } else {
                    byte[] docRec = listaArchivos.get(i).getDoc();
                    RespuestaRecuperar respuesta = new RespuestaRecuperar(idRegistro, "Documento recuperado correctamente", docRec, listaArchivos.get(i).getFirmaServidor(), listaArchivos.get(i).getFirmaCliente(), listaArchivos.get(i).getSelloTemporal(), true);
                    sendObject.writeObject(respuesta);
                    System.out.println("(no validar cliente) Documento recuperado correctamente\nEnviando respuesta...\n");
                }

            } else {
                RespuestaRecuperar respuesta = new RespuestaRecuperar(idRegistro, "Documento no existente", null, null, null, "", false);
                System.out.println("Documento no existente " + idRegistro + " " + idpropietario + "\n\n");
                sendObject.writeObject(respuesta);
            }

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
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
            for (Archivo documento : listaArchivos) {
                if (documento.isPrivado()) {
                    if (documento.getIdPropietario().equalsIgnoreCase(idpropietario)) {
                        idRegistro = documento.getIdRegistro();
                        nombreDoc = documento.getNombredoc();
                        selloTemporal = documento.getSelloTemporal();
                        ListaPrivados.add("IdRregistro: " + idRegistro + "| Nombre: " + nombreDoc + "| SelloTemporal: " + selloTemporal);
                    }
                } else {
                    idRegistro = documento.getIdRegistro();
                    nombreDoc = documento.getNombredoc();
                    selloTemporal = documento.getSelloTemporal();
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

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public long idOperacion() {
        long idOperacion;
        do {
            idOperacion = (long) (Math.random() * (Math.pow(2, 80)));
        } while (IdsOperacion.contains(idOperacion));
        IdsOperacion.add(idOperacion);
        return idOperacion;
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
