import java.io.Serializable;

public class Archivo implements Serializable{

    private int idRegistro;
    private String nombredoc;
    private String idPropietario;
    private String selloTemporal;
    private boolean privado;
    private String extension;
    private byte[] doc;
    private byte[] firmaCliente;
    private byte[] firmaServidor;
    private byte[] firmaTSA;
    private byte[] encoding;

    public Archivo(int idRegistro, String nombredoc, String extension, String idPropietario, String selloTemporal, byte[] firmaTSA, boolean privado, byte[] doc, byte[] firmaCliente, byte[] firmaServidor, byte[] encoding){
        this.idRegistro = idRegistro;
        this.nombredoc = nombredoc;
        this.extension = extension;
        this.idPropietario = idPropietario;
        this.selloTemporal = selloTemporal;
        this.privado = privado;
        this.doc = doc;
        this.firmaCliente = firmaCliente;
        this.firmaServidor = firmaServidor;
        this.encoding = encoding;
        this.firmaTSA = firmaTSA;

    }

    public byte[] getFirmaTSA() {
        return firmaTSA;
    }

    public String getExtension() {
        return extension;
    }

    public int getIdRegistro() {
        return idRegistro;
    }

    public String getIdPropietario() {
        return idPropietario;
    }

    public String getNombredoc() {
        return nombredoc;
    }

    public String getSelloTemporal() {
        return selloTemporal;
    }

    public byte[] getDoc() {
        return doc;
    }

    public boolean isPrivado() {
        return privado;
    }

    public byte[] getFirmaCliente() {
        return firmaCliente;
    }

    public byte[] getFirmaServidor() {
        return firmaServidor;
    }

    public byte[] getEncoding() {
        return encoding;
    }
}

