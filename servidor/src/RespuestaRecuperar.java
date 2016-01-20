import java.io.Serializable;

public class RespuestaRecuperar implements Serializable {

    private long idRegistro;
    private String mensaje;
    byte[] firmaServidor;
    private byte[] doc;
    private String selloTemporal;
    private boolean correcto;
    private byte[] firmaCliente;

    public RespuestaRecuperar(long idRegistro, String mensaje, byte[] doc, byte[] firmaServidor, byte[] firmaCliente, String selloTemporal, boolean correcto){
        this.idRegistro = idRegistro;
        this.selloTemporal = selloTemporal;
        this.doc = doc;
        this.mensaje = mensaje;
        this.firmaCliente = firmaCliente;
        this.firmaServidor = firmaServidor;
        this.correcto = correcto;
    }

    public byte[] getDoc() {
        return doc;
    }

    public long getIdRegistro() {
        return idRegistro;
    }

    public String getMensaje() {
        return mensaje;
    }

    public boolean isCorrecto() {
        return correcto;
    }

    public byte[] getFirmaServidor() {
        return firmaServidor;
    }
    public byte[] getFirmaCliente() {
        return firmaCliente;
    }

    public String getSelloTemporal() {
        return selloTemporal;
    }
}