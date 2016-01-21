import java.io.Serializable;

public class RespuestaRegistro implements Serializable{

    private long idRegistro;
    private int mensaje;
    byte[] firmaServidor;
    private String selloTemporal;
    private boolean correcto;

    public RespuestaRegistro(long idRegistro, int mensaje, byte[] firmaServidor, String selloTemporal, boolean correcto){
        this.idRegistro = idRegistro;
        this.selloTemporal = selloTemporal;
        this.mensaje = mensaje;
        this.firmaServidor = firmaServidor;
        this.correcto = correcto;
    }

    public long getIdRegistro() {
        return idRegistro;
    }

    public int getMensaje() {
        return mensaje;
    }

    public boolean isCorrecto() {
        return correcto;
    }

    public byte[] getFirmaServidor() {
        return firmaServidor;
    }

    public String getSelloTemporal() {
        return selloTemporal;
    }
}
