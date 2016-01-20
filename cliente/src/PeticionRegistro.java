import java.io.Serializable;

public class PeticionRegistro implements Serializable {

    private String nombreDoc;
    private String idPropietario;
    private byte[] documento;
    private byte[] firmaDoc;
    private boolean privado;

    public PeticionRegistro(String nombreDoc, String idPropietario, byte[] documento, byte[] firmaDoc, boolean privado){
        this.nombreDoc = nombreDoc;
        this.idPropietario = idPropietario;
        this.documento = documento;
        this.firmaDoc = firmaDoc;
        this.privado = privado;
    }

    public String getNombreDoc() {
        return nombreDoc;
    }

    public String getIdPropietario() {
        return idPropietario;
    }

    public byte[] getDocumento() {
        return documento;
    }

    public byte[] getFirmaDoc() {
        return firmaDoc;
    }

    public boolean isPrivado() {
        return privado;
    }
}
