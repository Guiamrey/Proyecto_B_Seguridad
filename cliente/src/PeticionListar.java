import java.io.Serializable;

public class PeticionListar implements Serializable {
    private String idPropietario;

    public PeticionListar(String idPropietario){
        this.idPropietario = idPropietario;
    }

    public String getIdPropietario() {
        return idPropietario;
    }
}
