
public class BaseDeDatos {

    private int idRegistro;
    private String nombredoc;
    private String idPropietario;
    private String selloTemporal;
    private boolean privado;

    public BaseDeDatos(int idRegistro, String nombredoc, String idPropietario, String selloTemporal, boolean privado) {
        this.idRegistro = idRegistro;
        this.nombredoc = nombredoc;
        this.idPropietario = idPropietario;
        this.selloTemporal = selloTemporal;
        this.privado = privado;
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

    public boolean isPrivado() {
        return privado;
    }

}
