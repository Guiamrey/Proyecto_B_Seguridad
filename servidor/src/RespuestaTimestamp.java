import java.io.Serializable;

public class RespuestaTimestamp implements Serializable {

    private String selloTemporal;
    private byte[] firmaTSA;

    public RespuestaTimestamp(String selloTemporal, byte[] firmaTSA){
        this.selloTemporal = selloTemporal;
        this.firmaTSA = firmaTSA;
    }

    public String getSelloTemporal() {
        return selloTemporal;
    }

    public byte[] getFirmaTSA() {
        return firmaTSA;
    }
}
