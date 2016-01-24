import java.io.Serializable;

public class PeticionTimestamp implements Serializable{

    private byte[] hashDoc;

    public PeticionTimestamp(byte[] hashDoc){
        this.hashDoc = hashDoc;
    }

    public byte[] getHashDoc() {
        return hashDoc;
    }
}
