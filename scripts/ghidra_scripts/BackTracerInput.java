import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.Varnode;

public class BackTracerInput {
    private Address startingAddress;
    private Integer sequenceNumber;
    private Varnode target;
    private Utility utility;

    public BackTracerInput(Address startingAddress, int sequenceNumber, Varnode target) {
        this.startingAddress = startingAddress;
        this.sequenceNumber = sequenceNumber;
        this.target = target;
        this.utility = Utility.getInstance();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BackTracerInput that = (BackTracerInput) o;
        return sequenceNumber.equals(that.sequenceNumber) && startingAddress.equals(that.startingAddress) && utility.varnodeEquals(target, that.target);
    }
}
