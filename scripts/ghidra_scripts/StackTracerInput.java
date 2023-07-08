import com.google.common.base.Objects;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.Varnode;

public class StackTracerInput {
    private Address address;
    private Varnode varnode;
    private Utility utility;

    public StackTracerInput(Address address, Varnode varnode) {
        this.address = address;
        this.varnode = varnode;
        this.utility = Utility.getInstance();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StackTracerInput that = (StackTracerInput) o;
        return Objects.equal(address, that.address)
                && utility.varnodeEquals(varnode, that.varnode);
    }

}
