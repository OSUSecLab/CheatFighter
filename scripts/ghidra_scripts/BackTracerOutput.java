import ghidra.program.model.pcode.Varnode;

import java.util.List;

public class BackTracerOutput {
    private List<Varnode> result;
    private List<String> operations;

    public BackTracerOutput(List<Varnode> result, List<String> operations) {
        this.result = result;
        this.operations = operations;
    }

    public List<Varnode> getResult() {
        return result;
    }

    public List<String> getOperations() {
        return operations;
    }
}
