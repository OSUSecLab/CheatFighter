//
// @category Cheat
// @author Md Sakib Anwar
//


import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class LoadStoreAnalyzerScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Utility utility = Utility.getInstance(currentProgram);
        Tracker tracker = Tracker.getInstance(currentProgram);
        DecompilerHelper decompilerHelper = DecompilerHelper.getInstance(currentProgram, getMonitor());
        LoadStoreAnalyzer loadStoreAnalyzer = new LoadStoreAnalyzer(currentProgram, new BackTracer(currentProgram, decompilerHelper), new StackVariableTracer(currentProgram, decompilerHelper), decompilerHelper);
        Address address = currentAddress;
        if (address == null) {
            address = askAddress("Load/Store Location", "Enter the address of load/store operation");
        }
        PcodeOp[] pcodeOps = getInstructionAt(address).getPcode();
        for (PcodeOp pcodeOp : pcodeOps) {
            if (pcodeOp.getOpcode() == PcodeOp.LOAD || pcodeOp.getOpcode() == PcodeOp.STORE) {
                Varnode analyze = loadStoreAnalyzer.analyze(pcodeOp);
                if (analyze == null) {
                    printerr("Could not analyze load/store at address: " + address.toString());
                } else {
                    println("Result: " + analyze.toString());
                }
            }
        }
    }
}
