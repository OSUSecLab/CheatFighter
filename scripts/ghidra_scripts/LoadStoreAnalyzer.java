import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class LoadStoreAnalyzer {
    private Utility utility;
    private BackTracer backTracer;
    private DecompilerHelper decompilerHelper;
    private StackVariableTracer stackVariableTracer;
    private Program program;

    public LoadStoreAnalyzer(Program program, BackTracer backTracer, StackVariableTracer stackVariableTracer, DecompilerHelper decompilerHelper) {
        this.utility = Utility.getInstance();
        this.backTracer = backTracer;
        this.decompilerHelper = decompilerHelper;
        this.stackVariableTracer = stackVariableTracer;
        this.program = program;
    }

    public Varnode analyze(PcodeOp loadStorePCode) {
        verifyInputs(program, loadStorePCode);
        Address targetAddress = loadStorePCode.getSeqnum().getTarget();
        if (targetAddress.getOffset() == 0x00101450 || targetAddress.getOffset() == 0x00101424) {
            System.out.println("checkpoint");
        }
        Function function = program.getFunctionManager().getFunctionContaining(targetAddress);
        HighFunction highFunction = decompilerHelper.decompile(function);
        Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps(targetAddress);
        Varnode result = null;
        int size = loadStorePCode.getOpcode() == PcodeOp.LOAD ? loadStorePCode.getOutput().getSize() : loadStorePCode.getInput(2).getSize();
        /**
         * Get ram storage from high function
         */
        while (pcodeOps != null && pcodeOps.hasNext() && result == null) {
            PcodeOpAST pcodeOpAST = pcodeOps.next();
            PcodeOp def = null;
            Varnode target = null;
            if (loadStorePCode.getOpcode() == PcodeOp.STORE && pcodeOpAST.getOpcode() == loadStorePCode.getOpcode()) {
                target = pcodeOpAST.getInput(1);
                def = target.getDef();
                target = new Varnode(target.getAddress(), target.getSize());
            } else if (loadStorePCode.getOpcode() == PcodeOpAST.LOAD) {
                target = loadStorePCode.getOutput();
                def = pcodeOpAST;
            }
            if (def != null && target != null) {
                switch (def.getOpcode()) {
                    case PcodeOp.COPY:
                    case PcodeOp.CAST:
                        Varnode output = def.getOutput();
                        output = new Varnode(output.getAddress(), output.getSize());
                        if (target.equals(output)) {
                            result = def.getInput(0);
                            Tracker.pointerTracked();
                        }
                        break;
                    default:
//                        System.out.println("Could not get result from pcode ast for load store for: " + def.getMnemonic());
                }
            }
        }

        if (result == null || result.isUnique()) {
            List<Varnode> varnodes = new ArrayList<>();
            List<String> backtrace = backTracer.backtrace(targetAddress,
                    loadStorePCode.getSeqnum().getTime() - 1,
                    loadStorePCode.getInput(1),
                    varnodes);
            if (varnodes.isEmpty() && backtrace.isEmpty()) {
                throw new RuntimeException("could not load/store analyze");
            }
            boolean hasRamAddress = varnodes.stream().anyMatch(v -> v.getAddress().isMemoryAddress());
            boolean hasStack = varnodes.stream().anyMatch(v -> v.getAddress().isStackAddress());

            if (!hasRamAddress && hasStack && varnodes.size() == 1) {
                return varnodes.get(0);
            }
            if (hasStack) {
                for (Varnode varnode : varnodes) {
                    if (varnode.getAddress().isStackAddress()) {
                        List<Varnode> stackVariableValues = stackVariableTracer.getStackVariableValues(targetAddress, varnode);
                        backtrace = stackVariableTracer.replaceValueInOperation(backtrace, varnode, stackVariableValues);
                    }
                }
            }
            List<Varnode> resultList = new ArrayList<>();
            stackVariableTracer.addStackValueToResult(resultList, backtrace);
            if (resultList.isEmpty()) {
                throw new RuntimeException("could not analyze load/store");
            } else if (resultList.size() == 1) {
                return resultList.get(0);
            } else {
                Varnode offset = resultList.stream().filter(Varnode::isConstant).findAny().orElse(null);
                Varnode base = resultList.stream().filter(Varnode::isAddress).findAny().orElse(null);
                Data data = program.getListing().getDataAt(base.getAddress());
                if (data != null) {
                    if (data.isPointer()) {
                        Address dataAddress = program.getAddressFactory().getAddress("ram:0x" + data.getValue().toString());
                        data = program.getListing().getDefinedDataAt(dataAddress);
                    }
                    if (data.isArray()) {
                        Data arrayValue = null;
                        if (offset != null) {
                            arrayValue = data.getComponent((int) offset.getOffset());
                        } else {
                            arrayValue = data.getComponent(0);
                        }
                        if (arrayValue == null) {
//                            System.out.println("checkpoint");
                        }
                        result = new Varnode(arrayValue.getAddress(), program.getDefaultPointerSize());
                        return result;
                    }
                }
                return base;
            }

        }


        return result;
    }

    private void verifyInputs(Program program, PcodeOp pcodeOp) {
        if (program == null) {
            throw new RuntimeException("Program can not be null for analyzing load/store");
        }
        if (pcodeOp == null) {
            throw new RuntimeException("PCodeOp null for analyzing load/store");
        }
        if (pcodeOp.getOpcode() != PcodeOp.LOAD && pcodeOp.getOpcode() != PcodeOp.STORE) {
            throw new RuntimeException("Load Store analyzer called for operation other than load/store");
        }
    }

}
