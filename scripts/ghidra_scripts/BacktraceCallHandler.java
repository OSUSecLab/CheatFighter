import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Iterator;

public class BacktraceCallHandler {
    private Program program;
    private DecompilerHelper decompilerHelper;
    private Utility utility;

    public BacktraceCallHandler(Program program, DecompilerHelper decompilerHelper) {
        this.program = program;
        this.decompilerHelper = decompilerHelper;
        this.utility = Utility.getInstance();
    }

    public Pair<Varnode, Address> handleBacktraceCalls(Varnode target, PcodeOp pCodeOP) {
        Address callSite = pCodeOP.getSeqnum().getTarget();
        Address calledFunctionAddress = pCodeOP.getInput(0).getAddress();

        Function calleeFunction = program.getFunctionManager().getFunctionContaining(callSite);
        Function calledFunction = program.getFunctionManager().getFunctionAt(calledFunctionAddress);

        if (calleeFunction == null || calledFunction == null) {
            return null;
        }

        HighFunction calleeHighFunction = decompilerHelper.decompile(calleeFunction);
        HighFunction calledHighFunction = decompilerHelper.decompile(calledFunction);
        PcodeOpAST callPCodeAST = utility.getCallPCodeAST(calleeHighFunction, callSite);

        // check if system call or user defined function call

        // system calls
        Varnode output, input;
        Parameter outputParameter, inputParameter;
        Pair<Varnode, Address> result = null;
        if (calledFunction.isThunk()) {
            switch (calledFunction.getName()) {
                // system calls that do not flow to output
                case "snprintf":
                case "fgets":
                case "pread64":
                    inputParameter = calledFunction.getParameter(0);
                    input = inputParameter.getFirstStorageVarnode();
                    if (utility.varnodeEquals(input, target)) {
                        output = callPCodeAST.getInput(3);
                        result = new ImmutablePair<>(output, callSite);
                    }
                    break;

                // system calls that flow to output
                case "closedir":
                case "atoi":
                case "sprintf":
                case "fopen":
                case "fclose":
                case "open":
                case "strtok":
                case "strtoul":
                case "opendir":
                case "readdir":
                case "strlen":
                case "strcpy":
                case "sscanf":
                    input = callPCodeAST.getOutput();
                    if (utility.varnodeEquals(input, target)) {
                        outputParameter = calledFunction.getParameter(0);
                        output = outputParameter.getFirstStorageVarnode();
                        result = new ImmutablePair<>(output, callSite);
                    }
                    break;


                case "fscanf":
                    inputParameter = calledFunction.getParameter(1);
                    input = inputParameter.getFirstStorageVarnode();
                    if (utility.varnodeEquals(input, target)) {
                        output = calledFunction.getParameter(0).getFirstStorageVarnode();
                        result = new ImmutablePair<>(output, callSite);
                    }
                    break;


                case "strcmp":
                case "strstr":
                case "strncmp":
                case "calloc":
                case "__assert2":
                case "posix_memalign":
                case "__stack_chk_fail":
                    break;

                default:
                    throw new RuntimeException("Not handled for " + calledFunction.getName());
            }
        }

        // user defined functions
        else {
            Iterator<PcodeOpAST> pCodeASTs = calledHighFunction.getPcodeOps();
            PcodeOpAST returnPCodeOpAst = null;
            while (pCodeASTs != null && pCodeASTs.hasNext()) {
                PcodeOpAST next = pCodeASTs.next();
                if (next.getOpcode() == PcodeOp.RETURN) {
                    returnPCodeOpAst = next;
                }
            }
            if (returnPCodeOpAst != null) {
                input = returnPCodeOpAst.getInput(1);
                result = new ImmutablePair<>(input, returnPCodeOpAst.getSeqnum().getTarget());
//                result = backtrace(new Node(input, node.getBacktrace()), returnPCodeOpAst.getSeqnum().getTarget());
            }
        }
        return result;
    }
}
