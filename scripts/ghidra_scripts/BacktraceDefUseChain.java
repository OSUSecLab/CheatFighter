import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.ArrayList;
import java.util.Iterator;

public class BacktraceDefUseChain {
    private DecompilerHelper decompilerHelper;
    private Program program;
    private Utility utility;
    private boolean initialized = false;

    public void init(Program program, DecompilerHelper decompilerHelper) {
        this.utility = Utility.getInstance();
        this.program = program;
        this.decompilerHelper = decompilerHelper;
        initialized = true;
    }

    public ArrayList<Node> backtrace(Node node, Address startingAddress) {
        if (!initialized) {
            throw new RuntimeException("Backtrace not initialized");
        }
        if (startingAddress.getOffset() == 0x000110f6) {
//            System.out.println("checkpoint");
        }
        ArrayList<Node> result = new ArrayList<>();
        Varnode varnode = node.getVarnode();
        if (startingAddress != null) {
            node.addFirst(startingAddress);
        }
        if (varnode.isConstant()) {
            node.addFirst(varnode.getAddress());
            result.add(node);
            Tracker.pointerTracked();
            return result;
        }

        if (utility.isInput(varnode)) {
            Address funcEntryPoint = utility.getFunctionEntry(varnode);
            Integer parameterNumber = utility.getFunctionParameterIndex(varnode);

            ReferenceIterator references = program.getReferenceManager().getReferencesTo(funcEntryPoint);
            while (references != null && references.hasNext()) {
                Reference r = references.next();
                if (r.getReferenceType().isCall()) {
                    Function functionContaining = program.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    if (functionContaining != null) {
                        PcodeOpAST callSitePCodeAST = utility.getCallPCodeAST(
                                decompile(functionContaining),
                                r.getFromAddress());
                        Varnode param = callSitePCodeAST.getInput(parameterNumber + 1);
                        if (param == null) {
                            continue;
                        }
                        Node previousNode = new Node(param, node);
                        result.addAll(backtrace(previousNode, r.getFromAddress()));
                    }
                }
            }
            Tracker.pointerTracked();
            return result;
        }

        PcodeOp def = varnode.getDef();
        if (def == null) {
            result.add(new Node(varnode, node));
            return result;
        }
        Tracker.addPCodeTracked();
        while (def.getOpcode() == PcodeOp.INDIRECT) {
            Address instrAddr = def.getSeqnum().getTarget();
            SequenceNumber sequenceNumber = new SequenceNumber(instrAddr, (int) def.getInput(1).getOffset());
            HighFunction highFunction = decompilerHelper.decompile(program.getFunctionManager().getFunctionContaining(instrAddr));
            def = highFunction.getPcodeOp(sequenceNumber);
        }

        Varnode input = null;
        switch (def.getOpcode()) {
            case PcodeOp.PTRSUB:
            case PcodeOp.PTRADD:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.CAST:
            case PcodeOp.COPY:
            case PcodeOp.SUBPIECE:
            case PcodeOp.INT_SEXT:
            case PcodeOp.INT_LEFT:
                input = def.getInput(0);
                break;
            case PcodeOp.LOAD:
                input = def.getInput(1);
                break;
            case PcodeOp.CALL:
                result = handleBacktraceCalls(node, def);
                return result;
            case PcodeOp.MULTIEQUAL:
                Varnode v1 = def.getInput(0);
                Varnode v2 = def.getInput(0);
                if (utility.varnodeEquals(v1, varnode) && utility.varnodeEquals(v2, varnode)) {
                    return result;
                } else if (utility.varnodeEquals(v1, varnode)) {
                    return backtrace(new Node(v2, node), def.getSeqnum().getTarget());
                } else {
                    return backtrace(new Node(v1, node), def.getSeqnum().getTarget());
                }
                /*if (utility.varnodeEquals(v2, varnode))
                else {
                    throw new RuntimeException("MULTIEQUAL Problem");
                }*/

            case PcodeOp.INT_ADD:
                Varnode op1 = def.getInput(0);
                Varnode op2 = def.getInput(1);
                if (op1.isAddress() || op2.isAddress()) {
                    Varnode address, offset;
                    address = op1.isAddress() ? op1 : op2;
                    offset = op2.isAddress() ? op1 : op2;
                    if (!offset.isConstant()) {
                        ArrayList<Node> backtrace = backtrace(new Node(offset, program), def.getSeqnum().getTarget());
                        long l = 0x0;
                        for (Node n : backtrace) {
                            if (n.getVarnode().isConstant()) {
                                l += n.getVarnode().getOffset();
                            } else if (n.getVarnode().isAddress()) {
                                Data dataAt = program.getListing().getDataAt(n.getVarnode().getAddress());
                                while (dataAt.isPointer()) {
                                    dataAt = program.getListing().getDataAt(program.getAddressFactory().getAddress("ram:" + dataAt.getValue().toString()));
                                }
                                l += Long.decode(dataAt.getValue().toString());
                            }
                        }
                        offset = new Varnode(program.getAddressFactory().getConstantAddress(l), offset.getSize());
                    }
                    Data data = program.getListing().getDataAt(address.getAddress());
                    data = data == null ? program.getListing().getDefinedDataAt(address.getAddress()) : data;
                    if (data == null) {
                        throw new RuntimeException("Could not get data for backtrace calculation");
                    }
                    long l = Long.decode(data.getValue().toString()) + offset.getOffset();
                    Varnode constantVarnode = new Varnode(program.getAddressFactory().getConstantAddress(l), op1.getSize());
                    result.addAll(backtrace(new Node(constantVarnode, node), def.getSeqnum().getTarget()));
//                    System.out.println("checkpoint");
                } else if (op1.isConstant() || op2.isConstant()) {
                    Varnode offset = op1.isConstant() ? op1 : op2;
                    Varnode theOtherOne = op1.isConstant() ? op2 : op1;
                    if (!theOtherOne.isConstant()) theOtherOne = getSingleBacktrace(theOtherOne, startingAddress);
                    if (theOtherOne != null) {
                        if (theOtherOne.isConstant()) {
                            Varnode r = new Varnode(program.getAddressFactory().getConstantAddress(offset.getOffset() + theOtherOne.getOffset()), theOtherOne.getSize());
                            result.add(new Node(r, node));
                            return result;
                        } else {
                            if (theOtherOne.isAddress()) {
                                Data data = program.getListing().getDefinedDataAt(theOtherOne.getAddress());
                                while (data.isPointer()) {
                                    data = program.getListing().getDefinedDataAt(program.getAddressFactory().getAddress("ram:" + data.getValue().toString()));
                                }
                                Varnode r = new Varnode(program.getAddressFactory().getConstantAddress(offset.getOffset() + Long.decode(data.getValue().toString())), offset.getSize());
                                result.add(new Node(r, node));
                                return result;
                            }
                        }
                    }
                } else {
                    result.addAll(backtrace(new Node(def.getInput(0), node), def.getSeqnum().getTarget()));
                    result.addAll(backtrace(new Node(def.getInput(1), node), def.getSeqnum().getTarget()));
                }
                return result;
            default:
                throw new RuntimeException("Need to handle P CODE for backtrace " + def.getMnemonic());
        }

        // local variable
        // defined in the format a = sp + offset
        // if input is stack pointer we know that this is a local variable we can stop backtrace
        if (utility.isStackPointer(input)) {
            Varnode output = getStackStorage(def);
            result.add(new Node(output, node));
            return result;
        }
        // global variable
        else if (utility.isGlobal(input)) {
            result.add(new Node(input, node));
            return result;
        }
        // we did not reach the root yet
        return backtrace(new Node(input, node), def.getSeqnum().getTarget());
    }

    private Varnode getSingleBacktrace(Varnode input, Address address) {
        ArrayList<Node> backtrace = backtrace(new Node(input, program), address);
        if (backtrace == null || backtrace.size() != 1) {
            return null;
        } else {
            return backtrace.get(0).getVarnode();
        }
    }

    private ArrayList<Node> handleBacktraceCalls(Node node, PcodeOp pCodeOP) {
        Address callSite = pCodeOP.getSeqnum().getTarget();
        Address calledFunctionAddress = pCodeOP.getInput(0).getAddress();

        Function calleeFunction = program.getFunctionManager().getFunctionContaining(callSite);
        Function calledFunction = program.getFunctionManager().getFunctionAt(calledFunctionAddress);

        HighFunction calleeHighFunction = decompile(calleeFunction);
        HighFunction calledHighFunction = decompile(calledFunction);
        PcodeOpAST callPCodeAST = utility.getCallPCodeAST(calleeHighFunction, callSite);

        // check if system call or user defined function call

        // system calls
        ArrayList<Node> result = new ArrayList<>();
        Varnode output;
        if (calledFunction.isThunk()) {
            switch (calledFunction.getName()) {
                // system calls that do not flow to output
                case "snprintf":
                case "fgets":
                    output = callPCodeAST.getInput(3);
                    result.add(new Node(output, node));
                    break;

                // system calls that flow to output
                case "closedir":
                case "atoi":
                case "sprintf":
                case "fopen":
                case "fclose":
                case "strcpy":
                case "open":
                case "strtok":
                case "strtoul":
                case "opendir":
                case "readdir":
                    output = callPCodeAST.getInput(1);
                    result.add(new Node(output, node));
                    break;

                // system calls that do not contribute to flow of the data
                case "strcmp":
                case "strstr":
                case "strncmp":
                    break;

                default:
                    try {
                        InputOutputMapping inputOutputMapping = InputOutputMapping.valueOf(calledFunction.getName());
                        if (inputOutputMapping.isDataFlowing()) {
                            Integer singleInput = inputOutputMapping.getSingleInput();
                            Varnode input = callPCodeAST.getInput(singleInput + 1);
                            if (input.isUnique())
                                result.addAll(backtrace(new Node(input, node), callSite));
                        } else {
                            return result;
                        }
                    } catch (Exception e) {
                        throw new RuntimeException("Not handled for " + calledFunction.getName());
                    }
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
                Varnode input = returnPCodeOpAst.getInput(1);
                if (input != null) {
                    result = backtrace(new Node(input, node), returnPCodeOpAst.getSeqnum().getTarget());
                }
            }
        }
        return result;
    }

    private HighFunction decompile(Function function) {
        if (function == null) {
            throw new RuntimeException("Function can not be null for decompiling");
        }
        return decompilerHelper.decompile(function);
    }


    private Varnode getStackStorage(PcodeOp pcodeOp) {
        Varnode offset = pcodeOp.getInput(1);
        if (offset instanceof VarnodeAST) {
            HighVariable high = offset.getHigh();
            if (high.getSymbol() != null && high.getSymbol().getStorage() != null && high.getSymbol().getStorage().getFirstVarnode() != null) {
                Varnode firstVarnode = high.getSymbol().getStorage().getFirstVarnode();
                if (utility.toHexString(firstVarnode.getOffset()).startsWith("0xf")) {
                    return firstVarnode;
                }
            }
        }
        Address target = pcodeOp.getSeqnum().getTarget();
        Function function = program.getFunctionManager().getFunctionContaining(target);
        HighFunction decompile = decompile(function);
        LocalSymbolMap localSymbolMap = decompile.getLocalSymbolMap();
        PcodeOp[] pcodes = program.getListing().getInstructionAt(target).getPcode();
        Varnode input = offset.isConstant() ? offset : null;
        if (input == null) {
            for (PcodeOp pcode : pcodes) {
                if (pcode.getOpcode() == PcodeOp.COPY) {
                    input = pcode.getInput(0);
                    break;
                }
            }
        }
        if (input == null) {
            return null;
        }
        long offsetLong = input.getOffset() - function.getStackFrame().getFrameSize();
        Address address = program.getAddressFactory().getStackSpace().getAddress(offsetLong);
        if (address == null) {
            return null;
        }
        HighSymbol local = localSymbolMap.findLocal(address, null);
        if (local == null) {
            return new Varnode(address, pcodeOp.getOutput().getSize());
        }
        return local.getStorage().getFirstVarnode();

    }

}
