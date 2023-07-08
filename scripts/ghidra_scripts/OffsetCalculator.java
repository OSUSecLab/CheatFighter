import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.*;

public class OffsetCalculator {
    private Program program;
    private BackTracer backTracer;
    private StackVariableTracer stackVariableTracer;
    private DecompilerHelper decompilerHelper;
    private Utility utility;
    private Map<Data, List<Varnode>> globalToValues;

    public OffsetCalculator(Program program, BackTracer backTracer, StackVariableTracer stackVariableTracer, DecompilerHelper decompilerHelper) {
        this.program = program;
        this.backTracer = backTracer;
        this.stackVariableTracer = stackVariableTracer;
        this.decompilerHelper = decompilerHelper;
        this.utility = Utility.getInstance();
        this.globalToValues = new HashMap<>();
    }

    public void setGlobalToValues(Map<Data, List<Varnode>> globalToValues) {
        this.globalToValues = globalToValues;
    }

    public List<Varnode> getOffsets(PcodeOp offsetCalculatingPCode, Varnode baseVarnode, Node base) {
        if (offsetCalculatingPCode.getSeqnum().getTarget().getOffset() == 0x0010143c) {
//            System.out.println("checkpoint");
        }
        Varnode output = offsetCalculatingPCode.getOutput();
        Address address = offsetCalculatingPCode.getSeqnum().getTarget();

        Function currentFunction = program.getFunctionManager().getFunctionContaining(address);
        HighFunction decompile = decompilerHelper.decompile(currentFunction);
        Iterator<PcodeOpAST> pcodeOps = decompile.getPcodeOps();
        List<Varnode> results = new ArrayList<>();
        /**
         * Try to get the offset from pcode ast first since complex structures are joined together to give easy pcode
         * such as base + 0x802473 will be divided into several steps in raw pcode such as x = higherBytesBase + 0x800000
         * x + 0x2473
         */
        while (pcodeOps != null && pcodeOps.hasNext()) {
            PcodeOpAST next = pcodeOps.next();
            if (next.getOpcode() == offsetCalculatingPCode.getOpcode()
                    && next.getOutput().getAddress().equals(output.getAddress())
                    && next.getOutput().getSize() == output.getSize()
                    && next.getSeqnum().getTarget().equals(address)) {
                if (next.getInput(0).isConstant()) {
                    results.add(next.getInput(0));
                    return results;
                } else if (next.getInput(1).isConstant()) {
                    results.add(next.getInput(1));
                    return results;
                }
            }
        }
        /**
         * If not found from pcode ast in most cases there is a stack variable involved
         * so we backtrace the offset varnode and call stack variable tracer if one of the result from backtracing is
         * a stack variable
         * the backtracer can return something as : [stack[-0x8], const:0x24]
         * this means the offset is stack[-0x8] + 0x24, we use stack variable tracer to find the initial value of stack[-0x8]
         */
        if (results.isEmpty()) {
            Varnode offset = utility.varnodeEquals(offsetCalculatingPCode.getInput(0), baseVarnode) ?
                    offsetCalculatingPCode.getInput(1) : offsetCalculatingPCode.getInput(0);
            List<Varnode> backtrace = new ArrayList<>();
            List<String> operations = backTracer.backtrace(address, offsetCalculatingPCode.getSeqnum().getTime(), offset, backtrace);
            for (Varnode varnode : backtrace) {
                if (varnode.getAddress().isStackAddress()) {
                    HighSymbol symbol = getSymbol(varnode);
                    if (symbol != null && symbol.isParameter()) {
                        int categoryIndex = symbol.getCategoryIndex();
                        results = getParameterizedOffsets(base, currentFunction, currentFunction.getParameter(categoryIndex).getFirstStorageVarnode());
                        return results;
                    } else {
                        List<Varnode> stackVariableValues = stackVariableTracer.getStackVariableValues(address, varnode);
                        if (stackVariableValues.size() == 1 && stackVariableValues.get(0).isRegister()) {
                            results = getParameterizedOffsets(base, currentFunction, stackVariableValues.get(0));
                            return results;
                        } else if (stackVariableValues.stream().anyMatch(varnode1 -> !varnode1.isConstant())) {
                            return results;
                        } else {
                            operations = stackVariableTracer.replaceValueInOperation(operations, varnode, stackVariableValues);
                        }
                    }
                }
            }
            stackVariableTracer.addStackValueToResult(results, operations);
        }

        List<Varnode> toBeRemoved = new ArrayList<>();
        List<Varnode> toBeAdded = new ArrayList<>();
        for (Varnode result : results) {
            if (!result.isConstant()) {
                toBeRemoved.add(result);
                Data data = program.getListing().getDefinedDataContaining(result.getAddress());
                while (data != null && data.isPointer()) {
                    Address dataAddress = program.getAddressFactory().getAddress("ram:0x" + data.getValue().toString());
                    if (dataAddress == null) {
                        break;
                    } else {
                        data = program.getListing().getDefinedDataAt(dataAddress);
                    }
                }
                if (data == null) {
                    throw new RuntimeException("Could not get data at " + result.getAddress());
                } else if (data.hasStringValue()) {
                    continue;
                } else if (globalToValues.containsKey(data)) {
                    toBeAdded.addAll(globalToValues.get(data));
                } else {
                    ReferenceIterator referenceIteratorTo = data.getReferenceIteratorTo();
                    while (referenceIteratorTo != null && referenceIteratorTo.hasNext()) {
                        Reference reference = referenceIteratorTo.next();
                        if (reference.getReferenceType().isWrite()) {
                            Varnode storage = getStorageReference(reference.getFromAddress());
                            List<Varnode> storageResult = new ArrayList<>();
                            backTracer.backtrace(reference.getFromAddress(), storage, storageResult);
                            for (Varnode s : storageResult) {
                                if (s.getAddress().isStackAddress()) {
                                    List<Varnode> stackVariableValues = stackVariableTracer.getStackVariableValues(reference.getFromAddress(), s);
                                    toBeAdded.addAll(stackVariableValues);
                                } else {
                                    toBeAdded.add(s);
                                }
                            }
                        }
                    }
                    if (toBeAdded.isEmpty()) {
                        System.out.println("checkpoint");
                        toBeAdded.add(new Varnode(program.getAddressFactory().getConstantAddress(Long.decode(data.getValue().toString())), program.getDefaultPointerSize()));
                    }
                    globalToValues.put(data, toBeAdded);
                }
            }
        }
        results.removeAll(toBeRemoved);
        results.addAll(toBeAdded);

        if (results.isEmpty()) {
            throw new RuntimeException("No offset found!!!!!!!!!!!!!!!! for address: " + address);
        }
        return results;
    }

    private Varnode getStorageReference(Address fromAddress) {
        if (fromAddress == null) {
            throw new RuntimeException("from address can not be null for getting storage reference");
        }
        Instruction instructionAt = program.getListing().getInstructionAt(fromAddress);
        if (instructionAt != null) {
            PcodeOp[] pcodes = instructionAt.getPcode();
            for (PcodeOp pcode : pcodes) {
                if (pcode.getOpcode() == PcodeOp.STORE) {
                    return pcode.getInput(2);
                }
            }
        }
        throw new RuntimeException("could not get storage reference");
    }

    private List<Varnode> getParameterizedOffsets(Node base, Function currentFunction, Varnode target) {
        Address entryPoint = currentFunction.getEntryPoint();
        ReferenceIterator referencesTo = program.getReferenceManager().getReferencesTo(entryPoint);
        List<Varnode> backtracingResult = new ArrayList<>();
        List<String> backtrace = new ArrayList<>();
        for (Reference reference : referencesTo) {
            Address fromAddress = reference.getFromAddress();
            if (base.contains(fromAddress)) {
                Instruction instructionBefore = program.getListing().getInstructionBefore(fromAddress);
                if (instructionBefore != null) {
                    backtrace = backTracer.backtrace(instructionBefore.getAddress(), target, backtracingResult);
                }
            }
        }
        List<Varnode> result = new ArrayList<>();
        if (backtrace != null && !backtrace.isEmpty()) {
            stackVariableTracer.addStackValueToResult(result, backtrace);
        }
        return result;
    }

    private HighSymbol getSymbol(Varnode varnode) {
        if (varnode.getHigh() != null && varnode.getHigh().getSymbol() != null) {
            return varnode.getHigh().getSymbol();
        }
        return null;
    }
}
