import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

import static ghidra.program.model.pcode.PcodeOp.*;

public class BackTracer {
    private Utility utility;
    private DecompilerHelper decompilerHelper;
    private Stack<Address> callTrace;
    private BacktraceCallHandler backtraceCallHandler;
    private Program program;
    private Map<BackTracerInput, BackTracerOutput> backtraced;
    private List<Address> backtracedAddresses;
    private Varnode lastTarget;
    private Address originalStartingAddress;

    public BackTracer(Program program, DecompilerHelper decompilerHelper) {
        this.utility = Utility.getInstance();
        this.program = program;
        this.callTrace = new Stack<>();
        this.decompilerHelper = decompilerHelper;
        this.backtraceCallHandler = new BacktraceCallHandler(program, decompilerHelper);
        this.backtraced = new HashMap<>();
    }

    public Varnode getLastTarget() {
        return lastTarget;
    }

    public List<String> backtrace(Address startingAddress,
                                  Varnode target,
                                  List<Varnode> result) {
        verifyInputs(program, startingAddress, target, result);
        originalStartingAddress = startingAddress;
        Instruction instructionAt = program.getListing().getInstructionAt(startingAddress);
        PcodeOp[] pcode = instructionAt.getPcode();
        List<String> operations = new ArrayList<>();
        backtracedAddresses = new ArrayList<>();
        backtrace(startingAddress, pcode.length - 1, target, result, operations);
        return operations;
    }

    /**
     * Backtracer traces the target varnode till it gets either a constant or a stack variable
     * It stores the backtracing result in the parameter result and return the sequence of operations that were done to
     * get to the target finally. For example: we are tracing x0 register, x0 can be defined as:
     * x0 = 0x84 + 0x25 + (((0x24 << 0x4) / 0x2) - stack[-0x8])
     * the returning will contain all of the operations : INT_ADD, INT_ADD, 0x84, 0x25, INT_ADD, INT_SUB, INT_DIV, INT_LEFT, 0x24, 0x4, 0x24, stack[-0x8]
     * where as the result will contain just the varnodes of the operations: [(const,0x84,8)....]
     *
     * @param startingAddress
     * @param sequenceNumber
     * @param target
     * @param result
     * @return
     */
    public List<String> backtrace(Address startingAddress,
                                  int sequenceNumber,
                                  Varnode target,
                                  List<Varnode> result) {
        verifyInputs(program, startingAddress, target, result);
        originalStartingAddress = startingAddress;
        List<String> operations = new ArrayList<>();
        backtracedAddresses = new ArrayList<>();
        backtrace(startingAddress, sequenceNumber, target, result, operations);
        return operations;
    }

    private List<String> backtrace(Address startingAddress,
                                   Varnode target,
                                   List<Varnode> result,
                                   List<String> operations) {
        Instruction instructionAt = program.getListing().getInstructionAt(startingAddress);
        PcodeOp[] pcode = instructionAt.getPcode();
        backtrace(startingAddress, pcode.length - 1, target, result, operations);
        return operations;
    }

    private void backtrace(Address startingAddress,
                           int sequenceNumber,
                           Varnode target,
                           List<Varnode> result,
                           List<String> operations) {
        verifyInputs(program, startingAddress, target, result);
        if (startingAddress.getOffset() == 0x0010134c) {
//            System.out.println("checkpoint");
        }

        BackTracerInput input = new BackTracerInput(startingAddress, sequenceNumber, target);
        BackTracerOutput output;
        List<Varnode> localResult = new ArrayList<>();
        List<String> localOperations = new ArrayList<>();
        Address entryPoint = program.getFunctionManager().getFunctionContaining(startingAddress).getEntryPoint();

        for (Map.Entry<BackTracerInput, BackTracerOutput> backtracedEntry : backtraced.entrySet()) {
            if (backtracedEntry.getKey().equals(input)) {
                result.addAll(backtracedEntry.getValue().getResult());
                operations.addAll(backtracedEntry.getValue().getOperations());
                return;
            }
        }

        /**
         * if varnode is constant we have reached the end
         */

        Instruction instruction = null;
        while (true) {
            lastTarget = target;
            if (target.isConstant()) {
                localResult.add(target);
                localOperations.add(String.valueOf(target.getOffset()));
                addLocalToFinal(localOperations, operations, localResult, result);
                output = new BackTracerOutput(localResult, localOperations);
                backtraced.put(input, output);
                return;
            }

            if (sequenceNumber < 0) {
                instruction = program.getListing().getInstructionBefore(startingAddress);
                startingAddress = instruction.getAddress();
                sequenceNumber = instruction != null ? instruction.getPcode().length - 1 : 0;
            } else {
                instruction = program.getListing().getInstructionAt(startingAddress);
            }
            Tracker.baddressTracked(startingAddress);

            Instruction previous = instruction.getPrevious();
            Varnode latestOffset = null, op1, op2, otherOperand, temp = target;
            PcodeOp[] pcodes = instruction.getPcode();
            for (int i = sequenceNumber; i >= 0; i--) {
                PcodeOp pcode = pcodes[i];
                switch (pcode.getOpcode()) {

                    case COPY:
                    case INT_NEGATE:
                        op1 = pcode.getInput(0);
                        if (utility.varnodeEquals(temp, pcode.getOutput())) {
                            if (utility.isStackPointer(op1)) {
                                Varnode stackStorage = getStackStorage(latestOffset, pcode.getSeqnum().getTarget(), temp.getSize(), pcodes.length - 1);
                                localResult.add(stackStorage);
                                localResult.remove(latestOffset);
                                if (localOperations.size() > 1) {
                                    localOperations = localOperations.subList(0, localOperations.size() - 2);
                                }
                                addLocalToFinal(localOperations, operations, localResult, result);
                                output = new BackTracerOutput(localResult, localOperations);
                                backtraced.put(input, output);
                                Tracker.pointerTracked();
                                return;
                            } else {
                                temp = op1;
                            }
                        }
                        break;

                    case CALL:
                        if (!target.getAddress().isStackAddress()) {
                            Pair<Varnode, Address> varnodeAddressPair = backtraceCallHandler.handleBacktraceCalls(temp, pcode);
                            if (varnodeAddressPair != null) {
                                Instruction returnInstruction = program.getListing().getInstructionBefore(varnodeAddressPair.getValue());
                                if (returnInstruction != null && previous != null && !previous.getAddress().equals(returnInstruction.getAddress())) {
                                    Set<Varnode> stackVariables = removeAllStackVariables(localResult);
                                    callTrace.push(previous.getAddress());
                                    List<Varnode> calledFunctionBacktrace = new ArrayList<>();
                                    backtrace(returnInstruction.getAddress(), target, calledFunctionBacktrace, localOperations);
                                    Set<Varnode> variables = utility.getNonInputStackVariables(calledFunctionBacktrace);
                                    calledFunctionBacktrace.removeAll(variables);
                                    localResult.addAll(calledFunctionBacktrace);
                                    localResult.addAll(stackVariables);
                                } else {
                                    temp = varnodeAddressPair.getKey();
                                }
                            }
                        }
                        break;

                    case INT_ADD:
                        op1 = pcode.getInput(0);
                        if (utility.isStackPointer(op1)) {
                            Varnode stackStorage = getStackStorage(pcode, temp.getSize());
                            if (utility.varnodeEquals(stackStorage, target)) {
                                Pair<Address, Varnode> stackReference = getStackReference(startingAddress, i, pcode.getOutput());
                                if (stackReference != null) {
                                    backtrace(stackReference.getKey(), stackReference.getValue(), localResult, localOperations);
                                    addLocalToFinal(localOperations, operations, localResult, result);
                                    output = new BackTracerOutput(localResult, localOperations);
                                    backtraced.put(input, output);
                                    return;
                                }
                            } else if (utility.varnodeEquals(temp, pcode.getOutput())) {
                                localResult.add(stackStorage);
                                localOperations.add(stackStorage.toString());
                                addLocalToFinal(localOperations, operations, localResult, result);
                                output = new BackTracerOutput(localResult, localOperations);
                                backtraced.put(input, output);
                                Tracker.pointerTracked();
                                return;
                            }
                            break;
                        }
                    case INT_SUB:
                    case INT_AND:
                    case INT_OR:
                    case INT_XOR:
                    case INT_MULT:
                    case INT_SDIV:
                    case FLOAT_MULT:
                    case FLOAT_ADD:
                    case FLOAT_SUB:
                    case FLOAT_DIV:
                        op1 = pcode.getInput(0);
                        op2 = pcode.getInput(1);
                        if (utility.varnodeEquals(temp, pcode.getOutput())) {
                            localOperations.add(pcode.getMnemonic());
                            if (op1.isUnique() && op2.isUnique()) {
                                List<Varnode> op1Result = new ArrayList<>();
                                List<Varnode> op2Result = new ArrayList<>();
                                List<String> op1Operations = backtrace(startingAddress, i - 1, op1, op1Result);
                                List<String> op2Operations = backtrace(startingAddress, i - 1, op2, op2Result);
                                if (op1Result.stream().allMatch(v -> v.isConstant())) {
                                    localResult.addAll(op1Result);
                                    localOperations.addAll(op1Operations);
                                    temp = op2;
                                } else if (op2Result.stream().allMatch(v -> v.isConstant())) {
                                    localResult.addAll(op2Result);
                                    localOperations.addAll(op2Operations);
                                    temp = op1;
                                } else if (op1Result.size() == 1 && op2Result.size() == 1) {
                                    twoRegisterExtraction(startingAddress, result, operations, input, localResult, localOperations, op1Result.get(0), op2Result.get(0), i);
                                    return;
                                } else {
                                    throw new RuntimeException("Both operand unique for addition can not backtrace");
                                }
                            } else if (op1.isConstant() && op2.isConstant()) {
                                localResult.add(op1);
                                localResult.add(op2);
                                localOperations.add(String.valueOf(op1.getOffset()));
                                localOperations.add(String.valueOf(op2.getOffset()));
                            } else if (op1.isConstant() || op2.isConstant()) {
                                temp = op1.isConstant() ? op1 : op2;
                                if (pcode.getOpcode() == PcodeOp.INT_ADD) {
                                    latestOffset = temp;
                                }
                                localResult.add(temp);
                                localOperations.add(String.valueOf(temp.getOffset()));
                                otherOperand = op1.isConstant() ? op2 : op1;
                                if (otherOperand.isUnique()) {
                                    temp = otherOperand;
                                } else {
                                    backtrace(startingAddress, i - 1, otherOperand, localResult, localOperations);
                                    addLocalToFinal(localOperations, operations, localResult, result);
                                    output = new BackTracerOutput(localResult, localOperations);
                                    backtraced.put(input, output);
                                    return;
                                }
                            } else {
                                if (op1.isUnique() || op2.isUnique()) {
                                    temp = op1.isUnique() ? op1 : op2;
                                    otherOperand = op1.isUnique() ? op2 : op1;
                                    backtrace(startingAddress, i - 1, otherOperand, localResult, localOperations);
                                } else if (op1.isRegister() && op2.isRegister()) {
                                    twoRegisterExtraction(startingAddress, result, operations, input, localResult, localOperations, op1, op2, i);
                                    return;
                                } else {
                                    throw new UnsupportedOperationException();
                                }
                            }
                        }
                        break;

                    case INT_LEFT:
                    case INT_2COMP:
                    case FLOAT_NEG:
                    case INT_ZEXT:
                    case INT_SEXT:
                    case SUBPIECE:
                    case INT_SRIGHT:
                    case INT_RIGHT:
                    case FLOAT_FLOAT2FLOAT:
                    case FLOAT_INT2FLOAT:
                        if (utility.varnodeEquals(temp, pcode.getOutput())) {
                            if (pcode.getOpcode() == INT_LEFT) {
                                localOperations.add(pcode.getMnemonic());
                                localOperations.add(String.valueOf(pcode.getInput(1).getOffset()));
                            } else if (pcode.getOpcode() == INT_2COMP) {
                                localOperations.add(pcode.getMnemonic());
                            }
                            temp = pcode.getInput(0);
                        }
                        break;

                    case LOAD:
                        if (utility.varnodeEquals(temp, pcode.getOutput())) {
                            temp = pcode.getInput(1);
                        }
                        break;

                    case STORE:
                        if (utility.varnodeEquals(temp, pcode.getInput(1))) {
                            temp = pcode.getInput(2);
                        }
                        break;

                    /**
                     * If we see a BRANCH or unconditional jump then it means the next address was not accessed by sequential operation
                     * so we find the references to the next instruction address since current instruction is the branch call
                     */
                    case BRANCH:
                        ReferenceIterator referencesTo = program.getReferenceManager().getReferencesTo(instruction.getNext().getAddress());
                        while (referencesTo != null && referencesTo.hasNext()) {
                            Reference next = referencesTo.next();
                            if (next.getReferenceType().isJump() || next.getReferenceType().isConditional()) {
                                Instruction instructionBefore = program.getListing().getInstructionBefore(next.getFromAddress());
                                if (instructionBefore != null
                                        && instructionBefore.getAddress().compareTo(entryPoint) > 0
                                        && !backtracedAddresses.contains(instructionBefore.getAddress())) {
                                    backtracedAddresses.add(instructionBefore.getAddress());
                                    backtrace(instructionBefore.getAddress(), target, localResult, localOperations);
                                }
                            }
                        }
                        return;
                    case CBRANCH:
                        break;

                    case MULTIEQUAL:
                        if (utility.varnodeEquals(temp, pcode.getOutput())) {
                            for (Varnode pcodeInput : pcode.getInputs()) {
                                backtrace(pcode.getSeqnum().getTarget(), pcodeInput, localResult, localOperations);
                            }
                        }
                        break;


                    case RETURN:
                        throw new RuntimeException("At the edge of previous function");
                    default:
                        if (Constants.ignoreList.contains(pcode.getOpcode())) {
                            break;
                        }
                        throw new RuntimeException("Backtrace not handled for " + pcode.getMnemonic());
                }
            }

            if (previous != null) {
                if (previous.getAddress().compareTo(entryPoint) < 0) {
                    removeAllStackVariables(localResult);
                    if (!callTrace.isEmpty()) {
                        startingAddress = callTrace.pop();
                        target = temp;
                    } else {
                        break;
                    }
                } else {
                    startingAddress = previous.getAddress();
                    if (temp != null && !temp.isUnique()) {
                        target = temp;
                    }
                }
                sequenceNumber = program.getListing().getInstructionAt(startingAddress).getPcode().length - 1;
            } else if (previous == null || target.isUnique()) {
                removeAllStackVariables(localResult);
                break;
            }
        }
        addLocalToFinal(localOperations, operations, localResult, result);
        output = new BackTracerOutput(localResult, localOperations);
        backtraced.put(input, output);
    }

    private void twoRegisterExtraction(Address startingAddress, List<Varnode> result, List<String> operations, BackTracerInput input, List<Varnode> localResult, List<String> localOperations, Varnode op1, Varnode op2, int i) {
        BackTracerOutput output;
        backtrace(startingAddress, i - 1, op1, localResult, localOperations);
        backtrace(startingAddress, i - 1, op2, localResult, localOperations);
        addLocalToFinal(localOperations, operations, localResult, result);
        output = new BackTracerOutput(localResult, localOperations);
        backtraced.put(input, output);
        return;
    }

    private void addLocalToFinal(List<String> localOperations, List<String> operations, List<Varnode> localResult, List<Varnode> result) {
        operations.addAll(localOperations);
        result.addAll(localResult);
    }

    private Pair<Address, Varnode> getStackReference(Address address, int sequenceNumber, Varnode target) {
        Pair<Address, Varnode> result = null;
        Instruction ins = program.getListing().getInstructionAt(address);
        int startingPoint = sequenceNumber + 1;
        while (ins != null && ins.getAddress().compareTo(originalStartingAddress) < 0) {
            PcodeOp[] pcodes = ins.getPcode();
            for (int i = startingPoint; i < pcodes.length; i++) {
                PcodeOp pcode = pcodes[i];
                if (pcode.getOpcode() == PcodeOp.STORE && utility.varnodeEquals(pcode.getInput(1), target)) {
                    return new ImmutablePair<>(ins.getAddress(), pcode.getInput(2));
                } else if (pcode.getOpcode() == PcodeOp.COPY && utility.varnodeEquals(pcode.getInput(0), target)) {
                    target = pcode.getOutput();
                }
            }
            if (target.isUnique()) {
                break;
            }
            ins = ins.getNext();
            startingPoint = 0;
        }
        return null;
    }

    private Set<Varnode> removeAllStackVariables(List<Varnode> result) {
        Set<Varnode> stackVariables = utility.getNonInputStackVariables(result);
        result.removeAll(stackVariables);
        return stackVariables;
    }

    private void verifyInputs(Program program, Address address, Varnode target, List<Varnode> result) {
        if (program == null) {
            throw new RuntimeException("Program can not be null for backtracing pcode");
        }
        if (address == null) {
            throw new RuntimeException("Starting Address can not be null for backtracing pcode");
        }
        if (target == null) {
            throw new RuntimeException("Target Varnode can not be null for backtracing pcode");
        }
        if (result == null) {
            throw new RuntimeException("Result can not be null for backtracing pcode");
        }
    }

    private Varnode getStackStorage(PcodeOp pcodeOp, int size) {
        Varnode offset = pcodeOp.getInput(1);
        Address target = pcodeOp.getSeqnum().getTarget();
        return getStackStorage(offset, target, size, pcodeOp.getSeqnum().getTime() - 1);
    }

    private Varnode getStackStorage(Varnode offset, Address targetAddress, int size, int sequenceNumber) {
        Function function = program.getFunctionManager().getFunctionContaining(targetAddress);
        HighFunction decompile = decompilerHelper.decompile(function);
        LocalSymbolMap localSymbolMap = decompile.getLocalSymbolMap();
        long offsetLong = 0;
        if (offset != null && !offset.isConstant()) {
            List<Varnode> offsets = new ArrayList<>();
            List<String> operations = new ArrayList<>();
            backtrace(targetAddress, sequenceNumber - 1, offset, offsets, operations);
            if (offsets.isEmpty()) {
                return null;
            }
            for (Varnode varnode : offsets) {
                if (varnode.isConstant()) {
                    offsetLong = offsetLong + varnode.getOffset();
                } else {
                    return null;
                }
            }
            if (offsetLong == 0) {
                return null;
            }
        } else if (offset != null && offset.isConstant()) {
            offsetLong = offset.getOffset();
        }
        offsetLong = function.getStackFrame().growsNegative() ? offsetLong - function.getStackFrame().getFrameSize(): offsetLong;
        Variable[] stackVariables = function.getStackFrame().getStackVariables();
        Address address = program.getAddressFactory().getStackSpace().getAddress(offsetLong);
        if (address == null) {
            return null;
        }
        HighSymbol local = localSymbolMap.findLocal(address, null);
        //TODO: Handle stack variable stack[-0x8] and stack[-0x4]
        Varnode result;
        if (local != null) {
            result = local.getStorage().getFirstVarnode();
        } else {
            result = new Varnode(address, size);
        }
        return result;
    }
}
