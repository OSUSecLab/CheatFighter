import ghidra.program.model.address.Address;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

import static ghidra.program.model.pcode.PcodeOp.*;

public class StackVariableTracer {
    private BackTracer backTracer;
    private Program program;
    private Utility utility;
    private DecompilerHelper decompilerHelper;
    private Map<StackTracerInput, List<Varnode>> inputOutputMap;


    public StackVariableTracer(Program program, DecompilerHelper decompilerHelper) {
        this.program = program;
        this.backTracer = new BackTracer(program, decompilerHelper);
        this.utility = Utility.getInstance();
        this.inputOutputMap = new HashMap<>();
        this.decompilerHelper = decompilerHelper;
    }

    public List<Varnode> getStackVariableValues(Address address, Varnode varnode) {
        StackTracerInput input = new StackTracerInput(address, varnode);
        for (Map.Entry<StackTracerInput, List<Varnode>> inputOutput : inputOutputMap.entrySet()) {
            if (inputOutput.getKey().equals(input)) {
                return inputOutput.getValue();
            }
        }
        List<Varnode> stackBacktrace = new ArrayList<>();
        List<String> operations = backTracer.backtrace(address, varnode, stackBacktrace);
        List<Varnode> stackVariableValues = null;
        stackVariableValues = getStackVariableValues(address, varnode, operations, stackBacktrace);
        if (stackVariableValues == null || stackVariableValues.isEmpty()) {
            stackVariableValues = new ArrayList<>();
            stackVariableValues.add(backTracer.getLastTarget());
        }
        inputOutputMap.put(input, stackVariableValues);
        return stackVariableValues;
    }

    private List<Varnode> getStackVariableValues(Address address, Varnode varnode, List<String> operations, List<Varnode> stackBacktrace) {
        checkInput(address, varnode, operations);
        List<Varnode> result = new ArrayList<>();
        if (operations.isEmpty() && stackBacktrace.isEmpty()) {
            List<Varnode> varnodes = baseValueFinder(varnode, program.getFunctionManager().getFunctionContaining(address).getEntryPoint());
            return varnodes;
        }
        List<Varnode> firstValues;
        if (stackBacktrace.stream().anyMatch(v -> utility.varnodeEquals(v, varnode))) {
            firstValues = baseValueFinder(varnode, program.getFunctionManager().getFunctionContaining(address).getEntryPoint());
            operations = replaceValueInOperation(operations, varnode, firstValues);
        }
        for (Varnode v : stackBacktrace) {
            if (!utility.varnodeEquals(v, varnode) && v.getAddress().isStackAddress()) {
                List<Varnode> stackVariableValues = getStackVariableValues(address, v);
                operations = replaceValueInOperation(operations, v, stackVariableValues);
            }
        }
        addStackValueToResult(result, operations);
        return result;
    }

    private void checkInput(Address address, Varnode varnode, List<String> operations) {
        if (address == null) {
            throw new RuntimeException("Address can not be null for getting stack variable trace");
        }
        if (varnode == null) {
            throw new RuntimeException("Varnode can not be null for getting stack variable trace");
        }
        if (operations == null) {
            throw new RuntimeException("Operations can not be null or empty for getting stack variable values");
        }
    }

    public void addStackValueToResult(List<Varnode> result, List<String> operations) {
        Stack<Long> operands = new Stack<>();
        long temp = 0;
        Long op1, op2;
        for (int i = operations.size() - 1; i >= 0; i--) {
            String pop = operations.get(i);
            if (pop.chars().allMatch(c -> Character.isDigit(c) || c == '-')) {
                operands.push(Long.valueOf(pop));
            } else {
                try {
                    switch (getOpcode(pop)) {
                        case INT_ADD:
                            op1 = operands.isEmpty() ? 0 : operands.pop();
                            op2 = operands.isEmpty() ? 0 : operands.pop();
                            temp = op1 + op2;
                            if (op1 < 0 || op2 < 0) {
                                operands.push(op2);
                                operands.push(op1);
                            } else if (checkIfGlobal(temp)) {
                                operands.push(temp * -1);
                            } else {
                                operands.push(temp);
                            }
                            break;

                        case INT_AND:
                            op1 = operands.isEmpty() ? 0 : operands.pop();
                            op2 = operands.isEmpty() ? 0 : operands.pop();
                            temp = op1 & op2;
                            operands.push(temp);
                            break;

                        case INT_OR:
                            op1 = operands.isEmpty() ? 0 : operands.pop();
                            op2 = operands.isEmpty() ? 0 : operands.pop();
                            temp = op1 | op2;
                            operands.push(temp);
                            break;

                        case INT_LEFT:
                            Long leftShiftAmount = operands.isEmpty() ? 0 : operands.pop();
                            Long leftShiftOperand = operands.isEmpty() ? 0 : operands.pop();
                            temp = leftShiftOperand << leftShiftAmount;
                            operands.push(temp);
                            break;

                        case INT_SUB:
                            op1 = operands.isEmpty() ? 0 : operands.pop();
                            op2 = operands.isEmpty() ? 0 : operands.pop();
                            temp = op1 > op2 ? op1 - op2 : op2 - op1;
                            operands.push(temp);
                            break;

                        default:
                            throw new IllegalStateException("Unexpected value: " + getOpcode(pop));
                    }
                } catch (UnknownInstructionException e) {
//                    System.out.println("result = " + result + ", operations = " + operations);
                }
            }
        }
        if (operands.isEmpty()) {
            throw new RuntimeException("Operands can not be empty after ");
        }

        Long constant = null;
        while (!operands.isEmpty()) {
            Long pop = operands.pop();
            if (pop < 0) {
                Varnode output = new Varnode(program.getAddressFactory().getAddress("ram:" + utility.toHexString(pop * -1)), 8);
                result.add(output);
            } else {
                if (constant != null) {
                    constant += pop;
                } else {
                    constant = pop;
                }
            }
        }
        if (constant != null) {
            Varnode output = new Varnode(program.getAddressFactory().getConstantAddress(constant), 8);
            result.add(output);
        }

    }

    private boolean checkIfGlobal(long temp) {
        SymbolIterator allSymbols = program.getSymbolTable().getAllSymbols(true);
        for (Symbol symbol : allSymbols) {
            if (symbol.getAddress().getOffset() == temp && symbol.isGlobal()) {
                return true;
            }
        }
        return false;
    }

    public List<String> replaceValueInOperation(List<String> operations, Varnode varnode, List<Varnode> values) {
        if (values == null || values.isEmpty()) {
            return operations;
        }
        String result = null;
        if (values.size() == 1) {
            result = String.valueOf(values.get(0).getOffset());
        } else {
            if (values.stream().anyMatch(v -> !v.isConstant())) {
                throw new RuntimeException("could not replace value in operations for: " + Arrays.toString(values.toArray()));
            }
            long resultLong = 0;
            for (Varnode v : values) {
                resultLong += v.getOffset();
            }
            result = String.valueOf(resultLong);
        }

        if (result == null) {
            throw new RuntimeException("could not replace value in operations for: " + Arrays.toString(values.toArray()));
        }

        List<String> modifiedOperations = new Stack<>();
        for (String operation : operations) {
            if (operation.startsWith(varnode.toString())) {
                modifiedOperations.add(result);
            } else {
                modifiedOperations.add(operation);
            }
        }
        return modifiedOperations;
    }

    /**
     * This Method finds the first use of the stack variable from after the
     * given address. It returns the values associated with the stack at the first instance after the address. It can
     * return an array
     *
     * @param target  stack varnode
     * @param address address from where the base value search should start from
     * @return
     */
    public List<Varnode> baseValueFinder(Varnode target, Address address) {
        if (address.getOffset() == 0x1013b0) {
//            System.out.println("checkpoint");
        }
        Instruction instruction = program.getListing().getInstructionAt(address);
        Pair<Address, Varnode> firstUse = null;
        PcodeOp[] pCodeOps;
        do {
            pCodeOps = instruction.getPcode();
            if (address.getOffset() == 0x001013ec) {
//                System.out.println("checkpoint");
            }
            Varnode temp = target;
            for (PcodeOp pCodeOp : pCodeOps) {
                switch (pCodeOp.getOpcode()) {
                    case INT_ADD:
                        if (utility.isStackPointer(pCodeOp.getInput(0))) {
                            Varnode stackStorage = getStackStorage(pCodeOp);
                            if (utility.varnodeEquals(stackStorage, temp)) {
                                temp = pCodeOp.getOutput();
                            }
                        }
                        break;
                    case STORE:
                        if (utility.varnodeEquals(pCodeOp.getInput(1), temp)) {
                            firstUse = new ImmutablePair<>(pCodeOp.getSeqnum().getTarget(), pCodeOp.getInput(2));
                        }
                        break;
                    case RETURN:
                        return null;
                    default:
                        continue;
                }
            }
            instruction = instruction.getNext();
            address = instruction != null ? instruction.getAddress() : address;
        } while (instruction != null && firstUse == null);
        if (firstUse == null) {
            return null;
        }
        List<Varnode> firstValue = new ArrayList<>();
        List<Varnode> result = new ArrayList<>();
        List<String> backtrace = backTracer.backtrace(firstUse.getKey(), firstUse.getValue(), firstValue);
        if (firstValue.isEmpty() || backtrace == null || backtrace.isEmpty()) {
//            System.out.println("could not");
        } else {
            addStackValueToResult(result, backtrace);
        }
        return result;
    }

    private Varnode getStackStorage(PcodeOp pcodeOp) {
        Varnode offset = pcodeOp.getInput(1);
        Address target = pcodeOp.getSeqnum().getTarget();
        return getStackStorage(offset, target);
    }

    private Varnode getStackStorage(Varnode offset, Address target) {
        if (offset instanceof VarnodeAST) {
            HighVariable high = offset.getHigh();
            return high.getSymbol().getStorage().getFirstVarnode();
        } else {
            Function function = program.getFunctionManager().getFunctionContaining(target);
            if (function == null) {
                return null;
            }
            HighFunction decompile = decompilerHelper.decompile(function);
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
                return null;
            }
            return local.getStorage().getFirstVarnode();
        }
    }
}
