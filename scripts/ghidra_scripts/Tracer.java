import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

import static ghidra.program.model.pcode.PcodeOp.*;

public class Tracer {
    private Set<Address> traced;
    private Set<Varnode> interestingVarnodes;
    private ArrayList<PcodeOpAST> functionCalls;
    private Stack<Function> functionStack;
    private Set<String> memoryAccessingFunctions;
    private Program program;
    private DecompilerHelper decompilerHelper;
    private Purpose purpose;
    private Node currentNode;
    private List<List<String>> sequence;
    private Utility utility;
    private BacktraceDefUseChain backtraceDefUseChain;
    private LoadStoreAnalyzer loadStoreAnalyzer;
    private boolean initialized = false;
    private boolean shouldTerminate = false;
    private boolean sequenceFound = false;
    private int current;
    private StringBuilder stringBuilder;
    private Pair<Address, Varnode> registerFinderResult;
    private OffsetCalculator offsetCalculator;
    private BackTracer backTracer;
    private StackVariableTracer stackVariableTracer;

    public Tracer(Program program, BackTracer backTracer, StackVariableTracer stackVariableTracer, DecompilerHelper decompilerHelper) {
        this.backTracer = backTracer;
        this.stackVariableTracer = stackVariableTracer;
        this.stringBuilder = new StringBuilder();
        this.offsetCalculator = new OffsetCalculator(program, backTracer, stackVariableTracer, decompilerHelper);
        this.loadStoreAnalyzer = new LoadStoreAnalyzer(program, backTracer, stackVariableTracer, decompilerHelper);
        this.utility = Utility.getInstance();
        this.decompilerHelper = decompilerHelper;
        this.program = program;
        this.backtraceDefUseChain = new BacktraceDefUseChain();
        backtraceDefUseChain.init(program, decompilerHelper);
    }

    private void init(Set<Varnode> interestingVarnodes) {
        this.traced = new HashSet<>();
        this.functionCalls = new ArrayList<>();
        this.interestingVarnodes = new HashSet<>();
        for (Varnode interestingVarnode : interestingVarnodes) {
            this.interestingVarnodes.add(interestingVarnode);
        }
        this.shouldTerminate = false;
    }

    public void init(Set<Varnode> interestingVarnodes,
                     Purpose purpose,
                     Node currentNode) {
        if (purpose != Purpose.OFFSET_FINDER) {
            throw new RuntimeException("Node is only needed if using for finding offsets");
        }
        init(interestingVarnodes);
        this.functionStack = new Stack<>();
        this.memoryAccessingFunctions = new HashSet<>();
        this.purpose = purpose;
        this.currentNode = currentNode;
        this.initialized = true;
    }

    public void init(Set<Varnode> interestingVarnodes,
                     Purpose purpose,
                     List<List<String>> sequence) {
        if (purpose != Purpose.SEQUENCE_FINDER) {
            throw new RuntimeException("Sequence given for non sequence finder tracer");
        }
        init(interestingVarnodes);
        this.purpose = purpose;
        this.sequence = sequence;
        this.initialized = true;
        this.sequenceFound = false;
        this.current = 0;
    }

    public Pair<Address, Varnode> traceTillRegister(Varnode varnode, Address startingAddress, int sequenceNumber) {
        if (varnode.isRegister()) {
            throw new RuntimeException("Trace till register can not start with register");
        }
        Set<Varnode> varnodeSet = new HashSet<>();
        varnodeSet.add(varnode);
        init(varnodeSet);
        this.purpose = Purpose.REGISTER_FINDER;
        this.initialized = true;
        this.registerFinderResult = null;
        trace(startingAddress, sequenceNumber);
        return registerFinderResult;
    }

    public boolean findSequence(Address address) {
        if (!initialized) {
            throw new RuntimeException("Tracer not initialized");
        }
        trace(address);
        if (!sequenceFound && !shouldTerminate) {
            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                return sequenceFound;
            }
            Address functionEntryPoint = function.getEntryPoint();
            List<Reference> calls = getCalls(functionEntryPoint);
            for (Reference call : calls) {
                Address nextInstructionAddress = utility.getNextInstructionAddress(program, call.getFromAddress());
                findSequence(nextInstructionAddress);
            }
        }
        initialized = false;
        return sequenceFound;
    }

    public void findOffsets(Address address) {
        if (!initialized) {
            throw new RuntimeException("Tracer not initialized");
        }
        if (address == null) {
            throw new RuntimeException("Address can not be null for finding offsets");
        }
        trace(address);
        Function function = program.getFunctionManager().getFunctionContaining(address);
        Address functionEntryPoint = function.getEntryPoint();
        ReferenceIterator references = program.getReferenceManager().getReferencesTo(functionEntryPoint);
        if (!references.hasNext()) {
            return;
        }
        while (references.hasNext()) {
            Reference reference = references.next();
            if (reference.getReferenceType().isCall() || currentNode.contains(reference.getFromAddress())) {
                Set<Varnode> varnodes = new HashSet<>(interestingVarnodes);
                Address nextInstructionAddress = utility.getNextInstructionAddress(program, reference.getFromAddress());
                if (nextInstructionAddress != null) {
                    findOffsets(nextInstructionAddress);
                }
                interestingVarnodes = new HashSet<>(varnodes);
            }
        }
        initialized = false;
        currentNode.saveState();
    }


    private List<Reference> getCalls(Address functionEntryPoint) {
        ReferenceIterator calls = program.getReferenceManager().getReferencesTo(functionEntryPoint);
        List<Reference> result = new ArrayList<>();
        while (calls != null && calls.hasNext()) {
            Reference call = calls.next();
            if (call.getReferenceType().isCall()) {
                result.add(call);
            }
        }
        return result;
    }

    public ArrayList<PcodeOpAST> getFunctionCalls() {
        return functionCalls;
    }

    private void trace(Address address) {
        trace(address, 0);
    }

    private Varnode trace(Address address, int sequenceStart) {
        if (shouldNotRun(address)) return null;
        Tracker.addressTracked(address);
        Instruction instruction = program.getListing().getInstructionAt(address);
        PcodeOp[] pCodeOps = instruction.getPcode();

        while (!shouldNotRun(address)) {
            if (address.getOffset() == 0x00101450) {
                System.out.println("here");
            }
            Function currentFunction = program.getFunctionManager().getFunctionContaining(address);
            traced.add(address);
            Varnode temp = null, op1, op2, input, output;
            Address branchingAddress;
            Set<Varnode> interestingVarnodesSnap;
            boolean op1IsInteresting, op2IsInteresting;
            ArrayList<Varnode> uniqueTemporaryVarnodes = new ArrayList<>();
            for (int i = sequenceStart; i < pCodeOps.length; i++) {
                PcodeOp pCodeOP = pCodeOps[i];
                switch (pCodeOP.getOpcode()) {
                    case PcodeOp.CALL:
                        handleCalls(pCodeOP);
                        break;

                    case INT_ADD:
                        op1 = pCodeOP.getInput(0);
                        op2 = pCodeOP.getInput(1);
                        output = pCodeOP.getOutput();
                        utility.removeFromSet(interestingVarnodes, output);
                        op1IsInteresting = utility.contains(interestingVarnodes, op1) || op1.equals(temp);
                        op2IsInteresting = utility.contains(interestingVarnodes, op2) || op2.equals(temp);
                        if (utility.isStackPointer(op1) && output != null && output.isUnique()) {
                            Varnode stackStorage = getStackStorage(pCodeOP);
                            if (purpose == Purpose.OFFSET_FINDER && stackStorage != null) {
                                currentNode.replace(stackStorage, Collections.singletonList(output), address);
                            }
                            if (utility.contains(interestingVarnodes, stackStorage)) {
                                interestingVarnodes.add(output);
                                uniqueTemporaryVarnodes.add(output);
                            }
                        } else if (op1IsInteresting || op2IsInteresting) {
                            temp = output;
                            if (purpose == Purpose.OFFSET_FINDER) {
                                if (address.getOffset() == 0x00104ae4) {
                                    System.out.println("checkpoint");
                                }
                                List<Varnode> offsets = new ArrayList<>();
                                input = op1IsInteresting ? op1 : op2;
                                Varnode offsetVarnode = op1IsInteresting ? op2 : op1;
                                Varnode baseVarnode = op1IsInteresting ? op1 : op2;
                                if (!offsetVarnode.isConstant()) {
                                    offsets = offsetCalculator.getOffsets(pCodeOP, input, currentNode);
                                } else {
                                    offsets.add(offsetVarnode);
                                }
                                currentNode.addOffset(offsets, address, baseVarnode, temp);
                            }
                        }
                        break;


                    case PcodeOp.INT_AND:
                    case PcodeOp.INT_OR:
                    case PcodeOp.INT_XOR:
                    case PcodeOp.INT_SUB:
                    case PcodeOp.INT_MULT:
                    case PcodeOp.INT_SDIV:
                    case INT_DIV:
                    case PcodeOp.FLOAT_MULT:
                    case PcodeOp.FLOAT_ADD:
                    case PcodeOp.FLOAT_SUB:
                    case PcodeOp.FLOAT_DIV:
                        op1 = pCodeOP.getInput(0);
                        op2 = pCodeOP.getInput(1);
                        output = pCodeOP.getOutput();
                        op1IsInteresting = utility.contains(interestingVarnodes, op1) || op1.equals(temp);
                        op2IsInteresting = utility.contains(interestingVarnodes, op2) || op2.equals(temp);
                        input = op1IsInteresting ? op1 : op2;
                        utility.removeFromSet(interestingVarnodes, output);
                        if (purpose == Purpose.OFFSET_FINDER) {
                            currentNode.replace(input, Collections.singletonList(output), address);
                        }
                        if (op1IsInteresting || op2IsInteresting) {
                            temp = output;
                        }
                        break;

                    case PcodeOp.BRANCH:
                        interestingVarnodesSnap = utility.copyList(interestingVarnodes);
                        branchingAddress = getBranchingAddress(pCodeOP);
//                        traced.add(address);
                        Integer version2 = null;
                        if (purpose == Purpose.OFFSET_FINDER) {
                            version2 = currentNode.saveState();
                        }
                        trace(branchingAddress);
                        if (purpose == Purpose.OFFSET_FINDER && version2 != null) {
                            currentNode.restoreState(version2);
                        }
//                        traced.add(branchingAddress);
                        interestingVarnodes = new HashSet<>(interestingVarnodesSnap);
                        return null;

                    case PcodeOp.CBRANCH:
                        interestingVarnodesSnap = utility.copyList(interestingVarnodes);
                        branchingAddress = getBranchingAddress(pCodeOP);
//                        traced.add(address);
                        Integer version = null;
                        if (purpose == Purpose.OFFSET_FINDER) {
                            version = currentNode.saveState();
                        }
                        trace(branchingAddress);
                        if (purpose == Purpose.OFFSET_FINDER && version != null) {
                            currentNode.restoreState(version);
                        }
//                        traced.add(branchingAddress);
                        interestingVarnodes = new HashSet<>(interestingVarnodesSnap);
                        break;

                    case PcodeOp.INT_ZEXT:
                    case PcodeOp.INT_SEXT:
                    case PcodeOp.INT_LEFT:
                    case PcodeOp.SUBPIECE:
                    case PcodeOp.INT_SRIGHT:
                    case PcodeOp.INT_RIGHT:
                    case PcodeOp.COPY:
                    case PcodeOp.FLOAT_TRUNC:
                    case PcodeOp.INT_NEGATE:
                    case PcodeOp.INT_2COMP:
                    case PcodeOp.FLOAT_NEG:
                    case PcodeOp.FLOAT_FLOAT2FLOAT:
                    case PcodeOp.FLOAT_INT2FLOAT:
                        input = pCodeOP.getInput(0);
                        output = pCodeOP.getOutput();
                        // since the content are being replaced removed output from watchlist if present and replace in node
                        utility.removeFromSet(interestingVarnodes, output);
                        if (purpose == Purpose.OFFSET_FINDER) {
                            currentNode.replace(input, Collections.singletonList(output), address);
                        }
                        if (utility.contains(interestingVarnodes, input) || input.equals(temp)) {
                            temp = output;
                        }
                        break;

                    case PcodeOp.STORE:
                        input = pCodeOP.getInput(2);
                        Varnode storedVarnode = null;
                        try {
                            storedVarnode = loadStoreAnalyzer.analyze(pCodeOP);
                            if (purpose == Purpose.REGISTER_FINDER &&
                                    (utility.contains(interestingVarnodes, pCodeOP.getInput(1)) ||
                                            utility.varnodeEquals(pCodeOP.getInput(1), temp))) {
                                registerFinderResult = new ImmutablePair<>(utility.getPreviousInstructionAddress(program, address), input);
                                return null;
                            }
                            if (utility.contains(interestingVarnodes, input) || utility.varnodeEquals(input, temp)) {
                                temp = utility.convertAstToVarnode(storedVarnode);
                                if (purpose == Purpose.OFFSET_FINDER) {
                                    currentNode.replace(input, Collections.singletonList(temp), address);
                                }
                            } else {
                                Varnode varnode = utility.convertAstToVarnode(storedVarnode);
                                utility.removeFromSet(interestingVarnodes, storedVarnode);
                                utility.removeFromSet(interestingVarnodes, varnode);
                            }
                        } catch (Exception e) {
//                            System.out.println("could not analyze store at: " + address + " : " + pCodeOP.toString());
                        }
                        break;

                    case PcodeOp.LOAD:
                        output = pCodeOP.getOutput();
                        Varnode loadedVarnode;
                        try {
                            loadedVarnode = loadStoreAnalyzer.analyze(pCodeOP);
                            input = utility.convertAstToVarnode(loadedVarnode);
                            if (input != null && (utility.contains(interestingVarnodes, input) || input.equals(temp))) {
                                temp = output;
                                if (purpose == Purpose.OFFSET_FINDER) {
                                    currentNode.replace(input, Collections.singletonList(temp), address);
                                }
                            }
                            utility.removeFromSet(interestingVarnodes, output);
                        } catch (Exception e) {
//                            System.out.println("could not analyze load at: " + address + " : " + pCodeOP.toString());
                        }
                        break;

                    case PcodeOp.INT_CARRY:
                    case PcodeOp.INT_SCARRY:
                    case PcodeOp.INT_EQUAL:
                    case PcodeOp.INT_SLESS:
                    case PcodeOp.INT_SLESSEQUAL:
                    case PcodeOp.INT_NOTEQUAL:
                    case PcodeOp.INT_SBORROW:
                    case PcodeOp.INT_LESSEQUAL:
                    case PcodeOp.FLOAT_LESS:
                    case PcodeOp.FLOAT_LESSEQUAL:
                    case PcodeOp.FLOAT_EQUAL:
                    case PcodeOp.BOOL_NEGATE:
                    case PcodeOp.BOOL_AND:
                    case PcodeOp.BOOL_OR:
                    case PcodeOp.BOOL_XOR:
                    case PcodeOp.FLOAT_NAN:
                    case PcodeOp.CALLOTHER:
                    case PcodeOp.CALLIND:
                        break;

                    case PcodeOp.RETURN:
                    case PcodeOp.BRANCHIND:
                        Set<Varnode> stackVariables = utility.getNonInputStackVariables(interestingVarnodes);
                        removeCurrentStackVariables(address, interestingVarnodes, stackVariables);
                        if (purpose == Purpose.OFFSET_FINDER) {
                            currentNode.removeAll(stackVariables);
                            currentNode.removeUniques();
                            currentNode.mergeAllVersion();
                        }
                        return null;

                    default:
                        throw new RuntimeException(address.toString() + ": Not handled for tracing: " + pCodeOP.getMnemonic());
                }
            }
            if (purpose == Purpose.OFFSET_FINDER) {
                currentNode.removeUniques();
            }
            if (temp != null && !temp.isConstant()) {
                interestingVarnodes.add(temp);
            }
            removeUnique(interestingVarnodes);
            interestingVarnodes.removeAll(uniqueTemporaryVarnodes);
            instruction = instruction.getNext();
            Function nextFunction = program.getFunctionManager().getFunctionContaining(instruction.getAddress());
            if (!currentFunction.equals(nextFunction)) {
                instruction = null;
            }
            if (instruction != null) {
                address = instruction.getAddress();
                pCodeOps = instruction.getPcode();
            }
        }
        return null;
    }

    private void removeCurrentStackVariables(Address address, Set<Varnode> interestingVarnodes, Set<Varnode> stackVariables) {
        Function f = program.getFunctionManager().getFunctionContaining(address);
        Variable[] allVariables = f.getAllVariables();
        List<Varnode> toBeRemoved = new ArrayList<>();
        for (Varnode stackVariable : stackVariables) {
            for (Variable allVariable : allVariables) {
                if (utility.varnodeEquals(stackVariable, allVariable.getFirstStorageVarnode())) toBeRemoved.add(stackVariable);
            }
        }
        interestingVarnodes.removeAll(toBeRemoved);
        return;
    }

    private void removeUnique(Set<Varnode> interestingVarnodes) {
        if (interestingVarnodes != null && !interestingVarnodes.isEmpty()) {
            Set<Varnode> uniqueVariables = new HashSet<>();
            for (Varnode v : interestingVarnodes) {
                if (v != null && (v.isUnique() || v.isConstant())) {
                    uniqueVariables.add(v);
                }
            }
            interestingVarnodes.removeAll(uniqueVariables);
        }
    }

    public String getString() {
        return stringBuilder.toString();
    }

    private boolean shouldNotRun(Address address) {
        if (!initialized) {
            throw new RuntimeException("Tracer not initialized for tracing");
        }
        if (shouldTerminate || interestingVarnodes.isEmpty()) {
            return true;
        }
        if (address == null) {
            throw new RuntimeException("Address can not be null for tracing");
        }
        if (traced.contains(address)) {
            return true;
        }
        Instruction result = program.getListing().getInstructionAt(address);
        return result == null;
    }

    private void handleCalls(PcodeOp pCodeOP) {
        if (pCodeOP == null) {
            throw new RuntimeException("PCodeOP can not be null for handle call");
        }
        Address callSite = pCodeOP.getSeqnum().getTarget();
        if (callSite == null) {
            throw new RuntimeException("Could not get call site from pcode. PCode: " + pCodeOP.toString());
        }
        Address calledFunctionAddress = pCodeOP.getInput(0).getAddress();

        Function calleeFunction = program.getFunctionManager().getFunctionContaining(callSite);
        Function calledFunction = program.getFunctionManager().getFunctionAt(calledFunctionAddress);
        Boolean isInteresting = false;

        if (calledFunction == null || calleeFunction == null) {
            return;
        }

        if (Constants.ignoredSystemCall.contains(calledFunction.getName())) {
            return;
        }

        HighFunction calleeHighFunction = decompile(calleeFunction);
        PcodeOpAST callPCodeAST = utility.getCallPCodeAST(calleeHighFunction, callSite);
        if (callPCodeAST == null) {
            return;
        }

        // check if system call or user defined function call
        // system calls
        if (calledFunction.isThunk()) {
            List<Varnode> inputs = new ArrayList<>(), outputs = new ArrayList<>();
            long sysCallNo = 0;

            InputOutputMapping inputOutputMapping = null;
            try {
                inputOutputMapping = InputOutputMapping.valueOf(calledFunction.getName());
            } catch (Exception e) {
               System.out.println("Could not get input output mapping for: " + calledFunction.getName() + e.toString());
                return;
            }
            List<Integer> inputIndices = inputOutputMapping.getInputIndices();
            List<Integer> outputIndices = inputOutputMapping.getOutputIndices();

            /**
             * Process Inputs
             * Case 1: Syscall
             * Default: We take input from mapping and decide if the current function call is interesting or not
             */
            if (inputOutputMapping == InputOutputMapping.syscall) {
                if (!callPCodeAST.getInput(1).isConstant()) {
                    List<Varnode> sysnoBacktraced = new ArrayList<>();
                    List<Varnode> sysnoResolved = new ArrayList<>();
                    List<String> operations = backTracer.backtrace(callSite, 0, callPCodeAST.getInput(1), sysnoBacktraced);
                    stackVariableTracer.addStackValueToResult(sysnoResolved, operations);
                    if (sysnoResolved.size() == 1) {
                        Data data = utility.getDataAt(program, sysnoResolved.get(0).getAddress());
                        byte[] bytes = new byte[10];
                        try {
                            program.getMemory().getBytes(data.getAddress(), bytes);
                        } catch (MemoryAccessException e) {
                            e.printStackTrace();
                        }
                        sysCallNo = getLongValue(bytes);
                    }
                } else {
                    sysCallNo = callPCodeAST.getInput(1).getOffset();
                }
                // 10e is the code for process_vm_readv which lets you get data from one pid to another
                if (sysCallNo == 0x10e) {
                    Varnode input = callPCodeAST.getInput(5);
                    if (input.isUnique()) {
                        input = getSingleBacktrace(input, callSite);
                    }
                    if (utility.contains(interestingVarnodes, input)) {
                        Varnode output = callPCodeAST.getInput(3);
                        inputs.add(input);
                        outputs.add(output);
                        isInteresting = true;
                    }
                }
            } else if (inputOutputMapping.multipleInput()) {
                Parameter[] parameters = calledFunction.getParameters();
                for (int inputIndex = inputOutputMapping.getMultipleInputStart(); inputIndex < parameters.length; inputIndex++) {
                    Parameter parameter = parameters[inputIndex];
                    isInteresting = checkIfInteresting(callSite, isInteresting, callPCodeAST, inputs, inputIndex, parameter);
                }
            } else {
                for (Integer inputIndex : inputIndices) {
                    Parameter inputParameter = calledFunction.getParameter(inputIndex);
                    isInteresting = checkIfInteresting(callSite, isInteresting, callPCodeAST, inputs, inputIndex, inputParameter);
                }
            }

            /**
             * Process Output if interesting
             */
            if (isInteresting) {
                Varnode output;
                functionCalls.add(callPCodeAST);

                /**
                 * Function that do not take part in flow of data
                 */
                if (purpose == Purpose.SEQUENCE_FINDER && !sequenceFound) {
                    checkSequence(calledFunction.getName());
                }
                if (!inputOutputMapping.isDataFlowing()) {
                    return;
                }

                /**
                 * Functions that take part in data flow
                 * Case 1: function that flows to output. Usually in these cases the output is later stored into a variable. Easiest form of analysis.
                 */
                if (inputOutputMapping.flowsToOutput()) {
                    output = callPCodeAST.getOutput();
                    if (output.isUnique()) {
                        ArrayList<Varnode> outputSources = getVarnodes(backtraceDefUseChain.backtrace(new Node(output, program), callSite));
                        outputs.addAll(outputSources);
                    } else {
                        outputs.add(utility.convertAstToVarnode(output));
                    }
                }

                /**
                 * Case 2: function that has variable number of output for example sscanf(source, format, arg1, arg2, ...)
                 * So we start from arg1 and keep iterating
                 */
                else if (inputOutputMapping.multipleOutput()) {
                    Integer outputStart = inputOutputMapping.getMultipleOutputStart();
                    Varnode[] functionInputs = callPCodeAST.getInputs();
                    for (int outputIndex = outputStart + 1; outputIndex < functionInputs.length; outputIndex++) {
                        output = functionInputs[outputIndex];
                        if (output.isUnique()) {
                            ArrayList<Varnode> outputSources = getVarnodes(backtraceDefUseChain.backtrace(new Node(output, program), callSite));
                            outputs.addAll(outputSources);
                        } else {
                            outputs.add(utility.convertAstToVarnode(output));
                        }
                    }
                }
                /**
                 * Case 3: function that flow into one/more input to the function. Usually, the inputs are reference to pointer or memory location
                 */
                else {
                    if (calledFunction.getName().startsWith("pread64")) {
                        System.out.println("here");
                    }
                    for (Integer outputIndex : outputIndices) {
                        output = callPCodeAST.getInput(outputIndex + 1);
                        if (output.isUnique()) {
                            ArrayList<Varnode> outputSources = getVarnodes(backtraceDefUseChain.backtrace(new Node(output, program), callSite));
                            outputs.addAll(outputSources);
                        } else {
                            if (output.getHigh().getDataType().getName().endsWith("*")) {
                                ArrayList<Varnode> outputSources = getVarnodes(backtraceDefUseChain.backtrace(new Node(output, program), callSite));
                                outputs.addAll(outputSources);
                            } else {

                                outputs.add(utility.convertAstToVarnode(output));
                            }
                        }
                    }
                }
                interestingVarnodes.addAll(outputs);

                /**
                 * Purpose specific behaviour
                 */
                if (purpose == Purpose.OFFSET_FINDER) {
                    if (calledFunction.getName().equals("pread64")) {
                        if (inputs.size() != 1) {
                            throw new RuntimeException("Memory Access input has more than one/no varnode");
                        }
                        taintFunctions();
                        currentNode.dereference(inputs.get(0), outputs);
                    } else if (calledFunction.getName().equals("pwrite64")) {
                        if (inputs.size() != 1) {
                            throw new RuntimeException("Memory Access input has more than one/no varnode");
                        }
                        currentNode.write(inputs.get(0));
                    } else if ((calledFunction.getName().equals("syscall") && sysCallNo == 0x10e)) {
                        taintFunctions();
                        if (inputs.size() != 1) {
                            throw new RuntimeException("Memory Access input has more than one/no varnode");
                        }
                        if (outputs.size() == 1) {
                            Varnode varnode = outputs.get(0);
                            Pair<Address, Varnode> addressVarnodePair;
                            if (!varnode.isRegister()) {
                                addressVarnodePair = traceTillRegister(varnode, program.getFunctionManager().getFunctionContaining(callSite).getEntryPoint(), 0);
                                if (addressVarnodePair != null) {
                                    currentNode.dereference(inputs.get(0), Collections.singletonList(addressVarnodePair.getValue()));
                                }
                            }
                        } else {
                            currentNode.dereference(inputs.get(0), outputs);
                        }
                    } else {
                        currentNode.replace(inputs, outputs, callSite);
                    }
                }
            }


        }

        // user defined functions
        else {
            /*if (purpose == Purpose.OFFSET_FINDER && memoryAccessingFunctions.contains(calledFunction.getName())) {
                Varnode lastOffset = currentNode.getLastOffset();
                Varnode outputVarnode = calledFunction.getReturn().getFirstStorageVarnode();
                interestingVarnodes.add(outputVarnode);
                currentNode.dereference(lastOffset, Collections.singletonList(outputVarnode));
                return;
            }*/
            Set<Varnode> stackVariables = utility.getNonInputStackVariables(interestingVarnodes);
            removeCurrentStackVariables(callSite, interestingVarnodes, stackVariables);
            //TODO: before going in remove all stack bases and add them after
            Map<Varnode, String> stackBases = new HashMap<>();
            Map<Varnode, String> storedBases = null;

            if (purpose == Purpose.OFFSET_FINDER) {
                storedBases = currentNode.getStoredBases();
                List<Varnode> stacks = new ArrayList<>();
                for (Map.Entry<Varnode, String> storedBase : storedBases.entrySet()) {
                    if (storedBase.getKey().getAddress().isStackAddress()) {
                        stackBases.put(storedBase.getKey(), storedBase.getValue());
                        stacks.add(storedBase.getKey());
                    }
                }
                storedBases.keySet().removeAll(stacks);
            }
            if (purpose == Purpose.OFFSET_FINDER) {
                functionStack.push(calledFunction);
            }
            HashSet<Address> addresses = new HashSet<>();
            addresses.addAll(traced);
            trace(calledFunctionAddress);
            traced = addresses;
            /*if (purpose == Purpose.OFFSET_FINDER) {
                Function pop = functionStack.pop();
                if (functionStack.isEmpty() && memoryAccessingFunctions.contains(calledFunction.getName())) {
                    Varnode lastDereference = currentNode.getLastDereference();
                    Varnode outputVarnode = calledFunction.getReturn().getFirstStorageVarnode();
                    interestingVarnodes.add(outputVarnode);
                    currentNode.dereference(lastDereference, Collections.singletonList(outputVarnode));
                }
            }*/
            if (purpose == Purpose.OFFSET_FINDER && !stackBases.isEmpty() && storedBases != null) {
                storedBases.putAll(stackBases);
            }
            interestingVarnodes.addAll(stackVariables);
        }
    }

    private Boolean checkIfInteresting(Address callSite, Boolean isInteresting, PcodeOpAST callPCodeAST, List<Varnode> inputs, int i, Parameter parameter) {
        Varnode input = parameter.getFirstStorageVarnode();
        if (utility.contains(interestingVarnodes, input)) {
            inputs.add(input);
            isInteresting = true;
        } else if (callPCodeAST.getInput(i + 1).isUnique() ||
                (callPCodeAST.getInput(i + 1).getDef() != null && callPCodeAST.getInput(i + 1).getDef().getOpcode() == PTRSUB)) {
            input = getSingleBacktrace(callPCodeAST.getInput(i + 1), callSite);
            if (utility.contains(interestingVarnodes, input)) {
                inputs.add(input);
                isInteresting = true;
            }
        }
        return isInteresting;
    }

    private void taintFunctions() {
        for (Function function : functionStack) {
            memoryAccessingFunctions.add(function.getName());
        }
    }

    private long getLongValue(byte[] bytes) {
        long value = 0;
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == 0x00) {
                break;
            }
            value += ((long) bytes[i] & 0xffL) << (8 * i);
        }
        return value;
    }

    private Varnode getSingleBacktrace(Varnode input, Address address) {
        ArrayList<Node> backtrace = backtraceDefUseChain.backtrace(new Node(input, program), address);
        if (backtrace == null || backtrace.size() != 1) {
            return null;
        } else {
            return backtrace.get(0).getVarnode();
        }
    }

    private Address getBranchingAddress(PcodeOp pCodeOP) {
        if (pCodeOP == null) {
            throw new RuntimeException("PCodeOp can not be null for calculating branch address");
        }
        switch (pCodeOP.getOpcode()) {
            case PcodeOp.CBRANCH:
            case PcodeOp.BRANCH:
                Varnode input = pCodeOP.getInput(0);
                return program.getAddressFactory().getAddress(input.getSpace(), input.getOffset());
            default:
                throw new RuntimeException("Could not calculate branch address for branching operation: " + pCodeOP.getMnemonic());
        }
    }

    private HighFunction decompile(Function function) {
        if (function == null) {
            throw new RuntimeException("Function can not be null for decompiling");
        }
        return decompilerHelper.decompile(function);
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
                return null;
            }
            return local.getStorage().getFirstVarnode();
        }
    }


    private ArrayList<Varnode> getVarnodes(ArrayList<Node> backtrace) {
        ArrayList<Varnode> varnodes = new ArrayList<>();
        if (backtrace != null) {
            for (Node node : backtrace) {
                varnodes.add(node.getVarnode());
            }
        }
        return varnodes;
    }

    private void checkSequence(String name) {
        System.out.println("Found System Call: " + name);
        if (sequence.get(current).contains(name)) {

            current++;
        }
        if (current == sequence.size()) {
            shouldTerminate = true;
            sequenceFound = true;
        }
    }

    private Varnode traceTillMemory(Varnode target, Address address) {
        this.purpose = Purpose.MEMORY_FINDER;
        Set<Varnode> varnodeSet = new HashSet<>();
        varnodeSet.add(target);
        Varnode result = trace(address, 0);
        return result;
    }

    public Set<String> getMemoryAccessingFunctions() {
        return memoryAccessingFunctions;
    }
}
