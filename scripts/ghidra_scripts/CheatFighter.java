//
// @category Cheat
// @author Md Sakib Anwar
//

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.string.FoundString;
import ghidra.util.exception.CancelledException;

import java.io.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

public class NarcDragon extends GhidraScript {
    private List<String> baseSearchFunctions;
    private List<String> baseCalculateFunctions;
    private DecompilerHelper decompilerHelper;
    private Utility utility;
    private String resultDirectory;
    private BackTracer backTracer;
    private StackVariableTracer stackVariableTracer;
    private Set<Node> bases;
    String gameName, cheatName;
    private PrintWriter summaryWriter = null;
    private boolean writes = false;
    private List<List<List<String>>> sequences;

    @Override
    protected void run() throws Exception {
        Instant start = Instant.now();
        init();
        StringSearchResult importantStrings = getImportantStrings(currentProgram);
        ArrayList<Address> mappingAccesses = new ArrayList<>();
        for (Map.Entry<String, Address> stringAddressEntry : importantStrings.getMappingStrings().entrySet()) {
            mappingAccesses.add(stringAddressEntry.getValue());
        }
        for (Address mappingAccess : mappingAccesses) {
            println(Constants.SUCCESS_PREFIX + "Found mapping access at: " + mappingAccess);
        }
        PcodeOpAST baseSearchPCodeAST = null;
        PcodeOpAST baseCalculatePCodeAST = null;
        Set<Varnode> interestingVarnodes;

        for (Address mappingAccess : mappingAccesses) {
            Reference[] references = getReferencesTo(mappingAccess);
            println(Constants.SUCCESS_PREFIX + "References of Mapping Accesses are: " + Arrays.toString(references));
            for (Reference reference : references) {
                if (reference.getFromAddress().getOffset() == 0x000115a0)
                    System.out.println();
                println(Constants.SUCCESS_PREFIX + "Found reference at: " + reference.getFromAddress());
                Varnode firstVarnode = utility.getFirstRegister(currentProgram, reference.getFromAddress());
                if (firstVarnode == null) {
                    println("Could not get first register");
                    continue;
                }
                interestingVarnodes = new HashSet<>();
                interestingVarnodes.add(firstVarnode);
                Address tracingStartAddress = utility.getNextInstructionAddress(currentProgram, reference.getFromAddress());

                /**
                 * Init tracer and find sequence
                 */
                Tracer tracer;
                tracer = new Tracer(currentProgram, backTracer, stackVariableTracer, decompilerHelper);
                boolean sequenceFound = false;
                for (List<List<String>> sequence : sequences) {
                    tracer.init(new HashSet<>(interestingVarnodes), Purpose.SEQUENCE_FINDER, sequence);
                    sequenceFound = tracer.findSequence(tracingStartAddress);
                    if (sequenceFound) {
                        println("Found Sequence: " + sequence);
                        break;
                    }
                }
                if (sequenceFound) {
                    ArrayList<PcodeOpAST> functionCalls = tracer.getFunctionCalls();
                    for (PcodeOpAST functionCall : functionCalls) {
                        Function function = utility.getFunctionFromCallPCode(functionCall, currentProgram);
                        if (baseSearchFunctions.contains(function.getName())) {
                            baseSearchPCodeAST = functionCall;
                        }
                        if (baseCalculateFunctions.contains(function.getName())) {
                            baseCalculatePCodeAST = functionCall;
                        }
                    }
                    println(Constants.SUCCESS_PREFIX + "Found Sequence");
                    println(Constants.SUCCESS_PREFIX + "Base Search at " + baseSearchPCodeAST.getSeqnum().getTarget());
                    println(Constants.SUCCESS_PREFIX + "Base Calculate at " + baseCalculatePCodeAST.getSeqnum().getTarget());
                    /**
                     * Find bases
                     */
                    BacktraceDefUseChain backtraceDefUseChain = new BacktraceDefUseChain();
                    backtraceDefUseChain.init(currentProgram, decompilerHelper);
                    if (getFunctionAt(baseCalculatePCodeAST.getInput(0).getAddress()).getName().equals("sscanf")) {
                        bases = new HashSet<>(backtraceDefUseChain.backtrace(
                                new Node(baseSearchPCodeAST.getInput(2), currentProgram),
                                baseSearchPCodeAST.getSeqnum().getTarget()));
                    } else {
                        bases = new HashSet<>(backtraceDefUseChain.backtrace(
                                new Node(baseSearchPCodeAST.getInput(2), currentProgram),
                                baseSearchPCodeAST.getSeqnum().getTarget()));
                    }
                    println(Constants.SUCCESS_PREFIX + "Found Base Search Calls. Bases: ");
                    int i = 1;
                    List<Node> nameLessBases = new ArrayList<>();
                    for (Node base : bases) {
                        try {
                            setBaseName(base);
                            if (base.getBaseName().contains("ram")
                                    || base.getBaseName().contains("lx")
                                    || base.getBaseName().contains("tack")
                                    || !base.getBaseName().contains("lib")) nameLessBases.add(base);
                            println(Constants.SUCCESS_PREFIX + i++ + ": " + base.getBaseName() + " location: " + base.getFirstUseAddress());
                        } catch (Exception e) {
                            println(Constants.ERROR_PREFIX + i++ + ": " + base.getBaseName());
                            nameLessBases.add(base);
                        }
                    }
                    bases.removeAll(nameLessBases);
                    /**
                     * Calculate offsets
                     */
                    try {
                        for (Node base : bases) {
                            interestingVarnodes = new HashSet<>();
                            Function functionAt = getFunctionAt(baseCalculatePCodeAST.getInput(0).getAddress());
                            Address target = baseCalculatePCodeAST.getSeqnum().getTarget();
                            if ("strtoul".equals(functionAt.getName())) {
                                interestingVarnodes.add(utility.convertAstToVarnode(baseCalculatePCodeAST.getOutput()));
                            } else {
                                Varnode input = baseCalculatePCodeAST.getInput(3);
                                if (input.isUnique()) {
                                    ArrayList<Node> backtrace = backtraceDefUseChain.backtrace(new Node(input, currentProgram), target);
                                    for (Node node : backtrace) {
                                        interestingVarnodes.add(node.getVarnode());
                                    }
                                } else if (input.isInput()) {
                                    //need to handle case for base being stored in input
                                    int index = input.getHigh().getSymbol().getCategoryIndex();
                                    Function currentFunction = getFunctionContaining(target);
                                    Reference[] referencesTo = getReferencesTo(currentFunction.getEntryPoint());
                                    for (Reference ref : referencesTo) {
                                        if (ref.getReferenceType().isJump() || ref.getReferenceType().isCall()) {
                                            Node instance = base.getInstance();
                                            instance.setBaseName(base.getBaseName());
                                            bases.add(instance);
                                            interestingVarnodes = new HashSet<>();
                                            Function functionContaining = getFunctionContaining(ref.getFromAddress());
                                            if (functionContaining == null) {
                                                continue;
                                            }
                                            PcodeOpAST callPCodeAST = utility.getCallPCodeAST(decompilerHelper.decompile(functionContaining), ref.getFromAddress());
                                            ArrayList<Node> backtrace = backtraceDefUseChain.backtrace(new Node(callPCodeAST.getInput(index + 1), currentProgram), ref.getFromAddress());
                                            if (backtrace.size() == 1)
                                                interestingVarnodes.add(backtrace.get(0).getVarnode());
                                            else continue;
                                            tracer.init(interestingVarnodes, Purpose.OFFSET_FINDER, instance);
                                            tracer.findOffsets(utility.getNextInstructionAddress(currentProgram, utility.getNextInstructionAddress(currentProgram, ref.getFromAddress())));
//                                            printBase(instance);
                                            instance.closeFile();
                                            Set<String> memoryAccessingFunctions = tracer.getMemoryAccessingFunctions();
                                            for (String memoryAccessingFunction : memoryAccessingFunctions) {
                                                println(memoryAccessingFunction);
                                            }
                                        }
                                    }
                                    continue;
                                } else {
                                    interestingVarnodes.add(input);
                                }
                            }
                            tracer.init(interestingVarnodes, Purpose.OFFSET_FINDER, base);
                            tracer.findOffsets(utility.getNextInstructionAddress(currentProgram, baseCalculatePCodeAST.getSeqnum().getTarget()));
                            //printBase(base);
                            base.closeFile();
                            Set<String> memoryAccessingFunctions = tracer.getMemoryAccessingFunctions();
                            for (String memoryAccessingFunction : memoryAccessingFunctions) {
                                println(memoryAccessingFunction);
                            }
                        }
                    } catch (StackOverflowError e) {
                        printerr(Constants.ERROR_PREFIX + "Stack overflow error occurred. Writing what has been gathered so far");
                        for (Node base : bases) {
                            base.saveState();
                            //printBase(base);
                            base.closeFile();
                        }
                    }
                }
                else {
                    println("No Sequences Found!!!!!!!!!!!!!!!!!!!!!!!!");
                }
            }
            printSummary(mappingAccess.getOffset());
        }
        Instant finish = Instant.now();
        long l = Duration.between(start, finish).toMillis();
        println("Time Taken: " + l);
        boolean allBaseHasStack = true;
        if (bases != null) {
            for (Node basis : bases) {
                if (!basis.getStackOffset()) {
                    allBaseHasStack = false;
                    break;
                }
            }
        }
        if (bases != null && !bases.isEmpty() && !allBaseHasStack) {
            long executableSize = Long.parseLong(currentProgram.getMetadata().get("# of Bytes")) / 1024;
            File file = new File(resultDirectory + "/summary_result.csv");
            FileWriter fileWriter;
            if (!file.exists()) {
                fileWriter = new FileWriter(file);
            } else {
                fileWriter = new FileWriter(file, true);
            }
            PrintWriter resultWriter = new PrintWriter(fileWriter);
            Tracker.setNodes(bases);
            String x = getStat(l, executableSize);
            resultWriter.print(x);
            resultWriter.flush();
            resultWriter.close();
            println(x);
            System.out.println(x);
        }
    }

    private String getStat(long l, long executableSize) {
        /*return Tracker.getNodes()
                + "\t" + Tracker.getHeight()
                + "\t" + Tracker.getBranch()

                + "\t" + Tracker.getFunctionTracked()
                + "\t" + Tracker.getInstructionTracked()
                + "\t" + Tracker.getPcodeTracked()

                + "\t" + Tracker.getBfunctionTracked()
                + "\t" + Tracker.getBinstructionTracked()
                + "\t" + Tracker.getBpcodeTracked()

                + "\t" + "Yes"
                + "\t" + (writes ? "Yes" : "No")

                + "\t" + bases.size()
                + "\t" + executableSize
                + "\t" + 0
                + "\t" + 0
                + "\t" + l
                + "\t" + Tracker.getIndirectDataAnalyzed();*/

        StringBuilder baseNames = new StringBuilder();
        for (Node basis : bases) {
            baseNames.append(basis.getBaseName()).append("|");
        }

        return gameName + "," + cheatName + ",1"
                + "," + executableSize

                + "," + Tracker.getFunctionTracked()
                + "," + Tracker.getInstructionTracked()
                + "," + Tracker.getPcodeTracked()

                + "," + Tracker.getBfunctionTracked()
                + "," + Tracker.getBinstructionTracked()
                + "," + Tracker.getBpcodeTracked()

                + "," + Tracker.getHeight()
                + "," + Tracker.getBranch()
                + "," + Tracker.getNodes()

                + "," + bases.size()
                + "," + baseNames.toString()

                + "," + "1"
                + "," + (writes ? "1" : "0")

                + "," + l/1000.00
                + "," + Tracker.getIndirectDataAnalyzed();


    }

    private StringSearchResult getImportantStrings(Program program) {
        List<FoundString> strings = findStrings(program.getMemory(), 4, 1, true, false);
        Map<String, Address> mappingStrings = new HashMap<>();
        Map<String, Address> libraryStrings = new HashMap<>();
        for (FoundString string : strings) {
            String s = string.getString(program.getMemory());
            if (s.contains("proc") && s.contains("maps")) {
                mappingStrings.put(s, string.getAddress());
            } else if (s.contains("lib") || s.contains("so")) {
                libraryStrings.put(s, string.getAddress());
            }
        }
        return new StringSearchResult(mappingStrings, libraryStrings);
    }

    private void printSummary(long offset) {
        if (bases == null) return;
        summaryWriter.println(offset + " : " + currentProgram.getName() + "###########");
        for (Node base : bases) {
            if (base.getStackOffset()) continue;
            if (!base.getWrites().isEmpty()) writes = true;
            List<String> traverse = base.getMemoryAccessGraph().traverse();
            Tracker.setBranch(base.getMemoryAccessGraph().getBranches());
            Tracker.setHeight(base.getMemoryAccessGraph().getHeight());
            for (String s : traverse) {
                summaryWriter.println(base.getBaseName() + " :" + s);
                println(base.getBaseName() + " :" + s);
            }
            long executableSize = Long.parseLong(currentProgram.getMetadata().get("# of Bytes")) / 1024;
            String stat = getStat(0, executableSize);
            println(stat);
        }
        if (summaryWriter != null) {
            for (Node base : bases) {
                summaryWriter.print(base.getBaseName() + ", ");
            }
            summaryWriter.println();
        }
    }

    private void setBaseName(Node base) throws MemoryAccessException {
        Varnode varnode = base.getVarnode();
        Address address = varnode.getAddress();
        if (!address.isConstantAddress()) {
            if (address.isStackAddress()) {
                List<Varnode> stackVariableValues = stackVariableTracer.getStackVariableValues(base.getFirst(), varnode);
                if (stackVariableValues != null) {
                    if (stackVariableValues.size() == 1 || !stackVariableValues.stream().anyMatch(v -> v.isConstant() && v.getOffset() > 0x0)) {
                        for (Varnode stackVariableValue : stackVariableValues) {
                            /*if ((stackVariableValue.getAddress().isStackAddress())) {
                                base.setBaseName(stackVariableValue.getAddress().toString());
                                return;
                            }*/
                            if (!stackVariableValue.isConstant()) {
                                address = stackVariableValue.getAddress();
                                break;
                            }
                        }
                    } else {
                        String baseName = "[";
                        for (Varnode stackVariableValue : stackVariableValues) {
                            baseName += stackVariableValue.toString() + "+";
                        }
                        baseName += "]";
                        base.setBaseName(baseName);
                        return;
                    }
                } else {
                    base.setBaseName(base.getVarnode().getAddress().toString());
                    return;
                }
            }
        }
        String s = toHexString(address.getOffset(), true, true);
        Address physicalAddress = getAddressFactory().getAddress("ram:" + s);
        if (physicalAddress == null) {
            throw new RuntimeException("Could not get address in ram for offset: " + address.getOffset());
        }
        Data data = getDataAt(physicalAddress);
        if (data == null) {
            data = currentProgram.getListing().getDataAt(physicalAddress);
            if (data == null) {
                throw new RuntimeException("Could not get string at physical address: " + physicalAddress.toString());
            }
            boolean b = data.hasStringValue();
            byte[] bytes = new byte[10];
            currentProgram.getMemory().getBytes(data.getAddress(), bytes);
            String baseName = new String(bytes);
            base.setBaseName(baseName);
        } else {
            while (data.isPointer()) {
                data = getDataAt(getAddressFactory().getAddress("ram:" + data.getValue().toString()));
//                System.out.println("checkpoint");
            }
            if (data.getValue().toString().startsWith("0x")) base.setBaseName(new String(data.getBytes()));
            else base.setBaseName(data.getValue().toString());
        }

    }

    private void printBase(Node base) {
        PrintWriter printWriter;
        FileWriter fileWriter;
        try {
            if (base.getBaseName() == null) {
                throw new RuntimeException("Base name must be set before adding offset to node");
            }
            String fileName = currentProgram.getName() + "__base__" + base.getBaseName().replace('/', '_');
            fileName = fileName.replaceAll("[\\\\/:*?.\"\0<>|%]", "_");
            fileName = resultDirectory + "/" + fileName + ".txt";
            File file = new File(fileName);
            if (!file.exists()) {
                fileWriter = new FileWriter(file);
            } else {
                fileWriter = new FileWriter(file, true);
            }
            printWriter = new PrintWriter(fileWriter, true);
        } catch (IOException e) {
            throw new RuntimeException(Constants.ERROR_PREFIX + "Could not open file for output");
        }
        Map<Integer, NodeState> allVersions = base.getAllVersions();
        Set<String> printedList = new HashSet<>();
        printWriter.println("****************** Reads *********************");
        for (Map.Entry<Integer, NodeState> versionEntry : allVersions.entrySet()) {
            for (Map.Entry<Set<Varnode>, String> varnodeStringEntry : versionEntry.getValue().getBases().entrySet()) {
                boolean printed = false;
//                if (!varnodeStringEntry.getKey().isEmpty()) {
                String value = varnodeStringEntry.getValue();
                for (String s : printedList) {
                    if (s.startsWith(value)) {
                        printed = true;
                        break;
                    }
                }
                if (!printed) {
                    printWriter.println(value);
                    printedList.add(value);
                }
//                }
            }
            for (Map.Entry<Varnode, String> varnodeStringEntry : versionEntry.getValue().getStoredBases().entrySet()) {
                boolean printed = false;
                if (varnodeStringEntry.getKey() != null) {
                    String value = varnodeStringEntry.getValue();
                    for (String s : printedList) {
                        if (s.startsWith(value)) {
                            printed = true;
                            break;
                        }
                    }
                    if (!printed) {
                        addGlobalName(printWriter, varnodeStringEntry.getKey());
                        printWriter.println(value);
                        printedList.add(value);
                    }
                }
            }
        }
        printWriter.println("****************** Writes *********************");
        for (String write : base.getWrites()) {
            printWriter.println(write);
        }
        printWriter.println("##############################################");
        println("##############################################");

        printWriter.close();
    }

    private void addGlobalName(PrintWriter printWriter, Varnode key) {
        if (key.getAddress().isMemoryAddress()) {
            Data data = getDataAt(key.getAddress());
            if (data != null && data.isPointer()) {
                data = getDataAt(getAddressFactory().getAddress("ram:" + data.getValue().toString()));
                printWriter.print(data.getPrimarySymbol().getName() + ": ");
            }
        }
    }


    private void init() throws CancelledException {
        Tracker.getInstance(currentProgram);
        this.decompilerHelper = DecompilerHelper.getInstance(currentProgram, getMonitor());
        this.utility = Utility.getInstance(currentProgram);
        this.stackVariableTracer = new StackVariableTracer(currentProgram, decompilerHelper);
        this.backTracer = new BackTracer(currentProgram, decompilerHelper);
        this.sequences = getSequences();
        baseSearchFunctions = new ArrayList<>();
        baseSearchFunctions.add("strstr");
        baseSearchFunctions.add("strcasestr");
//        baseSearchFunctions.add("sscanf");
        baseCalculateFunctions = new ArrayList<>();
        baseCalculateFunctions.add("atoi");
        baseCalculateFunctions.add("atol");
        baseCalculateFunctions.add("strtoul");
        baseCalculateFunctions.add("sscanf");
        File f = askDirectory("Enter Directory for result", "Select");
        gameName = askString("What Game?", "Enter Game Name");
        cheatName = askString("What Cheat?", "Enter Cheat Name");
        this.resultDirectory = f.getPath();
        FileWriter fileWriter;
        try {
            File file = new File(resultDirectory + "/summary");
            if (!file.exists()) {
                fileWriter = new FileWriter(file);
            } else {
                fileWriter = new FileWriter(file, true);
            }
            summaryWriter = new PrintWriter(fileWriter, true);
        } catch (Exception e) {
//            System.out.println("Could not initialize file writer for summary");
        }
//        this.resultDirectory = "C:\\Users\\Asus\\ghidra_scripts\\result";
    }

    private List<List<List<String>>> getSequences() {
        List<List<List<String>>> result = new ArrayList<>();
        try {
            String filename = String.valueOf(askFile("Sequence File", "Choose Sequence File"));
            BufferedReader br = new BufferedReader(new FileReader(filename));
            String line;
            while ((line = br.readLine()) != null)   //returns a Boolean value
            {
                println(line);
                List<List<String>> functionGroupsList = new ArrayList<>();
                String[] functionGroups = line.split(";"); // use comma as separator
                for (String functionGroup : functionGroups) {
                    String[] functions = functionGroup.split(",");
                    List<String> functionGroupList = new ArrayList<>();
                    Collections.addAll(functionGroupList, functions);
                    functionGroupsList.add(functionGroupList);
                }
                result.add(functionGroupsList);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CancelledException e) {
            throw new RuntimeException(e);
        }
        return result;
    }

}
