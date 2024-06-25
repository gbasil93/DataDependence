//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class Lab4 extends GhidraScript {

    public void run() throws Exception {
        Function cFunction = getFunctionAt(getAddressFactory().getAddress("0x004010C0"));
//        extractInfoForAllInstructionsForFunction(cFunction);
        runSingleFunction(cFunction);
    }

    void runSingleFunction(Function function) {
        Digraph digraph = createDigraphForFunction(function);
        print(digraph.toString());
    }

    void runAllFunctions() {
        List<Digraph> digraphs = new LinkedList<>();
        Function cFunction = getFirstFunction();
        while (cFunction != null) {
            digraphs.add(createDigraphForFunction(cFunction));
            cFunction = getFunctionAfter(cFunction);
        }
        writeToFile(digraphs);
    }

    private List<String> parseOpType(int operandType) {
        List<String> types = new LinkedList<>();
        if (OperandType.doesRead(operandType)) {
            types.add("doesRead");
        }
        if (OperandType.doesWrite(operandType)) {
            types.add("doesWrite");
        }
        if (OperandType.isIndirect(operandType)) {
            types.add("isIndirect");
        }
        if (OperandType.isRelative(operandType)) {
            types.add("isRelative");
        }
        if (OperandType.isImplicit(operandType)) {
            types.add("isImplicit");
        }
        if (OperandType.isCodeReference(operandType)) {
            types.add("isCodeReference");
        }
        if (OperandType.isDataReference(operandType)) {
            types.add("isDataReference");
        }
        if (OperandType.isPort(operandType)) {
            types.add("isPort");
        }
        if (OperandType.isRegister(operandType)) {
            types.add("isRegister");
        }
        if (OperandType.isList(operandType)) {
            types.add("isList");
        }
        if (OperandType.isFlag(operandType)) {
            types.add("isFlag");
        }
        if (OperandType.isText(operandType)) {
            types.add("isText");
        }
        if (OperandType.isAddress(operandType)) {
            types.add("isAddress");
        }
        if (OperandType.isScalar(operandType)) {
            types.add("isScalar");
        }
        if (OperandType.isBit(operandType)) {
            types.add("isBit");
        }
        if (OperandType.isByte(operandType)) {
            types.add("isByte");
        }
        if (OperandType.isWord(operandType)) {
            types.add("isWord");
        }
        if (OperandType.isQuadWord(operandType)) {
            types.add("isQuadWord");
        }
        if (OperandType.isSigned(operandType)) {
            types.add("isSigned");
        }
        if (OperandType.isFloat(operandType)) {
            types.add("isFloat");
        }
        if (OperandType.isCoProcessor(operandType)) {
            types.add("isCoProcessor");
        }
        if (OperandType.isDynamic(operandType)) {
            types.add("isDynamic");
        }
        if (OperandType.isScalarAsAddress(operandType)) {
            types.add("isScalarAsAddress");
        }
        return types;
    }

    private void extractInfoForAllInstructionsForFunction(Function function) {
        Instruction instruction = getInstructionAt(function.getEntryPoint());
        while (instruction.getAddress().compareTo(getFunctionAfter(function.getEntryPoint()).getEntryPoint()) < 0) {
            println("*************************************************************");
            println(instruction.getAddressString(false, false) + " " + instruction);

            // Fall from address
            Address fallFromAddr = instruction.getFallFrom();
            if (fallFromAddr != null) {
                println("\tFalls from: " + fallFromAddr);
            }

            // References
            Reference[] references = instruction.getReferencesFrom();
            for (Reference reference : references) {
                println("\tReference: " + reference);
            }

            // Input objects
            Object[] inputObjects = instruction.getInputObjects();
            println("\tInput Objects:");
            for (Object inputObject : inputObjects) {
                println("\t\t" + inputObject + " \t(" + inputObject.getClass().getSimpleName() + ")");
            }

            // Result objects
            Object[] resultObjects = instruction.getResultObjects();
            println("\tResult Objects:");
            for (Object resultObject : resultObjects) {
                println("\t\t" + resultObject + " \t(" + resultObject.getClass().getSimpleName() + ")");
            }

            // Operands
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                String operandRepresentation = instruction.getDefaultOperandRepresentation(i).replaceAll(".+ ptr ", "");
                println("\tOperand " + i + " = " + operandRepresentation);
                List<String> operandTypes = parseOpType(instruction.getOperandType(i));
                RefType operandRefType = instruction.getOperandRefType(i);
                println("\t\t" + operandTypes);
                println("\t\t" + operandRefType.getDisplayString());
                if (OperandType.isDynamic(instruction.getOperandType(i))) {
                    Object[] operandObjs = instruction.getOpObjects(i);
                    for (Object operandObj : operandObjs) {
                        println("\t\t" + operandObj + " \t(" + operandObj.getClass().getSimpleName() + ")");
                    }
                }
            }

            instruction = getInstructionAfter(instruction.getAddress());
        }
    }

    /**********************************************************************************************
     **************************************** FUNCTIONS *******************************************
     **********************************************************************************************/

    /**
     * Writes the result of a formatted Digraph's string representation to an output file
     *
     * @param digraphs list of Digraph objects, one per function in the program
     */
    private void writeToFile(List<Digraph> digraphs) {
        try (FileWriter fw = new FileWriter("/home/gbasil/Documents/cs6747/lab3/submission.dot")) {
            for (Digraph digraph : digraphs) {
                fw.append(digraph.toString()).append("\n\n");
                fw.flush();
            }
        } catch (IOException e) {
            println("Error writing file: " + e);
        }
    }

    /**
     * Creates a Digraph for a given function, including all Nodes and Edges
     *
     * @param function	the Function object to create the Digraph for 
     * @return			a Digraph object containing function, Node (instruction), and Edge metadata
     */
    private Digraph createDigraphForFunction(Function function) {
        List<Node> nodeList = createNodeList(getInstructionAt(function.getEntryPoint()));
        List<Edge> edgeList = createEdgeList(nodeList);

        return new Digraph("0x" + function.getEntryPoint().toString(), nodeList, edgeList);
    }

    /**
     * Creates a list of edges based on the fallthrough (if it exists) and/or a flow if a a jump is performed, of each Node's instruction
     *
     * @param nodeList	list of Nodes in a given function
     * @return			list of Edges based on the Nodes' metadata
     */
    private List<Edge> createEdgeList(List<Node> nodeList) {
        List<Edge> edgeList = new LinkedList<>();
        for (Node currentNode : nodeList) {
            List<Address> flowAddrs = currentNode.getPossibleFlows();
            List<Node> flowNodes = nodeList.stream().filter(node -> flowAddrs.contains(node.instruction.getAddress())).toList();
            for (Node flowNode : flowNodes) {
                edgeList.add(new Edge(currentNode, flowNode));
                flowNode.previousFlows.add(currentNode);
            }
        }
        return edgeList;
    }

    /**
     * Cretaes a list of Nodes for a given function, along with metadata including the Node's name, defs, uses, and label string
     *
     * @param instruction	Instruction object representing the entry point for the function in question
     * @return				list of instruction Nodes for the function starting with the entry point up until the next function's entry point
     */
    private List<Node> createNodeList(Instruction instruction) {
        List<Node> nodes = new LinkedList<>();
        List<String> edges = new LinkedList<>();
        Function functionAfter = getFunctionAfter(instruction.getAddress());

        int instructionCtr= 1;
        while (true) {
            if (functionAfter == null && instruction == null) {
                break;
            } else if (functionAfter != null && instruction.getAddress().compareTo(functionAfter.getEntryPoint()) >= 0) {
                break;
            }
            String labelString = instruction.getAddressString(false, false);
            Node cNode = new Node("n" + instructionCtr++, labelString, instruction);
            nodes.add(cNode);
            instruction = instruction.getNext();
        }
        return nodes;
    }

    /**********************************************************************************************
     ***************************************** CLASSES ********************************************
     **********************************************************************************************/

    private static class Digraph {
        private final String name;
        private final List<Node> nodeList;
        private final List<Edge> edgeList;

        public Digraph(String name, List<Node> nodeList, List<Edge> edgeList) {
            this.name = name;
            this.nodeList = nodeList;
            this.edgeList = edgeList;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("digraph \"" + this.name + "\" {\n");
            for (Node node : nodeList) {
                sb.append("\t").append(node).append("\n");
            }
            sb.append("\n");
            for (Edge edge : edgeList) {
                sb.append("\t").append(edge).append("\n");
            }
            sb.append("}");
            return sb.toString();
        }
    }

    private static class Edge {
        private final Node srcNode;
        private final Node dstNode;

        public Edge(Node srcNode, Node dstNode) {
            this.srcNode = srcNode;
            this.dstNode = dstNode;
        }

        @Override
        public String toString() {
            return String.format("%s -> %s", srcNode.name, dstNode.name);
        }
    }

    private class Node {
        private String name;
        private String label;
        private Set<String> defs;
        private Set<String> uses;
        private Instruction instruction;
        private Set<Node> previousFlows;

        public Node(String name, String label, Instruction instruction) {
            this.name = name;
//            this.label = "0x" + label + ";";
            this.label = instruction + "; ";
            this.instruction = instruction;
            this.defs = new HashSet<>();
            this.uses = new HashSet<>();
            this.previousFlows = new HashSet<>();
            parseOperands();
//            getOperandInfo();
//            defs.addAll(getInstructionDefs());
//            uses.addAll(getInstructionUses());
//            defs.addAll(getDefs());
//            uses.addAll(getUses());
            updateLabelWithDefs();
            updateLabelWithUses();
        }

        private void parseOperands() {
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                String operandRepresentation = instruction.getDefaultOperandRepresentation(i).replaceAll(".+ ptr ", "");
//                List<String> operandTypes = parseOpType(instruction.getOperandType(i));
                int operandType = instruction.getOperandType(i);
                RefType operandRefType = instruction.getOperandRefType(i);
                if (operandRefType.isRead()) {
                    uses.add(operandRepresentation);
                }
                if (operandRefType.isWrite()) {
                    defs.add(operandRepresentation);
                }
                if (OperandType.isDynamic(operandType)) {
                    Object[] opObjects = Arrays.stream(instruction.getOpObjects(i)).filter(obj -> obj instanceof Register).toArray();
                    for (Object opObject : opObjects) {
                        uses.add(opObject.toString());
                    }
                }
                if (operandRefType.isConditional()) {

                }
            }
            if (instruction.getMnemonicString().compareToIgnoreCase("PUSH") == 0) {
                defs.addAll(List.of(new String[]{"ESP", "[ESP]"}));
                uses.addAll(List.of(new String[]{"ESP"}));
            } else if (instruction.getMnemonicString().compareToIgnoreCase("POP") == 0) {
                defs.addAll(List.of(new String[]{"ESP"}));
                uses.addAll(List.of(new String[]{"ESP", "[ESP]"}));
            } else if (instruction.getMnemonicString().compareToIgnoreCase("cmp") == 0) {
                defs.add("EFLAGS");
            } else if (instruction.getMnemonicString().compareToIgnoreCase("test") == 0) {
                defs.add("EFLAGS");
            } else if (instruction.getFlowType().isConditional()) {
                uses.add("EFLAGS");
            }
        }

        private void updateLabelWithDefs() {
            label += " D: ";
            if (!defs.isEmpty()) {
                label += String.join(", ", defs) + " ";
            }
        }

        private void updateLabelWithUses() {
            label += "U: ";
            if (!uses.isEmpty()) {
                label += String.join(", ", uses);
            }
        }

//        private void getOperandInfo() {
//            for (int i = 0; i < instruction.getNumOperands(); i++) {
//                String operandStr = instruction.getDefaultOperandRepresentation(i);
//                if (operandStr.contains("[")) {
//                    operandStr = operandStr.substring(operandStr.indexOf("["));
//                }
//                RefType operandRefType = instruction.getOperandRefType(i);
//                if (operandRefType == RefType.READ || operandRefType == RefType.READ_WRITE) {
//                    uses.add(operandStr);
//                }
//                if (operandRefType == RefType.WRITE || operandRefType == RefType.READ_WRITE) {
//                    defs.add(operandStr);
//                }
//                if (operandRefType == RefType.DATA) {
//                    boolean opHasRegisterRef = instruction.getDefaultOperandRepresentationList(i).stream()
//                            .filter(obj -> !obj.toString().contains("EIP"))
//                            .anyMatch(obj -> obj instanceof Register);
//                    if (opHasRegisterRef) {
//                        uses.add(operandStr);
//                    }
//                }
//            }
//        }

//        public List<String> getUses() {
//            return Arrays.stream(instruction.getInputObjects())
//                    .filter(obj -> obj instanceof Register && !obj.toString().equals("EIP"))
//                    .map(object -> {
//                        if (object.toString().endsWith("F") && instruction.getFlowType().isJump()) {
//                            return "EFLAGS";
//                        }
//                        return object.toString();
//                    })
//                    .toList();
//        }
//
//        public List<String> getDefs() {
//            return Arrays.stream(instruction.getResultObjects())
//                    .filter(obj -> obj instanceof Register && !obj.toString().equals("EIP"))
//                    .map(object -> {
//                        if (object.toString().contains("F")) {
//                            if (instruction.getOperandRefType(0).equals(RefType.READ)) {
//                                return "EFLAGS";
//                            }
//                        }
//                        return object.toString();
//                    })
//                    .filter(objStr -> !objStr.endsWith("F"))
//                    .toList();
//        }
//
//        public List<String> getInstructionDefs() {
//            List<String> list = new LinkedList<>();
//            if (instruction.getMnemonicString().toLowerCase().contains("test")) {
//                list.add("EFLAGS");
//            } else if (instruction.getMnemonicString().toLowerCase().contains("push")) {
//                list.add("[ESP]");
//                list.add("ESP");
//            } else if (instruction.getMnemonicString().toLowerCase().contains("pop")) {
//                list.add("ESP");
//            }
//            return list;
//        }
//
//        public List<String> getInstructionUses() {
//            List<String> list = new LinkedList<>();
//            if (instruction.getMnemonicString().toLowerCase().contains("push")) {
//                list.add("ESP");
//            } else if (instruction.getMnemonicString().toLowerCase().contains("pop")) {
//                list.add("[ESP]");
//                list.add("ESP");
//            } else if (instruction.getNumOperands() > 0 && instruction.getOperandRefType(0) == RefType.CONDITIONAL_JUMP) {
//                list.add("EFLAGS");
//            }
//            return list;
//        }

        public List<Address> getPossibleFlows() {
            List<Address> possibleFlows = new LinkedList<>(Arrays.asList(instruction.getFlows()));
            if (instruction.hasFallthrough()) {
                possibleFlows.add(instruction.getDefaultFallThrough());
            }
            return possibleFlows;
        }

        @Override
        public String toString() {
            return String.format("%s [label =\"%s\"];", name, label);
        }
    }

}
