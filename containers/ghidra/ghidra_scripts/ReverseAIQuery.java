// ReverseAI's fixed Ghidra query (reviewed code baked into the image; requests cannot choose scripts).
// Arguments: <output JSON path> <mode> and the mode's fixed arguments (see analyze, functions, function and xrefs below).
// analyze writes what Ghidra reports, as plain JSON: memory blocks, functions (address order, at most MAX_FUNCTIONS; size is
// the span from the entry to the last body byte, decision m3a-function-span), the calls and the other references
// (with their reference-type flags) from the instructions of the first max_functions file-backed executable
// functions, pseudocode for the entry-point function and then the largest of those, and, in the same order, the
// first instructions of `assembly` of them (M3c). The Python worker checks what the bytes can confirm (each anchor's
// file offset, bytes and memory-block mapping, one rebase delta, bounds and order) and drops or refuses the rest;
// names, sizes, call and reference targets, reference types, instruction texts and pseudocode remain Ghidra's
// interpretation, reported as derived and never as verified. The M3d modes answer one question each (a page of
// functions, one function's parts, the references to one address) with the same blocks and the same kind of rows.
//@category ReverseAI

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

public class ReverseAIQuery extends GhidraScript {
	private static final int MAX_FUNCTIONS = 4096;
	private static final int MAX_CALLS_PER_FUNCTION = 1024;
	private static final int MAX_REFS_PER_FUNCTION = 1024;
	private static final int MAX_BODY_INSTRUCTIONS = 1000000;
	private static final int MAX_ROWS = 65536;  // functions, callers or xrefs counted by one run (decision m3d-seams-w)
	private static final int MAX_LOCATION = 4096;
	private static final int MAX_TEXT = 65536;
	private static final int MAX_EXPORT_TEXT = 1048576;
	// The same rule as ReverseAIOptions: the worker refuses the run if any of these is still on.
	private static final Pattern OFF = Pattern.compile("(?i).*(pdb|dwarf|swift).*");

	private Memory memory;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String mode = args.length > 1 ? args[1] : "";
		int expected = mode.equals("analyze") ? 8 : mode.equals("functions") ? 5 : mode.equals("function") ? 9
			: mode.equals("xrefs") ? 6 : mode.equals("export") ? 8 : -1;
		if (args.length != expected) {
			throw new IllegalArgumentException("ReverseAIQuery arguments");
		}
		memory = currentProgram.getMemory();
		StringBuilder out = header();
		out.append(",\"mode\":").append(quote(mode));
		if (mode.equals("analyze")) {
			analyze(out, args);
		}
		else if (mode.equals("functions")) {
			functions(out, args);
		}
		else if (mode.equals("function")) {
			function(out, args);
		}
		else if (mode.equals("export")) {
			export(out, args);
		}
		else {
			xrefs(out, args);
		}
		out.append("}");
		try (Writer writer = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
			writer.write(out.toString());
		}
	}

	/** The executable format, the analyzer options the worker checks and the loaded memory blocks. */
	private StringBuilder header() {
		StringBuilder out = new StringBuilder("{\"format\":").append(quote(currentProgram.getExecutableFormat()))
			.append(",\"options_off\":{");
		boolean first = true;
		for (Map.Entry<String, String> option : getCurrentAnalysisOptionsAndValues(currentProgram).entrySet()) {
			if (OFF.matcher(option.getKey()).matches()) {
				out.append(first ? "" : ",").append(quote(option.getKey())).append(":").append(quote(option.getValue()));
				first = false;
			}
		}
		out.append("},\"blocks\":[");
		first = true;
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isLoaded()) {
				continue; // non-loaded blocks (section headers, .symtab, ...) are not part of the program's address space
			}
			out.append(first ? "" : ",").append("{\"name\":").append(quote(block.getName()))
				.append(",\"start\":").append(block.getStart().getOffset())
				.append(",\"size\":").append(block.getSize())
				.append(",\"execute\":").append(block.isExecute())
				.append(",\"initialized\":").append(block.isInitialized())
				.append(",\"file_offset\":").append(blockFileOffset(block)).append("}");
			first = false;
		}
		return out.append("]");
	}

	/** analyze: <max_functions> <decompile> <entry file offset or -1> <decompile seconds> <assembly> <max_instructions>. */
	private void analyze(StringBuilder out, String[] args) throws Exception {
		int maxFunctions = Integer.parseInt(args[2]);
		int decompile = Integer.parseInt(args[3]);
		long entryOffset = Long.parseLong(args[4]);
		long deadline = System.currentTimeMillis() + 1000L * Integer.parseInt(args[5]);
		int assembly = Integer.parseInt(args[6]);
		int maxInstructions = Integer.parseInt(args[7]);

		List<Function> selected = new ArrayList<>();
		out.append(",\"functions\":[");
		boolean first = true;
		int count = 0;
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			if (function.isExternal() || count == MAX_FUNCTIONS) {
				continue;
			}
			count++;
			Address entry = function.getEntryPoint();
			long size = span(function);
			long offset = fileOffset(entry);
			MemoryBlock block = memory.getBlock(entry);
			boolean anchored = offset >= 0 && block != null && block.isExecute() && block.isInitialized()
				&& selected.size() < maxFunctions;
			out.append(first ? "" : ",").append("{\"name\":").append(quote(function.getName()))
				.append(",\"entry\":").append(entry.getOffset())
				.append(",\"size\":").append(size)
				.append(",\"file_offset\":").append(offset)
				.append(",\"anchored\":").append(anchored)
				.append(",\"bytes\":").append(quote(anchored ? hex(entry, block, size) : ""))
				.append(",\"calls\":[");
			if (anchored) {
				selected.add(function);
				appendCalls(out, function, MAX_CALLS_PER_FUNCTION);  // analyze: at most 1,024 rows, unchanged
			}
			out.append("],\"refs\":[");
			if (anchored) {
				appendRefs(out, function);
			}
			out.append("]}");
			first = false;
		}

		out.append("],\"pseudocode\":[");
		List<Function> order = new ArrayList<>();
		for (Function function : selected) {
			if (fileOffset(function.getEntryPoint()) == entryOffset) {
				order.add(function);
			}
		}
		List<Function> rest = new ArrayList<>(selected);
		rest.removeAll(order);
		rest.sort((a, b) -> {
			int bySize = Long.compare(span(b), span(a));
			return bySize != 0 ? bySize : a.getEntryPoint().compareTo(b.getEntryPoint());
		});
		order.addAll(rest);
		first = true;
		if (decompile > 0 && !order.isEmpty()) {
			DecompInterface decompiler = new DecompInterface();
			try {
				decompiler.setOptions(new DecompileOptions());
				decompiler.openProgram(currentProgram);
				for (Function function : order.subList(0, Math.min(decompile, order.size()))) {
					String text = decompiled(decompiler, function, deadline);
					if (text == null) {
						continue;
					}
					out.append(first ? "" : ",").append("{\"entry\":").append(function.getEntryPoint().getOffset())
						.append(",\"text\":").append(quote(text)).append("}");
					first = false;
				}
			}
			finally {
				decompiler.dispose();
			}
		}
		out.append("],\"assembly\":[");
		first = true;
		for (Function function : order.subList(0, Math.min(Math.max(assembly, 0), order.size()))) {
			out.append(first ? "" : ",");
			appendInstructions(out, function, maxInstructions);
			first = false;
		}
		out.append("]");
	}

	/** functions: <query (x + hex)> <start> <limit>: the page of file-backed executable functions whose name contains
	 * query, in address order, and how many there are (at most MAX_ROWS, else "overflow"). */
	private void functions(StringBuilder out, String[] args) throws Exception {
		String query = text(args[2]);
		int start = Integer.parseInt(args[3]);
		int limit = Integer.parseInt(args[4]);
		out.append(",\"functions\":[");
		boolean first = true;
		int total = 0;
		for (Function function : anchoredFunctions()) {
			if (!function.getName().contains(query)) {
				continue;
			}
			if (total == MAX_ROWS) {
				out.append("],\"overflow\":true,\"total\":").append(total);
				return;
			}
			if (total >= start && total - start < limit) {
				out.append(first ? "" : ",");
				appendFunction(out, function, total, false);
				first = false;
			}
			total++;
		}
		out.append("],\"overflow\":false,\"total\":").append(total);
	}

	/** function: <select entry|name> <entry file offset or -1> <name (x + hex)> <parts> <start> <limit> <decompile
	 * seconds>: the target (the function at that entry, or the lowest-entry one with that exact name), how many share
	 * the name, its calls and references, the calls to it from file-backed executable code, its pseudocode and a page
	 * of its instructions from the entry. */
	private void function(StringBuilder out, String[] args) throws Exception {
		boolean byEntry = args[2].equals("entry");
		long entryOffset = Long.parseLong(args[3]);
		String name = text(args[4]);
		String parts = args[5];
		int start = Integer.parseInt(args[6]);
		int limit = Integer.parseInt(args[7]);
		long deadline = System.currentTimeMillis() + 1000L * Integer.parseInt(args[8]);
		Function target = null;
		int matches = 0;
		for (Function function : anchoredFunctions()) {
			if (byEntry ? fileOffset(function.getEntryPoint()) == entryOffset : function.getName().equals(name)) {
				target = target == null ? function : target;  // address order: the first is the lowest entry
				matches++;
			}
		}
		out.append(",\"matches\":").append(matches).append(",\"target\":");
		if (target == null) {
			out.append("null");
			return;
		}
		appendFunction(out, target, 0, true);
		out.append(",\"callers\":");
		appendReferencesTo(out, target.getEntryPoint(), true);
		out.append(",\"pseudocode\":");
		String text = null;
		if (parts.equals("pseudocode") || parts.equals("all")) {
			DecompInterface decompiler = new DecompInterface();
			try {
				decompiler.setOptions(new DecompileOptions());
				decompiler.openProgram(currentProgram);
				text = decompiled(decompiler, target, deadline);
			}
			finally {
				decompiler.dispose();
			}
		}
		out.append(text == null ? "null" : quote(text)).append(",\"instructions\":");
		if (parts.equals("assembly") || parts.equals("all")) {
			appendPage(out, target, start, limit);
		}
		else {
			out.append("null");
		}
	}

	/** export: <entry|name> <entry file offset> <name (x + hex)> <pseudocode|assembly> <start> <limit>.
	 * Cached tables serve all other parts. A call here visits or decompiles only its selected function. */
	private void export(StringBuilder out, String[] args) throws Exception {
		if ((!args[2].equals("entry") && !args[2].equals("name"))
				|| (!args[5].equals("pseudocode") && !args[5].equals("assembly"))) {
			throw new IllegalArgumentException("ReverseAIQuery export arguments");
		}
		boolean byEntry = args[2].equals("entry");
		long offset = Long.parseLong(args[3]);
		String name = text(args[4]);
		int start = Integer.parseInt(args[6]);
		int limit = Integer.parseInt(args[7]);
		if (start < 0 || start > 1048575 || limit < 1 || limit > 128) {
			throw new IllegalArgumentException("ReverseAIQuery export page");
		}
		Function target = null;
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			monitor.checkCancelled();
			long entryOffset = uniqueExportFileOffset(function.getEntryPoint(), 1);
			if (!function.isExternal() && entryOffset >= 0
					&& (byEntry ? entryOffset == offset : function.getName().equals(name))) {
				target = function;
				break; // The iterator's address order selects the lowest exact match.
			}
		}
		out.append(",\"function\":");
		if (target == null) {
			out.append("null,\"pseudocode\":null,\"instructions\":null");
			return;
		}
		appendFunction(out, target, 0, false);
		out.append(",\"pseudocode\":");
		String pseudocode = args[5].equals("pseudocode") ? exportDecompiled(target) : null;
		out.append(pseudocode == null ? "null" : quote(pseudocode)).append(",\"instructions\":");
		if (args[5].equals("assembly")) {
			appendExportPage(out, target, start, limit);
		}
		else {
			out.append("null");
		}
	}

	/** Match the prepare traversal's validity rule, so every cursor counts the same admitted instructions. */
	private void appendExportPage(StringBuilder out, Function function, int start, int limit) throws Exception {
		StringBuilder rows = new StringBuilder();
		Address entry = function.getEntryPoint();
		int visits = 0;
		int total = 0;
		boolean first = true;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			monitor.checkCancelled();
			if (++visits > MAX_BODY_INSTRUCTIONS) {
				throw new IllegalStateException("TooManyRows");
			}
			Address at = instruction.getAddress();
			int length = instruction.getLength();
			if (at.compareTo(entry) < 0 || length < 1 || length > 16
					|| length > span(function) - at.subtract(entry) || uniqueExportFileOffset(at, length) < 0) {
				continue;
			}
			if (total >= start && total - start < limit) {
				rows.append(first ? "" : ",").append("{\"index\":").append(total)
					.append(",\"address\":").append(at.getOffset()).append(",\"length\":").append(length)
					.append(",\"file_offset\":").append(fileOffset(at))
					.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
					.append(",\"text\":").append(quote(instruction.toString())).append("}");
				first = false;
			}
			total++;
		}
		out.append("{\"start\":").append(Math.min(start, total)).append(",\"rows\":[").append(rows)
			.append("],\"total\":").append(total).append(",\"overflow\":false}");
	}

	/** Every byte must have exactly one executable, contiguous file mapping; identical to prepare's rule. */
	private long uniqueExportFileOffset(Address at, int length) {
		MemoryBlock block = memory.getBlock(at);
		long offset = fileOffset(at);
		if (block == null || !block.isLoaded() || !block.isExecute() || !block.isInitialized() || offset < 0
				|| blockFileOffset(block) < 0 || blockFileOffset(block) + at.subtract(block.getStart()) != offset
				|| block.getEnd().subtract(at) < length - 1L) {
			return -1;
		}
		for (int index = 0; index < length; index++) {
			Address address = at.add(index);
			List<Address> mapped = memory.locateAddressesForFileOffset(offset + index);
			if (fileOffset(address) != offset + index || mapped == null || mapped.size() != 1 || !address.equals(mapped.get(0))) {
				return -1;
			}
		}
		return offset;
	}

	/** One complete C result, at most 40 seconds and 1,048,576 Unicode scalars; never clipped.
	 * Python's printable_text is authoritative for normalization, including its Unicode category version. */
	private String exportDecompiled(Function function) throws Exception {
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.setOptions(new DecompileOptions());
			if (!decompiler.openProgram(currentProgram)) {
				return null;
			}
			DecompileResults result = decompiler.decompileFunction(function, 40, monitor);
			if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
				return null;
			}
			String raw = result.getDecompiledFunction().getC();
			if (raw == null) {
				return null;
			}
			if (raw.codePointCount(0, raw.length()) > MAX_EXPORT_TEXT) {
				throw new IllegalStateException("PseudocodeTooLarge");
			}
			return raw;
		}
		finally {
			decompiler.dispose();
		}
	}

	/** xrefs: <address file offset or -1> <address> <mapped file offset or -1> <its address>: every reference to the
	 * address from an instruction in file-backed executable code. An address without file bytes is rebased like the
	 * mapped pair (Ghidra may load the file at another base). */
	private void xrefs(StringBuilder out, String[] args) throws Exception {
		Address target = located(Long.parseLong(args[2]));
		if (target == null) {
			Address base = located(Long.parseLong(args[4]));
			if (base != null) {
				long address = Long.parseUnsignedLong(args[3]);
				long delta = base.getOffset() - Long.parseUnsignedLong(args[5]);
				try {
					target = base.getAddressSpace().getAddress(address + delta);
				}
				catch (Exception e) {
					target = null;  // outside the address space: no references
				}
			}
		}
		out.append(",\"to\":").append(target == null ? "null" : Long.toString(target.getOffset()))
			.append(",\"xrefs\":");
		if (target == null) {
			out.append("{\"rows\":[],\"overflow\":false}");
		}
		else {
			appendReferencesTo(out, target, false);
		}
	}

	/** The one address a file offset maps to, or null. */
	private Address located(long offset) {
		if (offset < 0) {
			return null;
		}
		List<Address> found = memory.locateAddressesForFileOffset(offset);
		return found != null && found.size() == 1 ? found.get(0) : null;
	}

	/** File-backed, executable, non-external functions in address order. */
	private List<Function> anchoredFunctions() {
		List<Function> found = new ArrayList<>();
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			Address entry = function.getEntryPoint();
			MemoryBlock block = memory.getBlock(entry);
			if (!function.isExternal() && fileOffset(entry) >= 0 && block != null && block.isExecute() && block.isInitialized()) {
				found.add(function);
			}
		}
		return found;
	}

	/** One function row at its anchor; with edges, its calls and references too. */
	private void appendFunction(StringBuilder out, Function function, int index, boolean edges) throws Exception {
		Address entry = function.getEntryPoint();
		long size = span(function);
		out.append("{\"index\":").append(index).append(",\"name\":").append(quote(function.getName()))
			.append(",\"entry\":").append(entry.getOffset())
			.append(",\"size\":").append(size)
			.append(",\"file_offset\":").append(fileOffset(entry))
			.append(",\"anchored\":true")
			.append(",\"bytes\":").append(quote(hex(entry, memory.getBlock(entry), size)));
		if (edges) {
			out.append(",\"calls\":[");
			boolean more = appendCalls(out, function, MAX_ROWS);  // the query modes count every call (decision m3d-fix-round)
			out.append("],\"calls_overflow\":").append(more).append(",\"refs\":[");
			appendRefs(out, function);
			out.append("]");
		}
		out.append("}");
	}

	/** References to the address from instructions in file-backed executable code (calls only, tail calls included,
	 * when onlyCalls), with Ghidra's flags and the containing function; at most MAX_ROWS, else "overflow". */
	private void appendReferencesTo(StringBuilder out, Address target, boolean onlyCalls) throws Exception {
		out.append("{\"rows\":[");
		boolean first = true;
		int rows = 0;
		ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(target);
		while (references.hasNext()) {
			Reference reference = references.next();
			Address at = reference.getFromAddress();
			Instruction instruction = currentProgram.getListing().getInstructionAt(at);
			MemoryBlock block = memory.getBlock(at);
			if (instruction == null || block == null || !block.isExecute() || !block.isInitialized() || fileOffset(at) < 0) {
				continue;
			}
			RefType type = reference.getReferenceType();
			boolean call = type.isCall() || (type.isFlow() && instruction.getFlowType().isCall());
			if (onlyCalls && !call) {
				continue;
			}
			if (rows == MAX_ROWS) {
				out.append("],\"overflow\":true}");
				return;
			}
			rows++;
			Function from = getFunctionContaining(at);
			out.append(first ? "" : ",").append("{\"address\":").append(at.getOffset())
				.append(",\"length\":").append(instruction.getLength())
				.append(",\"file_offset\":").append(fileOffset(at))
				.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
				.append(",\"to\":").append(target.getOffset())
				.append(",\"from\":").append(from == null ? "null" : Long.toString(from.getEntryPoint().getOffset()))
				.append(",\"from_file_offset\":").append(from == null ? -1 : fileOffset(from.getEntryPoint()))
				.append(",\"call\":").append(call)
				.append(",\"flow\":").append(type.isFlow())
				.append(",\"jump\":").append(type.isJump())
				.append(",\"read\":").append(type.isRead())
				.append(",\"write\":").append(type.isWrite())
				.append(",\"data\":").append(type.isData()).append("}");
			first = false;
		}
		out.append("],\"overflow\":false}");
	}

	/** Instructions start..start+limit-1 of the function, counted from its entry in address order, and the count of
	 * all of them; "overflow" when there are more than MAX_BODY_INSTRUCTIONS (the worker then fails the run). */
	private void appendPage(StringBuilder out, Function function, int start, int limit) throws Exception {
		Address entry = function.getEntryPoint();
		out.append("{\"start\":").append(start).append(",\"rows\":[");
		boolean first = true;
		boolean overflow = false;
		int index = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			if (instruction.getAddress().compareTo(entry) < 0) {
				continue;
			}
			if (index == MAX_BODY_INSTRUCTIONS) {
				overflow = true;
				break;
			}
			if (index >= start && index - start < limit) {
				out.append(first ? "" : ",").append("{\"index\":").append(index)
					.append(",\"address\":").append(instruction.getAddress().getOffset())
					.append(",\"length\":").append(instruction.getLength())
					.append(",\"file_offset\":").append(fileOffset(instruction.getAddress()))
					.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
					.append(",\"text\":").append(quote(instruction.toString())).append("}");
				first = false;
			}
			index++;
		}
		out.append("],\"total\":").append(index).append(",\"overflow\":").append(overflow).append("}");
	}

	/** Decompiled C for one function within the deadline (at most 15 s), cut at MAX_TEXT; null when it fails. */
	private String decompiled(DecompInterface decompiler, Function function, long deadline) throws Exception {
		int left = (int) ((deadline - System.currentTimeMillis()) / 1000);
		if (left < 1) {
			return null;
		}
		DecompileResults result = decompiler.decompileFunction(function, Math.min(left, 15), monitor);
		if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
			return null;
		}
		String text = result.getDecompiledFunction().getC();
		return text.length() > MAX_TEXT ? text.substring(0, MAX_TEXT) : text;
	}

	/** A query string the worker passed as "x" followed by its UTF-8 bytes in hex. */
	private static String text(String encoded) {
		if (!encoded.startsWith("x") || encoded.length() % 2 != 1) {
			throw new IllegalArgumentException("ReverseAIQuery text argument");
		}
		byte[] bytes = new byte[(encoded.length() - 1) / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(encoded.substring(1 + 2 * i, 3 + 2 * i), 16);
		}
		return new String(bytes, StandardCharsets.UTF_8);
	}

	/** One row per call instruction of the function with a memory target, at most cap rows; true when there are more. */
	private boolean appendCalls(StringBuilder out, Function function, int cap) throws Exception {
		boolean first = true;
		int calls = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			if (!instruction.getFlowType().isCall()) {
				continue;
			}
			Address target = null;
			for (Address flow : instruction.getFlows()) {
				if (flow.isMemoryAddress()) {
					target = flow;
					break;
				}
			}
			if (target == null) {
				for (Reference reference : instruction.getReferencesFrom()) {
					if (reference.getToAddress().isMemoryAddress()) {
						target = reference.getToAddress();
						break;
					}
				}
			}
			if (target == null) {
				continue;
			}
			if (calls == cap) {
				return true;
			}
			calls++;
			out.append(first ? "" : ",").append("{\"address\":").append(instruction.getAddress().getOffset())
				.append(",\"length\":").append(instruction.getLength())
				.append(",\"file_offset\":").append(fileOffset(instruction.getAddress()))
				.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
				.append(",\"to\":").append(target.getOffset())
				.append(",\"to_file_offset\":").append(fileOffset(target))
				.append(",\"to_name\":").append(quote(nameAt(target))).append("}");
			first = false;
		}
		return false;
	}

	/** Every non-call memory reference from the function's instructions, with Ghidra's reference-type flags. */
	private void appendRefs(StringBuilder out, Function function) throws Exception {
		boolean first = true;
		int refs = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			for (Reference reference : instruction.getReferencesFrom()) {
				Address target = reference.getToAddress();
				RefType type = reference.getReferenceType();
				if (refs == MAX_REFS_PER_FUNCTION || !target.isMemoryAddress() || type.isCall()) {
					continue;
				}
				refs++;
				out.append(first ? "" : ",").append("{\"address\":").append(instruction.getAddress().getOffset())
					.append(",\"length\":").append(instruction.getLength())
					.append(",\"file_offset\":").append(fileOffset(instruction.getAddress()))
					.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
					.append(",\"to\":").append(target.getOffset())
					.append(",\"to_file_offset\":").append(fileOffset(target))
					.append(",\"to_name\":").append(quote(nameAt(target)))
					.append(",\"type\":").append(quote(type.getName()))
					.append(",\"flow\":").append(type.isFlow())
					.append(",\"jump\":").append(type.isJump())
					.append(",\"read\":").append(type.isRead())
					.append(",\"write\":").append(type.isWrite())
					.append(",\"data\":").append(type.isData())
					.append(",\"inside\":").append(function.getBody().contains(target)).append("}");
				first = false;
			}
		}
	}

	/** The function's instructions from its entry in address order, at most maxInstructions, and how many it has. */
	private void appendInstructions(StringBuilder out, Function function, int maxInstructions) throws Exception {
		Address entry = function.getEntryPoint();
		out.append("{\"entry\":").append(entry.getOffset()).append(",\"instructions\":[");
		boolean first = true;
		int listed = 0;
		int count = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			if (count == MAX_BODY_INSTRUCTIONS) {
				break;
			}
			count++;
			if (listed == maxInstructions || instruction.getAddress().compareTo(entry) < 0) {
				continue;
			}
			listed++;
			out.append(first ? "" : ",").append("{\"address\":").append(instruction.getAddress().getOffset())
				.append(",\"length\":").append(instruction.getLength())
				.append(",\"file_offset\":").append(fileOffset(instruction.getAddress()))
				.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
				.append(",\"text\":").append(quote(instruction.toString())).append("}");
			first = false;
		}
		out.append("],\"count\":").append(count).append("}");
	}

	/** Entry to the last byte of the body: a body with gaps keeps the calls in its later ranges. */
	private static long span(Function function) {
		Address entry = function.getEntryPoint();
		Address last = function.getBody().getMaxAddress();
		return last == null || last.compareTo(entry) < 0 ? 1 : last.subtract(entry) + 1;
	}

	private String nameAt(Address address) {
		Function function = getFunctionAt(address);
		if (function != null) {
			return function.getName();
		}
		Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
		return symbol == null ? "" : symbol.getName();
	}

	private long fileOffset(Address address) {
		AddressSourceInfo info = memory.getAddressSourceInfo(address);
		return info == null ? -1 : info.getFileOffset();
	}

	private long blockFileOffset(MemoryBlock block) {
		List<MemoryBlockSourceInfo> sources = block.getSourceInfos();
		if (sources.size() != 1 || sources.get(0).getFileBytes().isEmpty() || sources.get(0).getLength() != block.getSize()) {
			return -1;
		}
		return sources.get(0).getFileBytesOffset();
	}

	private String hex(Address entry, MemoryBlock block, long size) throws Exception {
		if (block == null || !block.isInitialized()) {
			return "";
		}
		long left = block.getEnd().subtract(entry) + 1;
		byte[] bytes = new byte[(int) Math.max(0, Math.min(Math.min(size, MAX_LOCATION), left))];
		memory.getBytes(entry, bytes);
		return toHex(bytes);
	}

	private static String toHex(byte[] bytes) {
		StringBuilder text = new StringBuilder(bytes.length * 2);
		for (byte value : bytes) {
			text.append(String.format("%02x", value & 0xff));
		}
		return text.toString();
	}

	private static String quote(String value) {
		StringBuilder text = new StringBuilder("\"");
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c == '"' || c == '\\') {
				text.append('\\').append(c);
			}
			else if (c < 0x20 || c > 0x7e) {
				text.append(String.format("\\u%04x", (int) c));
			}
			else {
				text.append(c);
			}
		}
		return text.append('"').toString();
	}
}
