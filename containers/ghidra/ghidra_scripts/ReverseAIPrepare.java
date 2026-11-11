// Fixed prepare exporter: input is analyzed, never executed. Tables are streamed before the completion marker.
//@category ReverseAI

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class ReverseAIPrepare extends HeadlessScript {
	private static final int MAX_FUNCTIONS = 65536;
	private static final int MAX_CALLS = 262144;
	private static final int MAX_REFERENCES = 262144;
	private static final int MAX_FUNCTION_VISITS = 1000000;
	private static final long MAX_INSTRUCTION_VISITS = 8388608;
	private static final int MAX_RAW_ROW_BYTES = 16384;
	private static final Pattern OFF = Pattern.compile("(?i).*(pdb|dwarf|swift).*");
	private Memory memory;
	private long visits;
	private int calls;
	private int references;

	@Override
	public void run() throws Exception {
		// A post-script failure must also prevent HeadlessAnalyzer from saving partial analysis.
		setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("ReverseAIPrepare arguments");
		}
		requireComplete();
		memory = currentProgram.getMemory();
		Path folder = Path.of(args[0]);
		try (BufferedWriter functions = writer(folder.resolve("functions.jsonl"));
			 BufferedWriter callRows = writer(folder.resolve("calls.jsonl"));
			 BufferedWriter referenceRows = writer(folder.resolve("references.jsonl"))) {
			int count = 0;
			for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
				monitor.checkCancelled();
				if (function.isExternal() || uniqueFileOffset(function.getEntryPoint(), 1) < 0) {
					continue;
				}
				if (count == MAX_FUNCTIONS) {
					throw new IllegalStateException("TooManyRows");
				}
				int assemblyTotal = instructions(function, callRows, referenceRows);
				writeRow(functions, functionRow(function, count, assemblyTotal));
				count++;
			}
		}
		requireComplete();
		// Header is the sole completion marker, created only after every table was closed successfully.
		try (BufferedWriter header = writer(folder.resolve("header.json"))) {
			header.write(header().append(",\"complete\":true}\n").toString());
		}
		setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
	}

	private void requireComplete() throws Exception {
		monitor.checkCancelled();
		if (analysisTimeoutOccurred() || AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()
				|| !currentProgram.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED_OPTION_NAME, false)) {
			throw new IllegalStateException("IncompleteAnalysis");
		}
	}

	private static BufferedWriter writer(Path path) throws Exception {
		return Files.newBufferedWriter(path, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
	}

	private static void writeRow(BufferedWriter writer, StringBuilder row) throws Exception {
		String value = row.append('\n').toString();
		if (value.getBytes(StandardCharsets.UTF_8).length > MAX_RAW_ROW_BYTES) {
			throw new IllegalStateException("RowTooLarge");
		}
		writer.write(value);
	}

	/** Exactly one instruction traversal produces the assembly total and both edge tables. */
	private int instructions(Function function, BufferedWriter callRows, BufferedWriter referenceRows) throws Exception {
		int functionVisits = 0;
		int assemblyTotal = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
			monitor.checkCancelled();
			if (++functionVisits > MAX_FUNCTION_VISITS || ++visits > MAX_INSTRUCTION_VISITS) {
				throw new IllegalStateException("TooManyRows");
			}
			Address at = instruction.getAddress();
			int length = instruction.getLength();
			if (at.compareTo(function.getEntryPoint()) < 0 || length < 1 || length > 16
					|| length > span(function) - at.subtract(function.getEntryPoint()) || uniqueFileOffset(at, length) < 0) {
				continue;
			}
			assemblyTotal++;
			if (instruction.getFlowType().isCall()) {
				Address target = callTarget(instruction);
				if (target != null) {
					if (calls == MAX_CALLS) {
						throw new IllegalStateException("TooManyRows");
					}
					writeRow(callRows, edgeRow(function, instruction, target).append("}"));
					calls++;
				}
			}
			// An instruction can expose the same relationship through several operands. Keep one contract key.
			TreeMap<ReferenceKey, Reference> sorted = new TreeMap<>();
			for (Reference reference : instruction.getReferencesFrom()) {
				Address target = reference.getToAddress();
				RefType type = reference.getReferenceType();
				if (!target.isMemoryAddress() || type.isCall()) {
					continue;
				}
				String kind = referenceKind(type, function.getBody().contains(target));
				if (kind == null) {
					continue;
				}
				sorted.putIfAbsent(new ReferenceKey(target.getOffset(), kind), reference);
				if ((long) references + sorted.size() > MAX_REFERENCES) {
					throw new IllegalStateException("TooManyRows");
				}
			}
			for (Reference reference : sorted.values()) {
				Address target = reference.getToAddress();
				RefType type = reference.getReferenceType();
				writeRow(referenceRows, edgeRow(function, instruction, target)
					.append(",\"type\":").append(quote(type.getName()))
					.append(",\"flow\":").append(type.isFlow()).append(",\"jump\":").append(type.isJump())
					.append(",\"read\":").append(type.isRead()).append(",\"write\":").append(type.isWrite())
					.append(",\"data\":").append(type.isData())
					.append(",\"inside\":").append(function.getBody().contains(target)).append("}"));
				references++;
			}
		}
		return assemblyTotal;
	}

	private static final class ReferenceKey implements Comparable<ReferenceKey> {
		private final long target;
		private final String kind;
		ReferenceKey(long target, String kind) {
			this.target = target;
			this.kind = kind;
		}
		@Override
		public int compareTo(ReferenceKey other) {
			int address = Long.compareUnsigned(target, other.target);
			return address == 0 ? kind.compareTo(other.kind) : address;
		}
	}

	private static String referenceKind(RefType type, boolean inside) {
		if (type.isFlow()) {
			return type.isJump() && !inside ? "jump" : null;
		}
		return type.isRead() ? (type.isWrite() ? "read_write" : "read")
			: type.isWrite() ? "write" : type.isData() ? "data" : null;
	}

	private static Address callTarget(Instruction instruction) {
		for (Address target : instruction.getFlows()) {
			if (target.isMemoryAddress()) {
				return target;
			}
		}
		for (Reference reference : instruction.getReferencesFrom()) {
			if (reference.getToAddress().isMemoryAddress()) {
				return reference.getToAddress();
			}
		}
		return null;
	}

	private StringBuilder functionRow(Function function, int index, int assemblyTotal) throws Exception {
		Address entry = function.getEntryPoint();
		String signature = function.getPrototypeString(false, false);
		return new StringBuilder("{\"index\":").append(index).append(",\"name\":").append(quote(function.getName()))
			.append(",\"entry\":").append(entry.getOffset()).append(",\"size\":").append(span(function))
			.append(",\"file_offset\":").append(fileOffset(entry)).append(",\"anchored\":true")
			.append(",\"bytes\":").append(quote(hex(entry, memory.getBlock(entry), span(function))))
			.append(",\"signature\":").append(signature == null ? "null" : quote(signature))
			.append(",\"assembly_total\":").append(assemblyTotal).append("}");
	}

	private StringBuilder edgeRow(Function function, Instruction instruction, Address target) throws Exception {
		return new StringBuilder("{\"from\":").append(function.getEntryPoint().getOffset())
			.append(",\"address\":").append(instruction.getAddress().getOffset())
			.append(",\"length\":").append(instruction.getLength())
			.append(",\"file_offset\":").append(fileOffset(instruction.getAddress()))
			.append(",\"bytes\":").append(quote(toHex(instruction.getBytes())))
			.append(",\"to\":").append(target.getOffset()).append(",\"to_file_offset\":").append(fileOffset(target))
			.append(",\"to_name\":").append(quote(nameAt(target)));
	}

	/** Every byte must have exactly one executable, contiguous file mapping. Also used by export queries. */
	private long uniqueFileOffset(Address at, int length) {
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
				continue;
			}
			out.append(first ? "" : ",").append("{\"name\":").append(quote(block.getName()))
				.append(",\"start\":").append(block.getStart().getOffset()).append(",\"size\":").append(block.getSize())
				.append(",\"execute\":").append(block.isExecute()).append(",\"initialized\":").append(block.isInitialized())
				.append(",\"file_offset\":").append(blockFileOffset(block)).append("}");
			first = false;
		}
		return out.append("]");
	}

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
		long left = block.getEnd().subtract(entry) + 1;
		byte[] bytes = new byte[(int) Math.max(0, Math.min(Math.min(size, 4096), left))];
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
		for (int index = 0; index < value.length(); index++) {
			char c = value.charAt(index);
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
