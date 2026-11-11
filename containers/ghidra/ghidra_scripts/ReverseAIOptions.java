// ReverseAI's fixed analysis options (pre-script; reviewed code baked into the image, never chosen by a request).
// Turns off every boolean analysis option whose name says PDB, DWARF or Swift: PDB symbol loading (symbol servers,
// local symbol files), DWARF (external debug files) and the Swift demangler, with their sub-options. Ghidra offers
// an analyzer only for programs it can analyze, so the rule is by name, not a fixed list; ReverseAIQuery reports
// the final values and the worker refuses the run if any of them is still on.
//@category ReverseAI

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;

public class ReverseAIOptions extends GhidraScript {
	static final Pattern OFF = Pattern.compile("(?i).*(pdb|dwarf|swift).*");
	private static final Set<String> FORMATS = Set.of("Executable and Linking Format (ELF)", "Portable Executable (PE)",
		"Mac OS X Mach-O");

	@Override
	public void run() throws Exception {
		if (!FORMATS.contains(currentProgram.getExecutableFormat())) {
			throw new IllegalStateException("UnsupportedFormat");
		}
		for (Map.Entry<String, String> option : getCurrentAnalysisOptionsAndValues(currentProgram).entrySet()) {
			String value = option.getValue();
			if (OFF.matcher(option.getKey()).matches() && ("true".equals(value) || "false".equals(value))) {
				setAnalysisOption(currentProgram, option.getKey(), "false");
			}
		}
	}
}
