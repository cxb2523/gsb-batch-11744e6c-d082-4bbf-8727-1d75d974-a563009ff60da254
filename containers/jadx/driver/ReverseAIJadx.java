import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import jadx.api.CommentsLevel;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.loader.JadxPluginLoader;
import jadx.core.dex.nodes.MethodNode;
import jadx.plugins.input.dex.DexInputPlugin;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * ReverseAI's fixed JADX driver (decision m4b-w-plan): the worker is its only caller.
 *
 * One JSON request on stdin: {"dex": [paths of the re-materialized DEX members], "targets": [{"dex": index, "class":
 * raw descriptor, "method": raw name, "prototype": raw "(params)return"}], "start", "max_chars"}. One JSON reply on
 * stdout: {"targets": [{"target", "status", "code_offset", "insns_count", "total", "text"}]} in target order. JADX loads
 * only those DEX files with its DEX input plugin, one thread, no resources, no deobfuscation or renames, comments at
 * WARN (no paths). A method's text is JADX's text for it without the enclosing class declaration line, every UTF-16
 * unit outside printable ASCII, newline and tab written as a Java \\uXXXX escape; total and the page count characters
 * of that escaped text. Status: fallback when JADX's text carries its error or inconsistent-code comment, omitted when
 * JADX prints no text for a method with code (default constructors and other methods it does not generate, decision
 * m4b-omitted), decompile_failed when it throws. Library logging goes to stderr, never to the reply.
 */
public final class ReverseAIJadx {
	private static final String OK = "ok";
	private static final String FALLBACK = "fallback";
	private static final String FAILED = "decompile_failed";
	/**
	 * JADX 1.5.6 drops a method's attributes once its class is generated, so a failure is read from the text: its own
	 * comment lines for an error or for code it could not make consistent, which open a line (a string constant in
	 * the code cannot start one).
	 */
	private static final Pattern FALLBACK_MARK = Pattern.compile(
			"(?m)^[ \\t]*/\\*\\s*(JADX ERROR:|Code decompiled incorrectly, please refer to instructions dump\\.)");

	private ReverseAIJadx() {
	}

	public static void main(String[] argv) throws Exception {
		PrintStream reply = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
		System.setOut(System.err);
		JsonObject request = JsonParser.parseReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).getAsJsonObject();
		Gson gson = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
		reply.println(gson.toJson(run(request)));
	}

	private static JsonObject run(JsonObject request) {
		List<File> files = new ArrayList<>();
		for (JsonElement path : request.getAsJsonArray("dex")) {
			files.add(new File(path.getAsString()));
		}
		int start = request.get("start").getAsInt();
		int maxChars = request.get("max_chars").getAsInt();
		JsonArray targets = request.getAsJsonArray("targets");
		JsonArray rows = new JsonArray();
		try (JadxDecompiler jadx = new JadxDecompiler(arguments(files))) {
			boolean loaded;
			try {
				jadx.load();
				loaded = true;
			} catch (Exception e) {
				loaded = false;
			}
			Map<String, JavaClass> classes = new HashMap<>();
			if (loaded) {
				for (JavaClass cls : jadx.getClassesWithInners()) {
					classes.put(cls.getRawName(), cls);
				}
			}
			for (int index = 0; index < targets.size(); index++) {
				JsonObject target = targets.get(index).getAsJsonObject();
				rows.add(loaded ? decompile(index, target, files, classes, start, maxChars) : row(index, FAILED, null, "", 0));
			}
		}
		JsonObject result = new JsonObject();
		result.add("targets", rows);
		return result;
	}

	private static JadxArgs arguments(List<File> files) {
		JadxArgs args = new JadxArgs();
		args.setInputFiles(files);
		args.setSkipResources(true);
		args.setThreadsCount(1);
		args.setDeobfuscationOn(false);
		args.setRenameFlags(EnumSet.noneOf(JadxArgs.RenameEnum.class));
		args.setCommentsLevel(CommentsLevel.WARN);
		args.setPluginLoader(new JadxPluginLoader() {
			@Override
			public List<JadxPlugin> load() {
				return List.of(new DexInputPlugin());
			}

			@Override
			public void close() {
			}
		});
		return args;
	}

	private static JsonObject decompile(int index, JsonObject target, List<File> files, Map<String, JavaClass> classes,
			int start, int maxChars) {
		String descriptor = target.get("class").getAsString();
		File file = files.get(target.get("dex").getAsInt());
		JavaClass cls = descriptor.length() > 2 && descriptor.startsWith("L") && descriptor.endsWith(";")
				? classes.get(descriptor.substring(1, descriptor.length() - 1).replace('/', '.')) : null;
		if (cls == null || !file.getPath().equals(cls.getClassNode().getInputFileName())) {
			return row(index, "class_not_found", null, "", 0);
		}
		String shortId = target.get("method").getAsString() + target.get("prototype").getAsString();
		JavaMethod method = null;
		for (JavaMethod candidate : cls.getMethods()) {
			if (candidate.getMethodNode().getMethodInfo().getShortId().equals(shortId)) {
				method = candidate;
			}
		}
		if (method == null) {
			return row(index, "method_not_found", null, "", 0);
		}
		MethodNode node = method.getMethodNode();
		if (node.isNoCode() || node.getInsnsCount() == 0) {
			return row(index, "no_code", null, "", 0);
		}
		String text;
		try {
			text = withoutClassLine(method.getCodeStr(), cls);
		} catch (Exception e) {
			return row(index, FAILED, null, "", 0);
		}
		if (text.isEmpty()) {
			return row(index, "omitted", null, "", 0);
		}
		boolean fallback = FALLBACK_MARK.matcher(text).find();
		String escaped = escape(text);
		int from = Math.min(start, escaped.length());
		String page = escaped.substring(from, Math.min(escaped.length(), from + maxChars));
		return row(index, fallback ? FALLBACK : OK, node, page, escaped.length());
	}

	/** JADX prints a class's declaration line before the class's first method: it is not the method's text. */
	private static String withoutClassLine(String code, JavaClass cls) {
		String classCode = cls.getTopParentClass().getCode();
		int at = Math.max(0, Math.min(cls.getDefPos(), classCode.length()));
		int lineStart = classCode.lastIndexOf('\n', at - 1) + 1;
		int lineEnd = classCode.indexOf('\n', at);
		String declaration = classCode.substring(lineStart, lineEnd < 0 ? classCode.length() : lineEnd + 1);
		int found = declaration.isBlank() ? -1 : code.indexOf(declaration);
		return found < 0 ? code : code.substring(found + declaration.length());
	}

	static String escape(String text) {
		StringBuilder out = new StringBuilder(text.length());
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (c == '\n' || c == '\t' || (c >= 0x20 && c <= 0x7e)) {
				out.append(c);
			} else {
				out.append(String.format("\\u%04x", (int) c));
			}
		}
		return out.toString();
	}

	private static JsonObject row(int index, String status, MethodNode node, String text, int total) {
		JsonObject row = new JsonObject();
		row.addProperty("target", index);
		row.addProperty("status", status);
		boolean anchored = node != null && (OK.equals(status) || FALLBACK.equals(status));
		row.add("code_offset", anchored ? new JsonPrimitive(node.getMethodCodeOffset()) : JsonNull.INSTANCE);
		row.add("insns_count", anchored ? new JsonPrimitive(node.getInsnsCount()) : JsonNull.INSTANCE);
		row.addProperty("total", total);
		row.addProperty("text", text);
		return row;
	}
}
