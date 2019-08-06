package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmImportSection implements WasmPayload {

	private Leb128 count;
	private List<WasmImportEntry> imports = new ArrayList<WasmImportEntry>();

	public WasmImportSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			imports.add(new WasmImportEntry(reader));
		}
	}

	public int getCount() {
		return count.getValue();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ImportsSection", 0);
		structure.add(count.toDataType(), count.toDataType().getLength(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(imports.get(i).toDataType(), imports.get(i).toDataType().getLength(), "import_"+i, null);
		}
		return structure;
	}

	@Override
	public String getName() {
		return ".import";
	}
}
