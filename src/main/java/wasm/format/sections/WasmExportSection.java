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

public class WasmExportSection implements WasmPayload {

	private Leb128 count;
	private List<WasmExportEntry> exports = new ArrayList<WasmExportEntry>();
	
	public WasmExportSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			exports.add(new WasmExportEntry(reader));
		}		
	}


	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ExportSection", 0);
		structure.add(count.toDataType(), count.toDataType().getLength(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(exports.get(i).toDataType(), exports.get(i).toDataType().getLength(), "export_"+i, null);
		}		
		return structure;
	}

	@Override
	public String getName() {
		return ".export";
	}

}
