package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.sections.WasmSection.WasmSectionId;

public class WasmExportEntry implements StructConverter {
	
	Leb128 field_len;
	String name;
	WasmExternalKind kind;
	Leb128 index;
	
	
	public enum WasmExternalKind {
		KIND_FUNCTION,
		KIND_TABLE,
		KIND_MEMORY,
		KIND_GLOBAL
	}


	public WasmExportEntry (BinaryReader reader) throws IOException {
		field_len = new Leb128(reader);
		name = reader.readNextAsciiString(field_len.getValue());
		kind = WasmExternalKind.values()[reader.readNextByte()]; 
		index = new Leb128(reader);
	}
	
	public String getName() {
		return name;
	}
	
	public int getIndex() {
		return index.getValue();
	}
	
	public WasmExternalKind getType() {
		return kind;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("export_" + index, 0);
		structure.add(field_len.toDataType(), field_len.toDataType().getLength(), "field_len", null);
		structure.add(STRING, name.length(), "name", null);
		structure.add(BYTE, 1, "kind", null);
		structure.add(index.toDataType(), index.toDataType().getLength(), "index", null);
		return structure;
	}

	

}
