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

public class WasmExportEntry implements StructConverter {
	
	Leb128 field_len;
	String name;
	byte kind;
	Leb128 index;
	
	public WasmExportEntry (BinaryReader reader) throws IOException {
		field_len = new Leb128(reader);
		name = reader.readNextAsciiString(field_len.getValue());
		kind = reader.readNextByte();
		index = new Leb128(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("export_" + index, 0);
		structure.add(field_len.getType(), field_len.getSize(), "field_len", null);
		structure.add(STRING, name.length(), "name", null);
		structure.add(BYTE, 1, "kind", null);
		structure.add(index.getType(), index.getSize(), "index", null);
		return structure;
	}

	

}
