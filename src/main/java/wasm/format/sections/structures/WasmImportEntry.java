package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.WasmEnums.WasmExternalKind;

public class WasmImportEntry implements StructConverter {
	
	Leb128 module_len;
	String module_str;
	Leb128 field_len;
	String field_str;
	WasmExternalKind kind;
	
	Leb128 function_type;
	WasmResizableLimits memory_type;
	WasmTableType table_type;
	WasmGlobalType global_type;
	
	public WasmImportEntry (BinaryReader reader) throws IOException {
		module_len = new Leb128(reader);
		module_str = reader.readNextAsciiString(module_len.getValue());
		field_len = new Leb128(reader);
		field_str = reader.readNextAsciiString(field_len.getValue());
		kind = WasmExternalKind.values()[reader.readNextByte()];
		switch(kind) {
			case EXT_FUNCTION:
				function_type = new Leb128(reader);
				break;
			case EXT_MEMORY:
				memory_type = new WasmResizableLimits(reader);
				break;
			case EXT_GLOBAL:
				global_type = new WasmGlobalType(reader);
				break;
			case EXT_TABLE:
				table_type = new WasmTableType(reader);
				break;
			default:
				break;
		
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("import_" + module_str + "_" + field_str, 0);
		structure.add(module_len.toDataType(), module_len.toDataType().getLength(), "module_len", null);
		structure.add(STRING, module_str.length(), "module_name", null);
		structure.add(field_len.toDataType(), field_len.toDataType().getLength(), "field_len", null);
		structure.add(STRING, field_str.length(), "field_name", null);
		structure.add(BYTE, 1, "kind", null);
		switch(kind) {
			case EXT_FUNCTION:
				structure.add(function_type.toDataType(), function_type.toDataType().getLength(), "type", null);
				break;
			case EXT_MEMORY:
				structure.add(memory_type.toDataType(), memory_type.toDataType().getLength(), "type", null);				
				break;
			case EXT_GLOBAL:
				structure.add(global_type.toDataType(), global_type.toDataType().getLength(), "type", null);
				break;
			case EXT_TABLE:
				structure.add(table_type.toDataType(), table_type.toDataType().getLength(), "type", null);				
				break;
			default:
				break;
		}
		return structure;
	}

}
