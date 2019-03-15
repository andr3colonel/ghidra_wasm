package wasm.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.sections.WasmSection;

public class WasmHeader implements StructConverter {

	private byte[] magic;
	private int version;
	
	
	public WasmHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextByteArray( WasmConstants.WASM_MAGIC_BASE.length() );
		version = reader.readNextInt();
		if (!WasmConstants.WASM_MAGIC_BASE.equals(new String(magic))) {
			throw new IOException("not a wasm file.");
		}
	}

	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		structure.add(STRING, 4, "magic", null);
		structure.add(DWORD, 4, "version", null);
		return structure;
	}

	public byte[] getMagic() {
		return magic;
	}

	public int getVersion( ) {
		return version;
	}
	

}
