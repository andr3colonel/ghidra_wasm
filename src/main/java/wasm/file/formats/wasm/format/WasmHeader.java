package wasm.file.formats.wasm.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmHeader implements StructConverter {

	private byte[] magic;
	private byte [] version;

	public WasmHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextByteArray( WasmConstants.WASM_MAGIC_BASE.length() );
		version = reader.readNextByteArray( WasmConstants.WASM_VERSION_LENGTH);
		if (!WasmConstants.WASM_MAGIC_BASE.equals(new String(magic))) {
			throw new IOException("not a wasm file.");
		}
		
	}

	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		structure.add(UTF8, 8, "magic", null);

		return structure;
	}

	public byte[] getMagic() {
		return magic;
	}

	public byte [] getVersion( ) {
		return version;
	}

}
