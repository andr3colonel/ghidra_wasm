package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;

public class WasmResizableLimits implements StructConverter {

	byte flags;
	Leb128 initial;
	Leb128 maximum;
	
	public WasmResizableLimits  (BinaryReader reader) throws IOException {
		flags = reader.readNextByte();
		initial = new Leb128(reader);
		if (flags == 1) {
			maximum = new Leb128(reader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("global", 0);
		structure.add(BYTE, 1, "flags", null);
		structure.add(initial.toDataType(), initial.toDataType().getLength(), "mutability", null);
		if (flags == 1) {
			structure.add(maximum.toDataType(), maximum.toDataType().getLength(), "maximum", null);
		}
		return structure;
	}


}
