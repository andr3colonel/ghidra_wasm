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

public class WasmDataSegment implements StructConverter {

	private Leb128 index;
	private int offset;
	private Leb128 size;
	private byte[] data;

	public WasmDataSegment(BinaryReader reader) throws IOException {
		index = new Leb128(reader);
		offset = reader.readNextInt();
		size = new Leb128(reader);
		data = reader.readNextByteArray(size.getValue());
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("data_segment_" + index.getValue(), 0);
		structure.add(index.toDataType(), index.toDataType().getLength(), "index", null);
		structure.add(DWORD, 4, "offset", null);
		structure.add(size.toDataType(), size.toDataType().getLength(), "size", null);
		structure.add(new ArrayDataType(BYTE, data.length, BYTE.getLength()), "data", null);
		return structure;
	}

}
