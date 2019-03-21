package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;

public class WasmElementSegment implements StructConverter {

	private Leb128 index;
	private byte init_opcode;
	private short offset;
	private Leb128 size;
	private List<Leb128> data = new ArrayList<Leb128>();

	public WasmElementSegment(BinaryReader reader) throws IOException {
		index = new Leb128(reader);
		init_opcode = reader.readNextByte();
		offset = reader.readNextShort();
		size = new Leb128(reader);
		for (int i = 0; i < size.getValue(); i++) {
			data.add(new Leb128(reader));			
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("data_segment_" + index.getValue(), 0);
		structure.add(index.toDataType(), index.toDataType().getLength(), "index", null);
		structure.add(BYTE, 1, "init_opcode", null);
		structure.add(WORD, 2, "offset", null);
		structure.add(size.toDataType(), size.toDataType().getLength(), "size", null);
		for (int i = 0; i < size.getValue(); i++) {
			structure.add(data.get(i).toDataType(), data.get(i).toDataType().getLength(), "element_" + i, null);			
		}
		return structure;
	}
}
