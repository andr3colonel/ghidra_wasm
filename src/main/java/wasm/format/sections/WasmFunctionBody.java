package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;

public class WasmFunctionBody implements StructConverter {

	private int body_size;
	private List<WasmLocalEntry> locals = new ArrayList<WasmLocalEntry>();
	private int local_count;
	private long instructions_offset;
	private byte[] instructions;
	
	public WasmFunctionBody (BinaryReader reader) throws IOException {
		body_size = Leb128.read_int(reader);
		int body_start_offset = (int) reader.getPointerIndex();
		local_count = Leb128.read_int(reader);
		for (int i = 0; i < local_count; ++i) {
			locals.add(new WasmLocalEntry(reader));
		}
		instructions_offset = reader.getPointerIndex();
		instructions = reader.readNextByteArray((int) (body_start_offset + body_size - instructions_offset));
	}


	public long getOffset() {
		return instructions_offset;
	}
	
	public byte[] getInstructions() {
		return instructions;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}

}
