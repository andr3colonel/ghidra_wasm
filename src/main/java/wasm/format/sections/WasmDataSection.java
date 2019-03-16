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
import wasm.format.sections.structures.WasmDataSegment;

public class WasmDataSection extends WasmPayload {

	
	private Leb128 count;
	private List<WasmDataSegment> dataSegments = new ArrayList<WasmDataSegment>();

	public WasmDataSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			dataSegments.add(new WasmDataSegment(reader));
		}

	}

	@Override
	public void fillPayloadStruct(Structure structure) throws DuplicateNameException, IOException {
		structure.add(count.getType(), count.getSize(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(dataSegments.get(i).toDataType(), dataSegments.get(i).toDataType().getLength(), "segment_"+i, null);
		}
	}

	@Override
	public String getName() {
		return ".data";
	}


}
