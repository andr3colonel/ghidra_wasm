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
import wasm.format.sections.structures.WasmElementSegment;
import wasm.format.sections.structures.WasmExportEntry;

public class WasmElementSection extends WasmPayload {

	private Leb128 count;
	private List<WasmElementSegment> elements = new ArrayList<WasmElementSegment>();
	
	public WasmElementSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			elements.add(new WasmElementSegment(reader));
		}		
	}


	@Override
	public void fillPayloadStruct(Structure structure) throws DuplicateNameException, IOException {
		structure.add(count.getType(), count.getSize(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(elements.get(i).toDataType(), elements.get(i).toDataType().getLength(), "element_"+i, null);
		}		
	}

	@Override
	public String getName() {
		return ".element";
	}


}
