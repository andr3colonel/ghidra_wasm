package wasm.file;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.WasmConstants;
import wasm.format.WasmHeader;
import wasm.format.sections.WasmSection;

public class WasmModule implements StructConverter {
	
	private WasmHeader header;
	private List<WasmSection> sections = new ArrayList<WasmSection>();
	
	public WasmModule(BinaryReader reader) throws IOException {
		header = new WasmHeader(reader);
		while (reader.getPointerIndex() < reader.length()) {
			sections.add(new WasmSection(reader));
		}
	}

	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}
	
	public WasmHeader getHeader() {
		return header;
	}
	
	public List<WasmSection> getSections() {
		return sections;
	}
}
