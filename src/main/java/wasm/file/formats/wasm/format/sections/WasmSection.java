package wasm.file.formats.wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.file.formats.wasm.format.Leb128;

public class WasmSection implements StructConverter {
	
	private WasmSectionId id;
	private int payload_len;
	private StructConverter payload;
	private long payload_offset;

	public enum WasmSectionId {
		SEC_UNKNOWN,
		SEC_TYPE,
		SEC_IMPORT,
		SEC_FUNCTION,
		SEC_TABLE,
		SEC_LINEARMEMORY,
		SEC_GLOBAL,
		SEC_EXPORT,
		SEC_START,
		SEC_ELEMENT,
		SEC_CODE,
		SEC_DATA
	}
	
	private static StructConverter sectionsFactory(BinaryReader reader, WasmSectionId id) throws IOException {
		switch (id) {
			case SEC_UNKNOWN:
				return null;
			case SEC_TYPE:
				return new WasmTypeSection(reader);
			case SEC_IMPORT:
				return new WasmImportSection(reader);
			case SEC_FUNCTION:
				return new WasmFunctionSection(reader);
			case SEC_TABLE:
				return new WasmTableSection(reader);
			case SEC_LINEARMEMORY:
				return new WasmLinearMemorySection(reader);
			case SEC_GLOBAL:
				return new WasmGlobalSection(reader);
			case SEC_EXPORT:
				return new WasmExportSection(reader);
			case SEC_START:
				return new WasmStartSection(reader);
			case SEC_ELEMENT:
				return new WasmElementSection(reader);
			case SEC_CODE:
				return new WasmCodeSection(reader);
			case SEC_DATA:
				return new WasmDataSection(reader);
			default:
				return null;
		}
	}
	
	public WasmSection(BinaryReader reader) throws IOException {
		this.id = WasmSectionId.values()[Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ))];
		int len = Leb128.unsignedLeb128Size(this.id.ordinal());// consume leb...
		reader.readNextByteArray(len);// consume leb...

		this.payload_len = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
		len = Leb128.unsignedLeb128Size(this.payload_len);
		reader.readNextByteArray(len);// consume leb...
		
		payload_offset = reader.getPointerIndex();
		
		byte payload_buf[] = reader.readNextByteArray(this.payload_len);

		this.payload = sectionsFactory(new BinaryReader(new ByteArrayProvider(payload_buf), true), id);
	}

	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
			return null;
	}
	
	public WasmSectionId getId() {
		return id;
	}
	
	public StructConverter getPayload() {
		return payload;
	}
	
	public long getPayloadOffset() {
		return payload_offset;
	}
}
