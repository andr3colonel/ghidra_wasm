package wasm.format.sections;

import ghidra.program.model.data.Structure;

abstract public class WasmPayload {
	abstract public void deserializePayload(byte[] payload);
	abstract public void fillPayloadStruct(Structure structure);
	abstract public String getName();	
}
