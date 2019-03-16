/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wasm;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import wasm.file.WasmModule;
import wasm.format.Utils;
import wasm.format.WasmConstants;
import wasm.format.WasmHeader;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmLocalEntry.WasmLocalType;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class WasmLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "WebAssembly";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
			WasmHeader header = new WasmHeader(reader);
			if (WasmConstants.WASM_MAGIC_BASE.equals(new String(header.getMagic()))) {
				List<QueryResult> queries =
					QueryOpinionService.query(getName(), WasmConstants.MACHINE, null);
				for (QueryResult result : queries) {
					loadSpecs.add(new LoadSpec(this, 0, result));
					loadSpecs.add(new LoadSpec(this, 0, result));
					loadSpecs.add(new LoadSpec(this, 0, result));
					loadSpecs.add(new LoadSpec(this, 0, result));
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
		return loadSpecs;
	}
	
	
	private void createMethodByteCodeBlock(Program program, long length, TaskMonitor monitor) throws Exception {
		Address address = Utils.toAddr( program, Utils.METHOD_ADDRESS );
		MemoryBlock block = program.getMemory( ).createInitializedBlock( "method_bytecode", address, length, (byte) 0xff, monitor, false );
		block.setRead( true );
		block.setWrite( false );
		block.setExecute( true );
	}

	private void createMethodLookupMemoryBlock(Program program, TaskMonitor monitor) throws Exception {
		Address address = Utils.toAddr( program, Utils.LOOKUP_ADDRESS );
		MemoryBlock block = program.getMemory( ).createInitializedBlock( "method_lookup", address, Utils.MAX_METHOD_LENGTH, (byte) 0xff, monitor, false );
		block.setRead( true );
		block.setWrite( false );
		block.setExecute( false );
	}

	private MemoryBlockUtil mbu; 
	
	
	public Data createData(Program program, Listing listing, Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "ELF data markup conflict at " + address);
		}
		catch (DataTypeConflictException e) {
			Msg.error(this, "ELF data type markup conflict:" + e.getMessage());
		}
		return null;
	}
	
	private void markupHeader(Program program, WasmHeader header, TaskMonitor monitor, InputStream reader) throws DuplicateNameException, IOException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "Wasm Header";
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress( 0x0 );
		try {
			mbu.createInitializedBlock(".header", start, reader, 8, "", BLOCK_SOURCE_NAME, r, w, x, monitor);
			createData(program, program.getListing(), start, header.toDataType());
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void markupSections(Program program, WasmModule module, TaskMonitor monitor, InputStream reader) throws DuplicateNameException, IOException, AddressOverflowException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "Wasm Section";
		for (WasmSection section: module.getSections()) {
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(section.getSectionOffset());
			mbu.createInitializedBlock(section.getPayload().getName(), start, reader, section.getSectionSize(), "", BLOCK_SOURCE_NAME, r, w, x, monitor);
			createData(program, program.getListing(), start, section.toDataType());			
		}
	}

	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
		Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
		throws CancelledException, IOException {
	
		monitor.setMessage( "Wasm Loader: Start loading" );
		
		try {
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress( 0x0 );
			long length = provider.length();
	
			InputStream inputStream;
			inputStream = provider.getInputStream(0);
			mbu = new MemoryBlockUtil(program, handler);

			
			BinaryReader reader = new BinaryReader( provider, true );
			WasmModule module = new WasmModule( reader );
	
			createMethodLookupMemoryBlock( program, monitor );
			createMethodByteCodeBlock( program, length, monitor);
			markupHeader(program, module.getHeader(), monitor, inputStream);
			markupSections(program, module, monitor, inputStream);
			monitor.setMessage( "Wasm Loader: Create byte code" );
			
			for (WasmSection section: module.getSections()) {
				monitor.setMessage("Loaded " + section.getId().toString());
				if (section.getId() == WasmSectionId.SEC_CODE) {
					WasmCodeSection codeSection = (WasmCodeSection)section.getPayload();
					long code_offset = section.getPayloadOffset();
					int lookupOffset = 0;
					for (WasmFunctionBody method: codeSection.getFunctions()) {
						long method_offset = code_offset + method.getOffset();
						Address methodAddress = Utils.toAddr( program, Utils.METHOD_ADDRESS + method_offset );
						Address methodend = Utils.toAddr( program, Utils.METHOD_ADDRESS + method_offset + method.getInstructions().length);
						Address methodIndexAddress = Utils.toAddr( program, Utils.LOOKUP_ADDRESS + lookupOffset );
						byte [] instructionBytes = method.getInstructions();
						program.getMemory( ).setBytes( methodAddress, instructionBytes );
						program.getMemory( ).setInt( methodIndexAddress, (int) methodAddress.getOffset( ) );
						program.getFunctionManager().createFunction("Method_" + lookupOffset, methodAddress, new AddressSet(methodAddress, methodend), SourceType.ANALYSIS);
						lookupOffset += 4;
					}
				}
			}
		} catch (Exception e) {
			log.appendException( e );
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {
		return super.validateOptions(provider, loadSpec, options);
	}
}
