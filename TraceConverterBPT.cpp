/*
 * TraceConverterBPT.cpp
 *
 *  Created on: Sep 8, 2015
 *      Author: Anselm
 */

#include "TraceConverterBPT.h"
#include "TraceReaderBinX86.h"
#include "trace.container.hpp"
#include "trace_x86.h"
#include <iostream>
using namespace SerializedTrace;

#define ARCH_32
#ifdef ARCH_64
#define BFD_ARCH bfd_arch_i386
#define BFD_MACH bfd_mach_x86_64
#define STACK_OFFSET 8
#define MAX_ADDRESS "0xffffffffffffffff"
#define MEM_ACCESS qword
#elif defined(ARCH_32)
#define BFD_ARCH bfd_arch_i386
#define BFD_MACH bfd_mach_i386_i386
#define STACK_OFFSET 4
#define MAX_ADDRESS "0xffffffff"
#define MEM_ACCESS dword
#endif

TraceConverterBPT::TraceConverterBPT(std::string TraceFileName, std::string BptFileName) {
	TraceContainerWriter tw(BptFileName, BFD_ARCH, BFD_MACH, default_frames_per_toc_entry, false);

	TraceReaderBinX86 tr;
	size_t counter = 0;
	tr.init(TraceFileName, ""); //defaults to cout
	tr.setVerbose(1);
	uint32_t currentEFLAGS = 0;

	while (tr.readNextInstruction() == 0) {
		counter++;
		//grab a reference to the current instruction
		const TRInstructionX86& insn = tr.getCurInstruction();
		//std::cout << "(" << counter << ") " << tr.getInsnString();
		frame fr;
		fr.mutable_std_frame()->set_address(insn.eh.address);
		fr.mutable_std_frame()->set_thread_id(insn.eh.tid);
		fr.mutable_std_frame()->set_rawbytes(insn.eh.rawbytes, insn.eh.inst_size);

		fr.mutable_std_frame()->mutable_operand_pre_list();
		for (int i = 0; (insn.eh.operand[i].type != TNone) && (i < MAX_NUM_OPERANDS); i++) {
			processOperand(insn.eh.operand[i], fr);
			//if (insn.eh.operand[i].type == TMemLoc) {
			for (int j = 0; (j < MAX_NUM_MEMREGS) && (insn.eh.memregs[i][j].type != TNone); j++) {
				processOperand(insn.eh.memregs[i][j], fr, true);
			}
			//}

		}

		if (currentEFLAGS != insn.eh.eflags) {
			currentEFLAGS = insn.eh.eflags;

			//pre
			operand_info *o = fr.mutable_std_frame()->mutable_operand_pre_list()->add_elem();
			o->mutable_operand_usage()->set_read(false);
			o->mutable_operand_usage()->set_written(true);
			o->mutable_operand_usage()->set_index(false);
			o->mutable_operand_usage()->set_base(false);
			o->mutable_taint_info()->set_no_taint(true);
			uint32_t addr = currentEFLAGS;
			char addrAsHex[5] = { (addr) & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF, 0 };
			o->set_value(addrAsHex, 4);
			o->set_bit_length(32);
			o->mutable_operand_info_specific()->mutable_reg_operand()->set_name("R_EFLAGS");

			//post
			o = fr.mutable_std_frame()->mutable_operand_post_list()->add_elem();
			o->mutable_operand_usage()->set_read(false);
			o->mutable_operand_usage()->set_written(false);
			o->mutable_operand_usage()->set_index(false);
			o->mutable_operand_usage()->set_base(false);
			o->mutable_taint_info()->set_no_taint(true);
			addr = insn.eh.eflags;
			char addrAsHex1[5] = { (addr) & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF, 0 };
			o->set_value(addrAsHex1, 4);
			o->set_bit_length(32);
			o->mutable_operand_info_specific()->mutable_reg_operand()->set_name("R_EFLAGS");
		}

		tw.add(fr);

		if (!(counter % 1000000)) {
			std::cout << "Processed " << counter << std::endl;
		}
		if (counter > 1000) break;
	}

	tw.finish();

}

const static char regname_mapBAP[40][9] = { { "R_ES_32" }, { "R_CS_32" }, { "R_SS_32" }, { "R_DS_32" }, { "R_FS_32" }, { "R_GS_32" }, { "" }, { "" }, { "" }, { "" }, { "" }, { "" }, { "" }, { "" }, { "" }, { "" }, { "R_AL_32" }, { "R_CL_32" }, { "R_DL_32" }, { "R_BL_32" }, { "R_AH_32" }, { "R_CH_32" }, { "R_DH_32" }, {
		"R_BH_32" }, { "R_AX_32" }, { "R_CX_32" }, { "R_DX_32" }, { "R_BX_32" }, { "R_SP_32" }, { "R_BP_32" }, { "R_SI_32" }, { "R_DI_32" }, { "R_EAX_32" }, { "R_ECX_32" }, { "R_EDX_32" }, { "R_EBX_32" }, { "R_ESP_32" }, { "R_EBP_32" }, { "R_ESI_32" }, { "R_EDI_32" } };
//{"eax"}, {"ecx"}, {"edx"}, {"ebx"}, {"esp"}, {"ebp"}, {"esi"}, {"edi"}};

void TraceConverterBPT::processOperand(const OperandVal& op, frame& fr) {
	processOperand(op, fr, false);
}

void TraceConverterBPT::processOperand(const OperandVal& op, frame& fr, bool isBase) {

	if (op.type != TRegister && op.type != TMemLoc && op.type != TMemAddress) return;

	operand_info *o = fr.mutable_std_frame()->mutable_operand_pre_list()->add_elem();

	o->set_bit_length(op.length * 8);
	if (isBase) {
		o->mutable_operand_usage()->set_read(false);
		o->mutable_operand_usage()->set_written(false);
		o->mutable_operand_usage()->set_index(false);
		o->mutable_operand_usage()->set_base(true);
	} else {
		o->mutable_operand_usage()->set_read(XED_IS_READ_OPERAND(op.access) ? 1 : 0);
		o->mutable_operand_usage()->set_written(XED_IS_WRITE_OPERAND(op.access) ? 1 : 0);
		o->mutable_operand_usage()->set_index(0);
		o->mutable_operand_usage()->set_base(0);
	}

	//o->mutable_operand_usage()->set_index((v.usage & USAGE_MASK) == INDEX);
	//o->mutable_operand_usage()->set_base((v.usage & USAGE_MASK) == BASE);
	// to fill when parsing operand registers
	//  OPERAND[1]'s REGISTERS: { R@edi[0xb77dff24][4](R) T_begin (0x0) T_end (0x0) ,
	//	R@eax[0x00000028][4](R) T_begin (0x0) T_end (0x0) }

	if (op.type == TRegister) {
		o->mutable_operand_info_specific()->mutable_reg_operand()->set_name(regname_mapBAP[op.addr - 100]);
	} else {

		switch (op.type) { //optype_map[7] = {'N', 'R', 'M', 'I', 'J', 'F', 'A'};
		case TMemLoc:
		case TMemAddress:
			o->mutable_operand_info_specific()->mutable_mem_operand()->set_address(op.addr);
			break;
		default:
			assert(false);
		}
	}
	uint32_t addr = op.value;
	char addrAsHex[5] = { (addr) & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF, 0 };
	o->set_value(addrAsHex, 4);
//	outs << "T_begin ";
//	outs << "(0x" << hex << op.tainted_begin << ")";
	if (op.tainted_begin)
		o->mutable_taint_info()->set_taint_multiple(true);
	else
		o->mutable_taint_info()->set_no_taint(true);

//	outs << " T_end (0x" << hex << op.tainted_end << ")";
	/*
	 if (op.tainted)
	 {
	 outs << "(0x";
	 if (op.length > 4)
	 {
	 outs << hex << op.records[0].taintBytes[0].source;
	 }
	 outs << hex << op.records[0].taintBytes[0].origin << ")";
	 }
	 */
}

TraceConverterBPT::~TraceConverterBPT() {
}
