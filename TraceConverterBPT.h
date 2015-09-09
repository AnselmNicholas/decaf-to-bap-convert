/*
 * TraceConverterBPT.h
 *
 *  Created on: Sep 8, 2015
 *      Author: Anselm
 */

#ifndef TRACECONVERTERBPT_H_
#define TRACECONVERTERBPT_H_

#include <string>
#include "trace_x86.h"
#include "trace.container.hpp"

class TraceConverterBPT {
public:
	TraceConverterBPT(std::string TraceFileName, std::string BptFileName);
	virtual ~TraceConverterBPT();

	// defaults to filling precondition
	void processOperand(const OperandVal& op, frame& fr);
	void processOperand(const OperandVal& op, frame& fr, bool isPre);
	void processOperand(const OperandVal& op, frame& fr, bool isBase, bool isPre);
};

#endif /* TRACECONVERTERBPT_H_ */
