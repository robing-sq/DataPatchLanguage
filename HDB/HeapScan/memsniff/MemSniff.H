/***************************************************************************
 *  MemSniff: Snoop on Memory Events
 *  Copyright (C) 2008 Michael E. Locasto
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the:
 *       Free Software Foundation, Inc.
 *       59 Temple Place, Suite 330
 *       Boston, MA  02111-1307  USA
 *
 * $Id: MemSniff.H,v 1.1 2008/04/20 15:54:09 locasto Exp $
 **************************************************************************/

#ifndef __MEMSNIFF_H_
#define __MEMSNIFF_H_

#include "pin.H"

const string eax_name = string("eax");
const string eip_name = string("eip");
const string esp_name = string("esp");
const string ebx_name = string("ebx");
const string ecx_name = string("ecx");
const string edx_name = string("edx");
const string ebp_name = string("ebp");
const string esi_name = string("esi");
const string edi_name = string("edi");
const string eflags_name = string("eflags");
const string cs_name = string("cs");
const string ss_name = string("ss");
const string ds_name = string("ds");
const string es_name = string("es");
const string fs_name = string("fs");
const string gs_name = string("gs");
REG reg_eax; //used for return value (if function has one)
REG reg_ebx;
REG reg_ecx;
REG reg_edx;
REG reg_ebp; //stack base pointer (current frame)
REG reg_eip; //program counter
REG reg_esp; //base of stack pointer
REG reg_esi;
REG reg_edi;
REG reg_eflags;
REG reg_cs;
REG reg_ss;
REG reg_ds;
REG reg_es;
REG reg_fs;
REG reg_gs;

string INVALID_RTN_NAME = "*** INVALID RTN NAME / NAME NOT FOUND ***";

typedef struct _function_arg
{
   UINT32 address;  //address of the parameter
   UINT32 value;    //value of first word at that address
   struct _function_args* _next;
} FUNCTION_ARG;

/**
 * A function can be uniquely identified by:
 *   its name or identifier or address
 *   its context (the address of the CALL instruction invoking it)
 *   the "depth" of the call stack when it is invoked
 *   the list of argument addresses & values passed to it
 * "context" can optionally include the stack+sibling stack state
 */
typedef struct _function_thunk
{
   string name;
   ADDRINT call_from;  //addr of the CALL instruction --- _not_ &name
   UINT32 depth;
   FUNCTION_ARG* args;
   UINT32 rvalue;
} FunctionThunk;

#endif
