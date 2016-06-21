/***************************************************************************
 *  MemSniff
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
 * $Id: MemSniff.C,v 1.5 2008/05/20 14:26:57 locasto Exp $
 **************************************************************************/

#include <ext/hash_map>
//using namespace __gnu_cxx;
using namespace std;
#include <string>
#include <sstream>
#include <iostream>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

namespace __gnu_cxx
{
   template<> struct hash< std::string >
   {
      size_t operator()(const std::string& x) const
      {
         return hash< const char* >()(x.c_str());
      }
   };
}

#include "pin.H"
#include "MemSniff.H"


/** 
 * This program emits a sequence of memory events.
 *
 * It aims to create a string of the form:
 *
 * w(mem[0x1].4)
 * op(mem[addr].len)
 *
 * Event records are separated by a \n
 *
 * @author Michael E. Locasto
 */

string PROGRAM_VERSION = "0.0.6-alpha-1";
string PROGRAM_NAME = "memsniff";

//__gnu_cxx::hash_map<string,int> rvalue_frequency_table;
//__gnu_cxx::hash_map<int,int> rvalue_frequency_table;

UINT64 m_read_count;
UINT64 m_write_count;
UINT64 m_total_memory_operations;

extern int errno;

KNOB<BOOL> KnobPrintVersionShort(KNOB_MODE_WRITEONCE,
                                 "pintool",
                                 "v",
                                 "0",
                                 "output version information and exit");
KNOB<BOOL> KnobPrintVersionLong(KNOB_MODE_WRITEONCE,
                                "pintool",
                                "version",
                                "0",
                                "output version information and exit");

//-----------------------------------------------------------------
//-------------  Boilerplate private service functions  -----------
//-----------------------------------------------------------------

static INT32
Usage()
{
   cerr << PROGRAM_NAME 
        << " prints out records of memory accesses\n";
   cerr << KNOB_BASE::StringKnobSummary();
   cerr << endl;
   return -1;
}

/**
 * This is a hack to get us a reference to EAX, the return value
 * register on x86. It also lets us get the value of the other
 * registers for debugging purposes.
 */
static VOID
SetupRegisters()
{
   REG reg;
   for(reg =  REG_PHYSICAL_CONTEXT_BEGIN; 
       reg <= REG_PHYSICAL_CONTEXT_END;
       reg = REG(reg + 1))
   {
      if(eax_name == REG_StringShort(reg))
      {
         reg_eax = reg;
      }else if(esp_name == REG_StringShort(reg)){
         reg_esp = reg;
      }else if(eip_name == REG_StringShort(reg)){
         reg_eip = reg;
      }else if(ebx_name == REG_StringShort(reg)){
         reg_ebx = reg;
      }else if(ecx_name == REG_StringShort(reg)){
         reg_ecx = reg;
      }else if(edx_name == REG_StringShort(reg)){
         reg_edx = reg;
      }else if(ebp_name == REG_StringShort(reg)){
         reg_ebp = reg;
      }else if(esi_name == REG_StringShort(reg)){
         reg_esi = reg;
      }else if(edi_name == REG_StringShort(reg)){
         reg_edi = reg;
      }else if(eflags_name == REG_StringShort(reg)){
         reg_eflags = reg;
      }else if(cs_name == REG_StringShort(reg)){
         reg_cs = reg;
      }else if(ss_name == REG_StringShort(reg)){
         reg_ss = reg;
      }else if(ds_name == REG_StringShort(reg)){
         reg_ds = reg;
      }else if(es_name == REG_StringShort(reg)){
         reg_es = reg;
      }else if(fs_name == REG_StringShort(reg)){
         reg_fs = reg;
      }else if(gs_name == REG_StringShort(reg)){
         reg_gs = reg;
      }
   }
}

//-----------------------------------------------------------------
//------------------------  Analysis Routines  --------------------
//-----------------------------------------------------------------

VOID
Fini(INT32 code,
     VOID *v)
{
   std::cerr << PROGRAM_NAME 
             << " processed " 
             << m_total_memory_operations
             << " total memory events.\n";
   std::cerr << PROGRAM_NAME << " finished with code " << code << "\n";
}

/**
 * Emit a memory write event dynamically (i.e., during runtime).
 */
VOID
ObserveMemoryWriteEvent(ADDRINT eip,
                        //const string *RTN_name,
                        VOID * ea,
                        UINT32 len
                        )
{
   ADDRINT addr = VoidStar2Addrint(ea);
   std::cerr << "X @ 0x" << hex << eip << dec 
             << " W 0x" << hex << addr << dec << " " << len << "\n";
   m_write_count++;
   m_total_memory_operations++;
}

/**
 * Emit a memory read event dynamically (i.e., during runtime).
 */
VOID
ObserveMemoryReadEvent(ADDRINT eip,
                       //const string *RTN_name,
                       VOID * ea,
                       UINT32 len
                       )
{
   ADDRINT addr = VoidStar2Addrint(ea);
   std::cerr << "X @ 0x" << hex << eip << dec 
             << " R 0x" << hex << addr << dec << " " << len << "\n";  
   m_read_count++;
   m_total_memory_operations++;
}

/**
 * Emit a memory instruction read event dynamically (i.e., during
 * runtime).
 */
VOID
ObserveMemoryFetchIREvent(ADDRINT eip,
                          USIZE len)
{
   std::cerr << "F @ 0x" << hex << eip << dec 
             << " R 0x" << hex << eip << dec << " " << len << "\n";  
   m_read_count++;
   m_total_memory_operations++;
}

//-----------------------------------------------------------------
//-----------------  Instrumentation Routines  --------------------
//-----------------------------------------------------------------

VOID
InjectMemoryEventSniffer(INS ins,
                         VOID *v)
{
   string *RTN_name = &INVALID_RTN_NAME;
   RTN container;   
   container = INS_Rtn(ins);
   USIZE instr_length;
   if(RTN_Valid(container))
   {
      RTN_name = new string(RTN_Name(container));
   }

   instr_length = INS_Size(ins);

   //for every dynamically executed instruction, print out a record of
   //the "instruction fetch" (a READ to memory via ICACHE).
   INS_InsertPredicatedCall(ins, 
                            IPOINT_BEFORE, 
                            (AFUNPTR)ObserveMemoryFetchIREvent,
                            IARG_INST_PTR,
                            IARG_UINT32, ((UINT32)instr_length),
                            IARG_END);

   if(INS_IsMemoryWrite(ins))
   {
      INS_InsertPredicatedCall(ins, 
                               IPOINT_BEFORE, 
                               (AFUNPTR)ObserveMemoryWriteEvent,
                               IARG_INST_PTR,
                               //IARG_PTR, RTN_name,
                               IARG_MEMORYWRITE_EA,
                               IARG_MEMORYWRITE_SIZE,
                               IARG_END);
   }

   if(INS_IsMemoryRead(ins))
   {
      INS_InsertPredicatedCall(ins, 
                               IPOINT_BEFORE, 
                               (AFUNPTR)ObserveMemoryReadEvent,
                               IARG_INST_PTR,
                               //IARG_PTR, RTN_name,
                               IARG_MEMORYREAD_EA,
                               IARG_MEMORYREAD_SIZE,
                               IARG_END);
   }

   if(INS_IsMemoryRead(ins) && 
      INS_HasMemoryRead2(ins) )
   {
      INS_InsertPredicatedCall(ins, 
                               IPOINT_BEFORE, 
                               (AFUNPTR)ObserveMemoryReadEvent,
                               IARG_INST_PTR,
                               //IARG_PTR, RTN_name,
                               IARG_MEMORYREAD2_EA,
                               IARG_MEMORYREAD_SIZE,
                               IARG_END);
   }
}


//-----------------------------------------------------------------
//------------------------  Entry Point     -----------------------
//-----------------------------------------------------------------

/**
 * Entry point for the tool.
 */
int main(int argc, char *argv[])
{
   PIN_InitSymbols();

   if(PIN_Init(argc,argv))
   {
      return Usage();
   }

   if(KnobPrintVersionShort.Value() || KnobPrintVersionLong.Value())
   {
      std::cout << PROGRAM_NAME << "-" << PROGRAM_VERSION << "\n" << flush;
      return 0;
   }

   INS_AddInstrumentFunction(InjectMemoryEventSniffer, 0);
   PIN_AddFiniFunction(Fini, 0);

   SetupRegisters();

   // Never returns
   PIN_StartProgram();

   return 0;
}
