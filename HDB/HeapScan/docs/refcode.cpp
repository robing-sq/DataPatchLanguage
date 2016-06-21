/***************************************************************************
 *  HeapScan
 *  Copyright (C) 2009 Michael E. Locasto
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
 * $Id$
 **************************************************************************/

#include "pin.H"
#include "HeapScan.hpp"
#include <ext/hash_map>
//#include <unordered_map>
//using namespace __gnu_cxx;
using namespace std;
#include <string>
#include <iostream>
#include <sstream>
#include <errno.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
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


/** 
 * This program emits a sequence of control flow transfer events.
 *
 * @author Michael E. Locasto
 */

string PROGRAM_VERSION = "0.0.0-alpha-1";
string PROGRAM_NAME = "hscan";

__gnu_cxx::hash_map<string,int> model;

extern int errno;

std::ofstream ARVFile;

int m_gram_index_counter = 0;

UINT8 MAX_SYMBOLS = 255;

UINT64 m_depth = 0;

//this structure holds a set of unique virtual addresses
//the index indicates the 1 CHAR symbol that represents that address
INT32 symbol_map[MS];
UINT8 symbols_used = 0;
static UINT64 ignored_addresses = 0;

KNOB<BOOL> KnobProduceSmallTrace(KNOB_MODE_WRITEONCE,
                                 "pintool",
                                 "z",
                                 "0",
                                 "produce short encoding");

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




/** 
 * Return "edgeNNN" from a1 -> a2
 */
string
get_edge_label(ADDRINT a1, ADDRINT a2)
{
  string gram_string;
  stringstream ss;
  stringstream ss2;
  long long edge_counter;

  ss << "" << a1;
  ss << "" << a2;
  gram_string = ss.str();
  //if it is in the hashtable already, extract edge index
  edge_counter = model[gram_string];
  if(0==edge_counter)
  {
    //not in, insert it
    model[gram_string]=m_gram_index_counter;
    ss2 << "edge" << m_gram_index_counter;
    m_gram_index_counter++;
  }else{
    ss2 << "edge" << edge_counter;
  }
  return ss2.str();
}

BOOL
seen_symbol(ADDRINT addr)
{
  UINT8 i = 0;
  INT32 a = (INT32)addr;
  for(i=0;i<symbols_used;i++)
  {
    if(a==symbol_map[i])
    {
      return TRUE;
    }
  }
  return FALSE;
}

CHAR
get_symbol(ADDRINT addr)
{
  UINT8 i = 0;
  INT32 a = (INT32)addr;
  for(i=0;i<symbols_used;i++)
  {
    if(a==symbol_map[i])
    {
      return ((CHAR)i);
    }
  }
  return -1;
}

VOID
insert_symbol(ADDRINT addr)
{
  if(seen_symbol(addr))
  {
    //std::cout << "already seen addr\n";
    return;
  }

  if(symbols_used>=((UINT8)MAX_SYMBOLS))
  {
    //std::cout << "symbols_used: "<<symbols_used
    //      << " (UINT8)MAX_SYMBOLS: "
    //      << ((UINT8)MAX_SYMBOLS)
    //      << "\n";
    ignored_addresses++;
    return;
  }

  //std::cout << "inserting " << hex << addr << dec 
  //<< " into symbols[" << symbols_used << "]\n";

  symbol_map[symbols_used] = (INT32)addr;
  symbols_used++;
}

//-----------------------------------------------------------------
//------------------------  Analysis Routines  --------------------
//-----------------------------------------------------------------

VOID
Fini(INT32 code,
     VOID *v)
{
   DumpModel();
   //std::cout << "2-gram model has " 
   /*   
	ARVFile << "2-gram model has " 
           << model.size()
           << " entries\n";
   */
   //std::cout << PROGRAM_NAME << " ignored " 
   //	     << ignored_addresses << " addresses.\n";
   std::cout << PROGRAM_NAME << " finished with code " << code << "\n";
   std::cout << flush;
   ARVFile.clear();
   ARVFile.close();
}

/**
 * Supervise a control transfer
 */
VOID
SuperviseInstruction(const string *RTN_name,
                     CONTEXT *ctxt,
                     ADDRINT ip,
                     BOOL is_branch_ins,
                     ADDRINT branch_target,
                     BOOL branch_taken,
		     BOOL is_call,
		     BOOL is_return,
                     const string *INS_name,
                     THREADID thread_id
                     )
{
  //UINT32 gram_one;
  //UINT32 gram_two;
  //string gram_string;
  //stringstream ss;
  //CHAR src;
  //CHAR dst;
  string edge_label;

  if(is_branch_ins && branch_taken)
  {
    //std::cout << "arv_tail("
    /*
      ARVFile << thread_id 
      << ":0x"
      << hex << ip << dec
      << ":0x" 
      << hex << branch_target << dec
      << ":"
      << *RTN_name
      << "()\n";
    */

    //insert_symbol(ip);
    //insert_symbol(branch_target);
    //src = get_symbol(ip);
    //dst = get_symbol(branch_target);
    //if(-1==src || -1==dst)
    //{
      //we had no room, not FOUND
    //  src = '.';
    //  dst = '.';
    //}

    edge_label = get_edge_label(ip, branch_target); 
    ARVFile << edge_label << " " << flush;
    //ARVFile << hex << ip << " " << branch_target << dec << flush;
    //ARVFile << hex << src << dst << dec;
    //ARVFile << ((CHAR)src) << " " << ((CHAR)dst);
    //ARVFile << ((char)src) << " " << ((char)dst);

    if(is_call)
    {
      //m_depth++;
      //ARVFile << "\n" << *RTN_name << " ";
      ARVFile << " CALL(" << *RTN_name << ") " << flush;
    }

    if(is_return)
    {
      //m_depth--;
      ARVFile << " RET(" << *RTN_name << ") " << flush;
    }

    //gram_one = (UINT32)ip;
    // gram_two = (UINT32)branch_target;
    // ss << "" << gram_one;
    // ss << " " << gram_two;
    // gram_string = ss.str();
    // model[gram_string]++;
  }
}

//-----------------------------------------------------------------
//-----------------  Instrumentation Routines  --------------------
//-----------------------------------------------------------------

VOID
InjectSniffer(INS ins,
              VOID *v)
{
   string *RTN_name = &INVALID_RTN_NAME;
   string *INS_name;
   RTN container;
   BOOL is_call = FALSE;
   BOOL is_return = FALSE;
   
   container = INS_Rtn(ins);
   if(RTN_Valid(container))
   {
      RTN_name = new string(RTN_Name(container));
   }
   INS_name = new string(INS_Mnemonic(ins));
   is_call = INS_IsCall(ins);
   is_return = INS_IsRet(ins);

   //if(INS_IsBranch(ins))
   if(INS_IsBranchOrCall(ins))
   {
      INS_InsertCall(ins, 
                     IPOINT_BEFORE, 
                     (AFUNPTR)SuperviseInstruction,
                     IARG_PTR, RTN_name,
                     IARG_CONTEXT,
                     IARG_INST_PTR,
                     IARG_BOOL, (TRUE),
                     IARG_BRANCH_TARGET_ADDR,
                     IARG_BRANCH_TAKEN,
		     IARG_BOOL, is_call,
		     IARG_BOOL, is_return,
                     IARG_PTR, INS_name,
                     IARG_THREAD_ID,
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
   int i = 0;
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

   ARVFile.open("arvtail.dat");
   if(!ARVFile.is_open())
   {
      std::cerr << "Could not open arv tail profile file for writing.\n";
      return -1;
   }
   ARVFile << "# ARV Tail produced by " 
	   << PROGRAM_NAME << "-" << PROGRAM_VERSION 
	   << "\n" << flush;
   ARVFile << "# ARV Tail produced at: " << time(NULL) << "\n";
   ARVFile << "# CMDLINE: ";
   for(i=0;i<argc;i++)
      ARVFile << argv[i] << " ";
   ARVFile << "\n";

   for(i=0;i<MAX_SYMBOLS;i++)
   {
     symbol_map[i] = 0x0;
   }

   PIN_AddFiniFunction(Fini, 0);
   INS_AddInstrumentFunction(InjectSniffer, 0);

   SetupRegisters();

   // Never returns
   PIN_StartProgram();

   return 0;
}
