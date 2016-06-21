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

#ifndef __HEAPSCAN_HPP_
#define __HEAPSCAN_HPP_

#include "pin.H"
#include <map>

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

/** special value for the address to routine name translation function */
string INVALID_RTN_NAME = "**__invalid_routine_name___**";

string PROGRAM_VERSION = "0.1.22-alpha";
string PROGRAM_NAME = "hdb";
string PROGRAM_RELEASE = "(Bridge.Too.Far)"; //0.1.yy-alpha
//string PROGRAM_RELEASE = "(Red.October)";
//string PROGRAM_RELEASE = "(Solaris.Soder)";
//string PROGRAM_RELEASE = "(Event.Horizon)";
//string PROGRAM_RELEASE = "(2001.S.O)";
//string PROGRAM_RELEASE = "(Sunshine)";
//string PROGRAM_RELEASE = "(Dirty.Dozen)";
//string PROGRAM_RELEASE = "(Red.Dawn)";
//string PROGRAM_RELEASE = "(U571)";
//string PROGRAM_RELEASE = "(Kingdom.of.Heaven)";
//string PROGRAM_RELEASE = "(12.Clock.High)";
//string PROGRAM_RELEASE = "(Thin.Red.Line)";
//string PROGRAM_RELEASE = "(Apoc.Now)";
//string PROGRAM_RELEASE = "(Where.Eagles.Dare)";
//string PROGRAM_RELEASE = "(Great.Escape)";
//string PROGRAM_RELEASE = "(Tora.x3)";
//string PROGRAM_RELEASE = "(Flying.Tigers)";
//string PROGRAM_RELEASE = "(Sea.Bees)";
//string PROGRAM_RELEASE = "(The.Kingdom)";

#define HDB_G_CHAR_TYPE      "CHAR"
#define HDB_G_SHORT_TYPE     "SHORT"
#define HDB_G_INT_TYPE       "INT"
#define HDB_G_LONG_TYPE      "LONG"
#define HDB_G_FLOAT_TYPE     "FLOAT"
#define HDB_G_DOUBLE_TYPE    "DOUBLE"

/** The following set of types represent identifiers for a default
 set of abstract complex data types that HDB knows about. It tries to
 recognize these data collections by analyzing the relationships of
 pointers embedded in the nodes of the data structure itself. If your
 application has its own complex data types, or variations of the
 "standard" data types listed below, you would do well to supply HDB
 with a customized instance of CDTIdentifier. This is a feature planned
 to be implemented via the configuration file "conf/hs.conf", where you
 can specify a particular grammar to be recognized as a collection of
 basic types. Of course, this may or may not be easy for you to do if
 you're using HDB to reverse engineer anything. HDB does its best to
 detect these standard data structure patterns, but it's not perfect.

 Note one limitation: for generic data structure container types, such
 as the Linux kernel's doubly-linked list list_head structure, we would
 detect that as a list on its own merits, not because it holds a particular
 "type" such as task_structs, etc.
*/

const string HDB_ARRAY = "HDB_ARRAY";
const string HDB_LINKED_LIST = "HDB_LINKED_LIST";
const string HDB_DOUBLY_LINKED_LIST = "HDB_DOUBLY_LINKED_LIST";
const string HDB_BINARY_TREE = "HDB_BINARY_TREE";
const string HDB_STACK = "HDB_STACK";
const string HDB_HEAP = "HDB_HEAP";
const string HDB_SKIPLIST = "HDB_SKIPLIST";
const string HDB_BTREE = "HDB_BTREE";
const string HDB_RED_BLACK_TREE = "HDB_RED_BLACK_TREE";
const string HDB_HASHTABLE = "HDB_HASHTABLE";

typedef std::map<UINT32, UINT32> ChunkIndex;

typedef struct _complex_data_type_identifier
{
  string* name;
  //some "structure descriptor"
  //possibly a set of "structure rules" or hints/anchors
  //maybe also a list of registered handlers for firing when recognizing
  // this structure
} CDTIdentifier;

/**
 * Represent a line in the grammar file. Can represent either a single
 * variable or part of a structure/union. NB: parent_type==type is not
 * a reliable indicator that this is a standalone variable, as this
 * could easily be an expression of field in a recursive type.
 */
typedef struct _grammar_entry
{
  string* parent_type;  // multiple GrammarEntrys are related via this field
  string* type;         // type of specific field, can be "wrapped" with ptr()
  string* name;         // variable name
  INT32 offset;         // position in struct (-1 if not in struct)
  UINT32 length;        // length of variable
  BOOL is_ptr;          // is this a pointer? (length should be 4)
} GrammarEntry;

/**
 * A ChunkCollection represents a complex data type consisting of
 * multiple nodes or instances of Abstract Data Types (e.g., a linked
 * list containing multiple nodes, or a tree or a stack or heap or...
 * you get the picture.
 */
typedef struct _chunk_collection
{
  //best guess at known meta-structure of this collection
  CDTIdentifier type;
  //list of chunks associated with this structure. 
  ChunkIndex chunks;
  //read and write counters for collection's activity levels?
  //velocity, acceleration, etc.
} ChunkCollection;

/**
 * "Reconstructed" names have a particular layout:
   [action_list_regex]On[CDTIdentifier]Of[type_name]
 */
typedef struct _routine_identifier
{
  string* name; //from Pin, if possible
  string* rname; // "reconstructed" name
  ADDRINT entry_point; //from Pin
  //list of basic blocks or address range associated with this "routine"
} RTNIdentifier;

typedef struct _rtn_stack_node
{
  string* name;
  struct _rtn_stack_node* _next;
} RoutineStackNode;

typedef struct _instruction_event
{
  ADDRINT eip;
  UINT64 read_level;
  UINT64 write_level;
  UINT64 exec_level;
} InstructionEvent;

typedef std::map<ADDRINT, InstructionEvent*> InsEvtTable;

typedef std::map<std::string, GrammarEntry*> GE_Table;

typedef std::map<std::string, GrammarEntry*> CompositeType;

VOID   HDB_SetRTN_ExitContext();
VOID   HDB_SetRTN_EntryContext(string* rname, 
			       THREADID tid, 
			       const CONTEXT* ctxt);
VOID   HDB_RunScript(string script_name);
INT32  HDB_LoadGrammar(string filename);
INT32  HDB_FindHeapBoundaries();
BOOL   HDB_ScanForType(string target_type);
INT32  HDB_GET_TYPE_SIZE(CompositeType* ct);
BOOL   HDB_IS_TYPE_STRUCTURE_MATCH(ADDRINT start,
				   UINT32 extent,
				   CompositeType* def_table);

VOID   HDB_DisplayNestReport();
VOID   HDB_PrintSectionTable();
VOID   HDB_PrintRegisters();
VOID   HDB_PrintCurrentFunction();
VOID   HDB_PrintMemorySummary();
VOID   HDB_PrintChunkInfo();
VOID   HDB_PrintStack();
VOID   HDB_PrintBreakpointSummary();
VOID   HDB_PrintGrammarSummary();
VOID   HDB_PrintCollectionSummary();
VOID   HDB_PrintHelp();

#endif
