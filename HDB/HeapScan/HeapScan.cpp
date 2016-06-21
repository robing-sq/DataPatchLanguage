/***************************************************************************
 *  HeapScan: a data-oriented debugging tool 
 *  Copyright (C) 2008-2009 Michael E. Locasto
 *
 *  All rights reserved.
 * 
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *
 *
 * $Id$
 **************************************************************************/

#include <map>
#include <ext/hash_map>
//using namespace __gnu_cxx;
using namespace std;
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <ostream>
#include <iomanip>

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

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
#include "HeapScan.hpp"
#include "MallocSniff.hpp"
#include "MemSniff.hpp"
#include "CmdShell.hpp"

/** 
 * This program scans memory for patterns of data. It is able to
 * do so because it:
 *
 *  1. intercepts every malloc, realloc, and free
        (calloc is translated to malloc by glibc)
 *  2. observes each instruction-level memory R or W event
 *  3. loads a grammar of data structures and scans only
 *     allocated areas of the heap rather than trying to
 *     dereference invalid pointers or cause page faults for
 *     unallocated pages.
 *
 * This debugger also provides a minimal command-line interface for
 * controlling the execution of the program being analyzed by
 * hdb. This interface is mainly for setting watchpoints on certain
 * types of data-structure related events (i.e., list foo is 76%
 * full).
 *
 * HDB contains four subcomponents:
 *  1. the command interpreter (provide a cmd shell for the debugger)
 *  2. MemSniff (keep track of memory R/W events)
 *  3. MallocSniff (keep track of malloc/realloc/free chunks)
 *  4. HeapScan (logic for parsing data structure grammars, finding
                 instances of them in the heap, config file interpreter)
 *
 * @author Michael E. Locasto
 */

//__gnu_cxx::hash_map<string,int> rvalue_frequency_table;
//__gnu_cxx::hash_map<int,int> rvalue_frequency_table;

pid_t m_supervised_pid = 0;
BOOL m_break_at_each_RTN = FALSE;
BOOL m_break_at_each_INS = FALSE;
BOOL m_break_after_each_RTN = FALSE;
BOOL m_break_after_each_INS = FALSE;
BOOL m_is_initial_prompt = TRUE;
BOOL m_report_on_nests = FALSE;
UINT32 m_num_code_nests = 0;
stringstream m_sections_log;
string* m_current_rtn_name= &INVALID_RTN_NAME;
UINT64 m_stack_depth; //not really handled 100% correct (exceptions/longjmp)
THREADID m_thread_id;
CONTEXT m_ctxt; //global CPU context, updated at each INS and RTN
RoutineStackNode* rtn_stack_head;
GE_Table ge_table;
AChunkCache chunk_cache;
HeapMetaMap m_hmmap;
InsEvtTable m_ie_table;
ADDRINT mg_heap_start = 0; //merge these with m_hmmap.heap_start and _end
ADDRINT mg_heap_end = 0;
unsigned long m_continue_for = 0; //how many times to run/cont...

size_t COMMAND_SIZE = 81;
extern UINT64 m_read_count;
extern UINT64 m_write_count;
extern UINT64 m_total_memory_operations;
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
//-------------  Internal service functions   ---------------------
//-----------------------------------------------------------------

static INT32
Usage()
{
  std::cerr << PROGRAM_NAME 
	    << " is a specialized debugging and reverse engineering tool.\n"
	    << "It scans memory for data structure patterns.\n"
	    << "It can also perform anomaly detection on those structures\n";
  std::cerr << KNOB_BASE::StringKnobSummary();
  std::cerr << endl;
  return -1;
}

static VOID
DumpModel()
{
  /*
   __gnu_cxx::hash_map<std::string,int>::iterator ranger
      = model.begin();
   for( ;ranger!=model.end();ranger++)
   {
      ARVFile << "model[ "
              << ranger->first
              <<" ] = "
              << ranger->second
              << "\n";      
   }
  */   
}

static BOOL
NO_BREAKPOINTS_SET()
{
  BOOL answer = FALSE;

  answer = 
    !m_break_at_each_INS &&
    !m_break_after_each_INS &&
    !m_break_at_each_RTN &&
    !m_break_after_each_RTN;
  return answer;
}

//-----------------------------------------------------------------
//------------------------  Prompt Routines  ----------------------
//-----------------------------------------------------------------

VOID
HDB_PrintHelp()
{
  fprintf(stdout,
	  "Available commands: (commands do not include colon)\n");
  fprintf(stdout,
	  "version:                print HDB version\n");
  fprintf(stdout,
	  "help:                   print this help\n");
  fprintf(stdout,
	  "quit:                   terminate and exit HDB\n");
  fprintf(stdout,
	  "exit:                   terminate and exit HDB\n");
  fprintf(stdout,
	  "run <n>:                Continue running the program until the\n" 
          "                        next breakpoint. If <n> is absent, run\n"
          "                        to next breakpoint. If <n> is present,\n"
          "                        run past n breakpoints.\n");
  fprintf(stdout,
	  "load <filename>:        load a type grammar\n");
  fprintf(stdout,
	  "scan <type>:            scan for instances of <type> in the heap\n"
	  "                        If <type> is unspecified, scan for all\n");
  fprintf(stdout,
	  "info(...)\n"
	  " info(mem):             summarize malloc action\n"
	  " info(memory):          summarize malloc action\n"
	  " info(rtn):             print out current function context\n"
	  " info(function):        print out current function context\n"
	  " info(routine):         print out current function context\n"
	  " info(sec):             print out table of ELF sections\n"
	  " info(sections):        print out table of ELF sections\n"
	  " info(chunks):          print out list of allocated mem chunks\n"
	  " info(stack):           print out current program function stack\n"
	  " info(reg):             print out CPU registers\n"
	  " info(registers):       print out CPU registers\n"
	  " info(g):               list grammar\n"
	  " info(grammar):         list grammar\n"
	  " info(b):               list all breakpoints\n"
	  " info(breakpoints):     list all breakpoints\n"
	  " info(collections):     list collections of ADT/CDTs\n"
	  " info(ADT):             list collections of ADT/CDTs\n"
	  );
  fprintf(stdout,
	  "break(...)\n"
	  " break(rtn,before):     insert breakpoint BEFORE every routine\n"
	  " break(rtn,after):      insert breakpoint AFTER each routine\n"
	  " break(ins,before):     insert breakpoint BEFORE every instruction\n"
	  " break(ins,after):      insert breakpoint AFTER every instruction\n"
	  " break(\"function\"):     XXX unimplemented\n"
	  );
  fprintf(stdout,
	  "track(...)\n"
	  " track(nests):          keep track of instruction nestings\n"
	  "                        to detect code that modifies itself\n"
	  "                        **WARNING**: this procedure impacts\n"
	  "                        performance heavily!\n"
	  );
  fprintf(stdout,
	  "tighten:                clear all breakpoints, on next \'run\',\n" 
	  "                        program will continue until\n"
	  "                        it terminates on its own\n");
  fprintf(stdout,
	  "bt:                     print stack. The same as \'info(stack)\'\n");
  fprintf(stdout,
	  "backtrace:              print stack (same as \'bt\')\n");
  fprintf(stdout,
	  "\n \t -----  Planned Features  -----\n");
  fprintf(stdout,
	  "name(actionpattern,<name>)\n"
	  "tag(addr,extent,TAG)\n"
	  "istagged(addr,TAG)\n"
	  "info(tags,addr): print list of tags for this <addr>\n"
	  "info(tags): print list of all tags used\n"
	  "taglink(addr1,addr2)\n"
	  "untag(addr): remove all tags from this address\n"
	  "untag(addr,extent): remove tags for EXTENT following bytes\n"
	  "autotag: cause taglink to be called for every memcpy and memset"
	  "tag(pattern,name): associate r/w pattern w/ a name\n"
	  "script name / end: following commands are a script\n"
	  "info(scripts): print out list of registered scripts\n"
	  "runscript <name>: execute script <name>\n"
	  "watch(condition,script): run script upon satisfying condition\n"
	  "watch(condition)\n");
  return;
}

VOID 
HDB_RunScript(string script_name)
{
  fprintf(stdout,
	  "not yet implemented\n");
  return;
}

VOID 
HDB_PrintGrammarSummary()
{
  unsigned int i = 0;
  GE_Table::iterator it = ge_table.begin();
  GrammarEntry* ge = NULL;
  if(ge_table.size()<=0)
  {
    fprintf(stdout,
	    "type grammar has no loaded entries, use \'load <filename>\'\n");
    return;
  }
  for(;it!=ge_table.end();it++)
  {
    ge = (*it).second;
    fprintf(stdout,
	    "GrammarEntry[%d] = %s:%s:%s:%d:%d:%s\n",
	    i,
	    ge->parent_type->c_str(),
	    ge->type->c_str(),
	    ge->name->c_str(),
	    ge->offset,
	    ((INT)ge->length),
	    ( (TRUE == ge->is_ptr) ? "true" : "false")
	    );
    i++;
  }
  return;
}

VOID 
HDB_PrintChunkInfo()
{
  unsigned int i = 0;
  AChunkCache::iterator it = chunk_cache.begin();

  if(chunk_cache.size()<=0)
  {
    fprintf(stdout,
	    "the program has no allocated chunks\n");
    return;
  }
  for(;it!=chunk_cache.end();it++)
  {
    AllocatedChunk* ac = (*it).second;
    if(ac->start!=0)
    {
      fprintf(stdout,
	      "chunk(%3d) @ 0x%8x (%4ld bytes)\n",
	      i,
	      ((unsigned int)ac->start),
	      ((unsigned long)ac->extent));
      i++;
    }
  }
  fprintf(stdout,
	  "tracking %d chunks\n",
	  chunk_cache.size());
  return;
}

VOID
HDB_PrintSectionTable()
{
  std::cout << "Sections:\n";
  std::cout << "============================================\n";
  fprintf(stdout, 
	  "%20s %10s %10s",
	  "[Name]",
	  "[Address]",
	  "[Size]\n");
  std::cout << "============================================\n";
  std::cout << m_sections_log.str();
}

/**
 * This is a hack to get us a reference to EAX, the return value
 * register on x86. It also lets us get the value of the other
 * registers for debugging purposes.
 */
VOID
HDB_PrintRegisters()
{
  std::cout << eax_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_eax) << dec << "\n";
  std::cout << ecx_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_ecx) << dec << "\n";
  std::cout << edx_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_edx) << dec << "\n";
  std::cout << ebx_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_ebx) << dec << "\n";
  std::cout << esp_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_esp) << dec << "\n";
  std::cout << ebp_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_ebp) << dec << "\n";
  std::cout << esi_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_esi) << dec << "\n";
  std::cout << edi_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_edi) << dec << "\n";
  std::cout << eip_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_eip) << dec << "\n";
  std::cout << eflags_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_eflags) << dec 
	    << "\n";
  std::cout << cs_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_cs) << dec << "\n";
  std::cout << ss_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_ss) << dec << "\n";
  std::cout << ds_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_ds) << dec << "\n";
  std::cout << es_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_es) << dec << "\n";
  std::cout << fs_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_fs) << dec << "\n";
  std::cout << gs_name << "\t0x" 
	    << std::hex << PIN_GetContextReg(&m_ctxt, reg_gs) << dec << "\n";
}

VOID
HDB_PrintCurrentFunction()
{
  fprintf(stdout,
	  "%lld %s()/%d\n",
	  m_stack_depth,
	  m_current_rtn_name->c_str(),
	  m_thread_id);
}

VOID
HDB_PrintStack()
{
  RoutineStackNode* ptr = NULL;
  ptr = rtn_stack_head;
  int i = 0;

  while(NULL!=ptr)
  {
    fprintf(stdout,
	    "%4d %30s()\n",
	    i,
	    ptr->name->c_str());
    ptr = ptr->_next;
    i++;
  }
}

VOID 
HDB_PrintBreakpointSummary()
{
  if(FALSE==m_break_at_each_INS &&
     FALSE==m_break_after_each_INS &&
     FALSE==m_break_after_each_RTN &&
     FALSE==m_break_at_each_RTN)
  {
    fprintf(stdout,
	    "the program has no registered breakpoints\n");
  }

  if(TRUE==m_break_at_each_INS)
    fprintf(stdout, "break before each instruction\n");

  if(TRUE==m_break_after_each_INS)
    fprintf(stdout, "break after each instruction\n");

  if(TRUE==m_break_at_each_RTN)
    fprintf(stdout, "break before each function\n");

  if(TRUE==m_break_after_each_RTN)
    fprintf(stdout, "break after each function\n");
}

VOID
HDB_PrintCollectionSummary()
{
  fprintf(stdout,
	  "not yet implemented\n");
}

VOID
HDB_PrintMemorySummary()
{
  fprintf(stdout,
	  "# mem reads:         %lld\n"
	  "# mem writes:        %lld\n"
	  "# mem ops:           %lld\n"
	  "heap start:          0x%x\n"
	  "heap end:            0x%x\n"
	  "total freed:         %lld\n"
	  "total alloc:         %lld\n"
	  "current alloc:       %lld\n",
	  m_read_count,
	  m_write_count,
	  m_total_memory_operations,
	  ((UINT32)m_hmmap.heap_start),
	  ((UINT32)m_hmmap.heap_end),
	  m_hmmap.chunks_freed,
	  m_hmmap.chunk_high_water_mark,
	  m_hmmap.chunks_allocated);
}

VOID   
HDB_DisplayNestReport()
{
  fprintf(stdout,
	  "HDB detected %ld code nestings\n",
	  ((long)m_num_code_nests));
  return;
}

/** 
 * Set initial break and watch points so we can get back to a prompt
 * and examine all these lovely memory events and data structures.
 * 
 * right now this relies on strict string equality but we use Pin's
 * ReadLine(), so in the future it will be easy to parse commands and
 * their arguments i.e., 'info memory' rather than "info(memory)" and
 * 'break rtn "foo" before'
 *
 * 'watch <address>'
 * 'watch (expression)'
 * disassemble <n> //print current <n> instruction(s)
 * scan (all types)
 * scan <typename>  (e.g., scan StackNode)
 * untrack <chunks> ('untrack' drops all chunks) 
 *
 * TODO: promp string gives context [prefix] == mode, [prompt], suffix=context
 * TODO: define a query language that can report 1) individual types and 2)
 *       how those types are organized into various canonical data structures
 */
VOID
HDB_Prompt()
{
  string commandline = "";
  UINT32 lineNum = 0;
  unsigned int command_pos = 0;
  BOOL matched_command_flag = FALSE;

  if(FALSE==m_is_initial_prompt)
  {
    if(FALSE==m_break_at_each_RTN)
    {
      return;
    }
    //same for others...
  }
  m_is_initial_prompt = FALSE;

  if(m_continue_for>0)
  {
    m_continue_for--;
    return;
  }
  if(m_continue_for<=0)
  {
    m_continue_for = 0;
  }

  fflush(stdout);
  for(;;)
  {
    matched_command_flag = FALSE;
    fprintf(stdout,
	    "(hdb) ");
    commandline = ReadLine(std::cin, &lineNum);
    //std::cerr << "i read: [" << commandline << "]\n";

    command_pos = commandline.find("quit", 0);
    if(0==command_pos)
    {
      m_break_at_each_INS = FALSE;
      m_break_after_each_INS = FALSE;
      m_break_at_each_RTN = FALSE;
      m_break_after_each_RTN = FALSE;

      exit(-1);
    }
    command_pos = commandline.find("exit", 0);
    if(0==command_pos)
    {
      //set a flag to kill Pin, call Fini
      m_break_at_each_INS = FALSE;
      m_break_after_each_INS = FALSE;
      m_break_at_each_RTN = FALSE;
      m_break_after_each_RTN = FALSE;

      exit(-1);
    }
    command_pos = commandline.find("runscript", 0);
    if(0==command_pos)
    {
      string scriptname = "";
      unsigned int space_pos = 0;
      space_pos = commandline.find(" ", command_pos);
      if(space_pos!=string::npos)
      {
	scriptname = commandline.substr((space_pos+1), string::npos);
	fprintf(stdout,
		"running script <%s>...\n",
		scriptname.c_str());
	HDB_RunScript(scriptname);
      }
      return;
    }
    command_pos = commandline.find("run", 0);
    if(0==command_pos)
    {
      string runtimes = "";
      unsigned int space_pos = 0;
      space_pos = commandline.find(" ", command_pos);
      if(space_pos!=string::npos)
      {
	//reset m_continue_for if we have found two args...
	//XXX this is broken, only detects space, not 2 args
	runtimes = commandline.substr((space_pos+1), string::npos);     
	//m_continue_for = (unsigned long)(strtol(runtimes.c_str(), NULL, 16));
	m_continue_for = (unsigned long)(strtol(runtimes.c_str(), NULL, 10));
	if(TRUE==NO_BREAKPOINTS_SET())
	{
	  fprintf(stdout,
		  "Warning: no breakpoints set. Execution will continue uninterrupted. Ignoring argument \"%ld\" to \"run\" command\n", m_continue_for);
	}else{
	  fprintf(stdout,
		  "continuing past %ld breakpoints\n",
		  m_continue_for);
	}
      }
      return;
    }
    command_pos = commandline.find("tighten", 0);
    if(0==command_pos)
    {
      if(TRUE==NO_BREAKPOINTS_SET())
      {
	fprintf(stdout,
		"already tightened up, all seals in place\n");
      }else{
	m_break_at_each_INS = FALSE;
	m_break_after_each_INS = FALSE;
	m_break_at_each_RTN = FALSE;
	m_break_after_each_RTN = FALSE;
      }
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("track(nests)", 0);
    if(0==command_pos)
    {
      m_report_on_nests = TRUE;
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("help", 0);
    if(0==command_pos)
    {
      HDB_PrintHelp();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("version", 0);
    if(0==command_pos)
    {
      fprintf(stdout,
	      "%s v%s\n",
	      PROGRAM_NAME.c_str(),
	      PROGRAM_VERSION.c_str());
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(stack)", 0);
    if(0==command_pos)
    {
      HDB_PrintStack();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("bt", 0);
    if(0==command_pos)
    {
      HDB_PrintStack();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("backtrace", 0);
    if(0==command_pos)
    {
      HDB_PrintStack();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(collections)", 0);
    if(0==command_pos)
    {
      HDB_PrintCollectionSummary();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(ADT)", 0);
    if(0==command_pos)
    {
      HDB_PrintCollectionSummary();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(b)", 0);
    if(0==command_pos)
    {
      HDB_PrintBreakpointSummary();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(breakpoints)", 0);
    if(0==command_pos)
    {
      HDB_PrintBreakpointSummary();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(memory)", 0);
    if(0==command_pos)
    {
      HDB_PrintMemorySummary();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(mem)", 0);
    if(0==command_pos)
    {
      HDB_PrintMemorySummary();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(registers)", 0);
    if(0==command_pos)
    {
      HDB_PrintRegisters();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(reg)", 0);
    if(0==command_pos)
    {
      HDB_PrintRegisters();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(sec)", 0);
    if(0==command_pos)
    {
      HDB_PrintSectionTable();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(sections)", 0);
    if(0==command_pos)
    {
      HDB_PrintSectionTable();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(chunks)", 0);
    if(0==command_pos)
    {
      HDB_PrintChunkInfo();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(function)", 0);
    if(0==command_pos)
    {
      HDB_PrintCurrentFunction();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(rtn)", 0);
    if(0==command_pos)
    {
      HDB_PrintCurrentFunction();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(routine)", 0);
    if(0==command_pos)
    {
      HDB_PrintCurrentFunction();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(g)", 0);
    if(0==command_pos)
    {
      HDB_PrintGrammarSummary();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(grammar)", 0);
    if(0==command_pos)
    {
      HDB_PrintGrammarSummary();
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("info(scripts)", 0);
    if(0==command_pos)
    {
      //print script summary
      fprintf(stdout,
	      "not yet implemented\n");
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("break(rtn,before)", 0);
    if(0==command_pos)
    {
      fprintf(stdout,
	      "hdb will return to prompt before entering each function\n");
      m_break_at_each_RTN = TRUE;
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("break(ins,before)", 0);
    if(0==command_pos)
    {
      fprintf(stdout,
	      "hdb will return to prompt before each instruction\n");
      m_break_at_each_INS = TRUE;
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("break(rtn,after)", 0);
    if(0==command_pos)
    {
      fprintf(stdout,
	      "hdb will return to prompt after each function (immediately before function exit)\n");
      m_break_after_each_RTN = TRUE;
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("break(ins,after)", 0);
    if(0==command_pos)
    {
      fprintf(stdout,
	      "hdb will return to prompt after each instruction\n");
      m_break_after_each_INS = TRUE;
      matched_command_flag = TRUE;
    }
    command_pos = commandline.find("load", 0);
    if(0==command_pos)
    {
      string grammar_filename = "";
      unsigned int space_pos = 0;
      space_pos = commandline.find(" ", command_pos);
      if(space_pos!=string::npos)
      {
	grammar_filename = commandline.substr((space_pos+1), string::npos);     
	fprintf(stdout,
		"loading data structure grammars in \'%s\'...",
		grammar_filename.c_str());
	//expecting to print "...read N lines.\n" after this
	if(-1==HDB_LoadGrammar(grammar_filename))
	{
	  fprintf(stderr,
		  "failed to load grammar file\n");
	}
      }
      matched_command_flag = TRUE;
      //why are we returning here? -MEL
      return;
    }
    command_pos = commandline.find("scan", 0);
    if(0==command_pos)
    {
      string target_type = "";
      unsigned int space_pos = 0;
      space_pos = commandline.find(" ", command_pos);
      if(space_pos!=string::npos)
      {
	target_type = commandline.substr((space_pos+1), string::npos);
	fprintf(stdout,
		"searching for type <%s>\n",
		target_type.c_str());
      }

      HDB_FindHeapBoundaries();
      HDB_ScanForType(target_type);

      //report on actual allocated chunks (this is the search space, not
      // the entire heap --- for most programs...)
      //ReportOnMallocdChunks();
      //ScanForDataStructures();
      //ReportDataStructures();
      matched_command_flag = TRUE;
    }

    if(FALSE==matched_command_flag)
    {
      fprintf(stdout,
	      "command not found\n");
    }
  }
}

//-----------------------------------------------------------------
//------------------------  Various Utilities  --------------------
//-----------------------------------------------------------------

/**
StackNode:ptr(CHAR):name:0:4:true
StackNode:INT:name_length:1:4:false
StackNode:LONG:age:2:4:false
StackNode:ptr(StackNode):_next:3:4:true 
  string parent_type;  // multiple GrammarEntrys are related via this field
  string type;         // type of specific field, can be "wrapped" with ptr()
  string name;         // variable name
  INT32 offset;        // position in struct (-1 if not in struct)
  UINT32 length;       // length of variable
  BOOL is_ptr;         // is this a pointer? (length should be 4)
 */
INT32
HDB_LoadGrammar(string filename)
{
  UINT32 lineNum = 0;
  unsigned int hash_pos = 0;
  unsigned int colons_pos[5] = {0,0,0,0,0};
  //field_counter is not a *field* counter, it is a field separator counter
  int field_counter = 0; //assert(field_counter>0 && field_counter<5) all times
  int start_search = 0;
  string line = "";
  char* g_filename = NULL;
  std::ifstream GrammarFile;
  GrammarEntry* ge = NULL;
  stringstream ge_key;
  string offset_field;
  string length_field;
  string is_ptr_field;
   
  g_filename = (char*)filename.c_str();

  GrammarFile.open(g_filename, std::ifstream::in);
  if(!GrammarFile.is_open())
  {
    std::cerr << "Could not open " << g_filename << "\n";
    return -5;
  }
  if(GrammarFile.fail())
  {
    std::cerr << "Some problem opening " << g_filename << "\n";
    return -6;
  }
  if(0==GrammarFile)
  {
    std::cout << "grammar file did not change.\n";
    GrammarFile.clear();
    GrammarFile.close();
    return -7;
  }
  GrammarFile.seekg(0, ios::beg);
  
  while(!GrammarFile.eof())
  {
    line = ReadLine(GrammarFile, &lineNum);
    hash_pos = line.find("#", 0);
    if(string::npos!=hash_pos)
    {
      //found a comment, skip line
      continue;
    }
    //std::cerr << "reading line: [" << line << "]\n";
    while(field_counter<=4)
    {
      colons_pos[field_counter] = line.find(":", start_search);
      if(string::npos!=colons_pos[field_counter])
      {
	/*
	fprintf(stdout,
		"colons_pos[%d] = %d\n",
		field_counter,
		colons_pos[field_counter]);
	*/
	//ordering of next 2 statements is critical
	start_search = colons_pos[field_counter];
	start_search++; //move beyond "found" colon
	field_counter++;
      }
    }

    if(5!=field_counter)
    {
      std::cerr << "malformed line\n";
      continue; //skip this line
    }
    //process fields
    ge = (GrammarEntry*)malloc(sizeof(GrammarEntry));
    if(NULL==ge)
    {
      std::cerr << "Could not allocate space for grammar entry\n";
      continue; //skip this entry, could cause bugs later
    }

    ge->parent_type = new string(line.substr(0, colons_pos[0]).c_str());
    //this may include a 'ptr(...)' wrapper around the type
    ge->type = new string(line.substr((colons_pos[0])+1, 
				      colons_pos[1]-colons_pos[0]-1
				      ));
    ge->name = new string(line.substr((colons_pos[1])+1, 
				      colons_pos[2]-colons_pos[1]-1
				      ));
    offset_field = line.substr((colons_pos[2])+1, 
			       colons_pos[3]-colons_pos[2]-1);
    length_field = line.substr((colons_pos[3])+1, 
			       colons_pos[4]-colons_pos[3]-1);
    is_ptr_field = line.substr((colons_pos[4])+1, string::npos);

    if(is_ptr_field.find("false", 0)!=string::npos)
    {
      ge->is_ptr = FALSE;
    }else{
      ge->is_ptr = TRUE;
    }
    ge->offset = strtol(offset_field.c_str(), NULL, 10);
    ge->length = strtol(length_field.c_str(), NULL, 10);

    ge_key << "" << ge->parent_type->c_str() 
	   << ":" << ge->type->c_str()
	   << ":" << ge->name->c_str();
    //ge_key << "" << *(ge->parent_type);
    //std::cout << "ge_key = " << (ge_key.str()) << "\n" << flush;
    ge_table[ge_key.str()] = ge;
    //reset for next line
    ge = NULL;
    field_counter = 0;
    ge_key.clear();
    ge_key.str("");
    line.clear();
    colons_pos[0] = 0;
    colons_pos[1] = 0;
    colons_pos[2] = 0;
    colons_pos[3] = 0;
    colons_pos[4] = 0;
    start_search = 0;
  }
  fprintf(stdout,
	  "read %d lines\n",
	  lineNum);
  GrammarFile.close();

  return 0;
}

/** 
 * lookup the heap in "/proc/self/maps"
   //cat /proc/self/maps | grep heap | gawk '{print $1}'
   //09084000-09386000
 */
INT32
HDB_FindHeapBoundaries()
{
   char* proc_pid_filename = NULL;
   string line = "";
   unsigned int heap_pos = 0;
   UINT32 lineNum = 0;
   std::ifstream ProcMapFile;
   BOOL found_heap_line = FALSE;
   unsigned int dash_pos = 0;
   unsigned int space_pos = 0;
   string hs = "";
   string he = "";

   string mapsfile = "/proc/self/maps";
   proc_pid_filename = (char*)mapsfile.c_str();
   //std::cout << "Opening " << proc_pid_filename << "\n";
   ProcMapFile.open(proc_pid_filename, std::ifstream::in);
   if(!ProcMapFile.is_open())
   {
      std::cerr << "Could not open " << proc_pid_filename << "\n";
      return -5;
   }
   if(ProcMapFile.fail())
   {
      std::cerr << "Some problem opening " << proc_pid_filename << "\n";
      return -6;
   }
   if(0==ProcMapFile)
   {
      std::cout << "proc map file did not change.\n";
      ProcMapFile.clear();
      ProcMapFile.close();
      return -7;
   }
   ProcMapFile.seekg(0, ios::beg);

   while(!ProcMapFile.eof() && (found_heap_line==FALSE))
   {
      line = ReadLine(ProcMapFile, &lineNum);
      //std::cerr << "reading line: [" << line << "]\n";
      //std::cerr << line << "\n";
      heap_pos = line.find("heap", 0);
      if(string::npos!=heap_pos)
      {
         //std::cerr << "found heap line: [" << line << "]\n";
         found_heap_line = TRUE;
      }
   }
   //std::cerr << "read " << lineNum << " lines\n";
   ProcMapFile.close();

   dash_pos = line.find("-", 0);
   space_pos = line.find(" ", 0);
   //std::cerr << "dash is at position " << dash_pos << "\n";
   //std::cerr << "space is at position " << space_pos << "\n";
   hs = line.substr(0, dash_pos);
   he = line.substr((dash_pos+1), (space_pos-dash_pos-1));
   //std::cerr << "heap start is: [" << hs << "]\n";
   //std::cerr << "heap end is:   [" << he << "]\n";

   m_hmmap.heap_start = ADDRINT( strtol(hs.c_str(), NULL, 16) );
   m_hmmap.heap_end = ADDRINT( strtol(he.c_str(), NULL, 16) );

   std::cout << "heap start is: [" 
	     << std::hex << m_hmmap.heap_start << std::dec << "]\n";
   std::cout << "heap end is:   [" 
	     << std::hex << m_hmmap.heap_end << std::dec << "]\n";

   return 0;
}

/**
 * Handle meta-information for each function entry / prologue
 */
VOID 
HDB_SetRTN_EntryContext(string* rname,
			THREADID tid,
			const CONTEXT* ctxt)
{
  RoutineStackNode* tmp = NULL;
  stringstream ss;
  ss << "" << *rname;
  m_current_rtn_name = new string(ss.str());
  m_thread_id = tid;
  m_stack_depth++;
  //cannot just directly assign, must use PIN API to save context
  //m_ctxt = ctxt;
  PIN_SaveContext(ctxt, &m_ctxt);
  //push ss.str() onto top of routine stack (support bt, info(stack))

  tmp = (RoutineStackNode*)malloc(sizeof(RoutineStackNode));
  if(NULL==tmp)
    return;
  tmp->name = new string(ss.str());
  tmp->_next = NULL;

  if(NULL==rtn_stack_head)
  {
    rtn_stack_head = tmp;
  }else{
    tmp->_next = rtn_stack_head;
    rtn_stack_head = tmp;
  }
}

VOID
HDB_SetRTN_ExitContext()
{
  RoutineStackNode* ptr = NULL;
  if(m_stack_depth<=0)
  {
    m_stack_depth=0;
  }else{
    m_stack_depth--;
    //pop top of routine stack
    if(NULL==rtn_stack_head)
      return;
    if(NULL==rtn_stack_head->_next)
    {
      free(rtn_stack_head);
      rtn_stack_head = NULL;
      return;
    }
    if(NULL!=rtn_stack_head->_next)
    {
      ptr = rtn_stack_head->_next;

      rtn_stack_head->_next = NULL;
      delete rtn_stack_head->name;
      rtn_stack_head->name = NULL;
      free(rtn_stack_head);
      rtn_stack_head = NULL;

      rtn_stack_head = ptr;
    }
  }
}

/**
 * Determine if this chunk of memory contains the type
 * specified in 'def_table'.
 *
 * We assume that 'extent' describes a size that is consistent
 * with the fields defined in 'def_table'
 * 
 * Should this function return a percentage match?
 * This function is designed to be recursive.
 */
BOOL 
HDB_IS_TYPE_STRUCTURE_MATCH(ADDRINT start,
			    UINT32 extent,
			    CompositeType* def_table)
{
  INT32 current_offset = 0; //increased by ge->offset
  INT32 current_field = 1;  //increased by 1 every time we process a ge
  //ADDRINT data; //bits/data at start+current_offset, for ge->length bytes
  unsigned int* addr = NULL;
  float percent_match = 0.0;  // number of matched fields / def_table->size()
  INT32 num_matched_fields = 0;

  GrammarEntry* ge = NULL;
  CompositeType::iterator ct;

  //assemble or iterate through the entries in 'def_table' in
  //order by their GE->offset field.

  //follow any recursive pointers to see if this points to
  //an object consistent with the 'def_table' structure.

  //base case is NULL pointers, or detection of a loop in the
  //data structure (i.e., we mark each 'start' as visited and
  //if we enter a visited location we know we looped back

  if(NULL==def_table)
  {
    return FALSE;
  }

  //if there is no space here to examine (illegal argument, most likely)
  if(0==extent)
  {
    return FALSE;
  }

  addr = ((unsigned int*)start);
  //if start points to NULL
  //this is brittle, especially if 'start' itself is not
  //properly initialized and holds an illegal memory address
  if(0==*addr)
  {
    return FALSE;
  }

  while(((unsigned int)current_field)<=def_table->size())
  {
    //iterate over ct
    ct = def_table->begin();
    for(;ct!=def_table->end();ct++)
    {
      ge = ct->second;
      //search for 'current_offset'
      if(current_offset == ge->offset)
      {
	//found the appropriate field
	//does the memory at this location (start+ge->offset)
	//match up with the type specified by ge->type?
	//the basic idea here is to see if the pile of bits
	//at this offset (start+ge->offset) is consistent with
	//what we know about ge->type and any relationship ge->type
	//might have to ge->parent_type
	
	if(TRUE==ge->is_ptr)
	{
	  //is it a primitive type or a user-defined type?
	}else{
	  //is it a primitive type or a user-defined type?
	}

	//char* (i.e., ptr(CHAR)) should point to char data that
	// ends in a \0, and the data contained in its length
	// that is, the pointer, should be a valid memory address
	// or NULL. False negatives are possible for uninitialized
	// pointers

	//if to a complex type, service recursively

	break;
      }
    }

    current_field++;
    current_offset += ge->length;
  }
  num_matched_fields = 0;
  percent_match = 0.0;

  return FALSE;
}

/**
 * Return the size, in bytes, of the supplied composite type.
 */
INT32 
HDB_GET_TYPE_SIZE(CompositeType* ct)
{
  INT32 c_size = 0;
  GrammarEntry* ge = NULL;
  CompositeType::iterator it;
  if(NULL==ct)
  {
    return 0;
  }

  it = ct->begin();
  for(;it!=ct->end();it++)
  {
    ge = it->second;
    c_size += ge->length; //length is in bytes
  }
  return c_size;
}

/**
 * Scan our list of collections to see if ac belongs to any
 * of them. Combine/consolidate those that 'ac' links.
 */
BOOL   
MALLOCSNIFF_AddChunkToCollections(AllocatedChunk* ac)
{
  return FALSE;
}

/**
 * For each entry in the ge_table that starts with "target_type",
 * build a "CompositeType" and then go iterate over the chunk_cache
 * and see if there is a potential "match" in that chunk for this
 * composite type. The special sauce here is twofold: how to create
 * a representation of a composite types, and how to deduce that
 * something is the proper type because we recursively follow the
 * pointers, if any.
 *
 * recall that ac->type_hints provides storage for noting the 'type'
 * of a chunk
 * 
 * 'target_type' can be a special type (e.g., 'LIST) and that
 * causes a deduction stage (not here, the command dispatcher makes
 * that decision).
 */
BOOL 
HDB_ScanForType(string target_type)
{
  GrammarEntry* ge = NULL;
  string* type_key;
  UINT32 type_size = 0;
  AChunkCache::iterator c_it = chunk_cache.begin();
  GE_Table::iterator it = ge_table.begin();
  CompositeType type_def_table;
  //key is ac->start of chunk, value is ??
  ChunkIndex chunk_candidates_index;
  AChunkCache matched_chunks;
  ChunkIndex::iterator ct_it;
  ADDRINT m;
  BOOL is_type_match = FALSE;

  if(""==target_type)
  {
    fprintf(stdout,
	    "scanning for all types Not Yet Implemented.\n");
    return FALSE;
  }

  if(ge_table.size()<=0)
  {
    fprintf(stdout,
	    "cannot find type <%s>: type grammar has no loaded entries."
	    " Use \'load <filename>\' to load in grammar definitions.\n",
	    target_type.c_str());
    return FALSE;
  }
  for(;it!=ge_table.end();it++)
  {
    type_key = new string(it->first.c_str());
    if(type_key->find(target_type, 0)!=string::npos)
    {
      /*
      fprintf(stdout,
	      "found %s\n",
	      type_key->c_str());
      fflush(stdout);
      */
      //key contains the type we are looking for
      ge = it->second; //do we need a "copy" operation here?
      type_def_table[(*type_key)] = ge;
    }
  }

  // BUILT TYPE COMPOSITE
  type_size = HDB_GET_TYPE_SIZE(&type_def_table);
  if(0==type_size)
  {
    fprintf(stdout,
	    "you have me looking for a zero-sized type. no dice.\n");
    return FALSE;
  }else if(type_size<0){
    fprintf(stdout,
	    "type size is negative for some reason. very bad.\n");
    return FALSE;
  }else{
    fprintf(stdout,
	    "type <%s> is %d bytes long\n",
	    target_type.c_str(),
	    type_size);
    fflush(stdout);
  }

  // a procedure for checking if a composite type resides at a chunk
  // first, is chunk larger than type? If yes, possible match.
  // is chunk smaller than type? If yes, no match

  if(chunk_cache.size()<=0)
  {
    fprintf(stdout,
	    "the program has no dynamically allocated memory chunks\n");
    return FALSE;
  }
  for(;c_it!=chunk_cache.end();c_it++)
  {
    AllocatedChunk* ac = (*c_it).second;
    if(ac->start!=0)
    {
      if(ac->extent < type_size)
      {
	//skip this chunk, unlikely that type resides here
	// (it is most likely a bug if so...)
	
      }else if(ac->extent > type_size){
	//also unlikely that there is a match here, but it could
	//be so, especially for large chunks that store _collections_
	//of composite types, like CT* ct = (CT*)calloc(N, sizeof(CT));
	//in that case, see if chunk _starts_ with the composite type
	//XXX
      }else{
	//sizes are equal. This is a very likely match
	//XXX
	//if successful match, then save the ID for further tests
	stringstream s;
	s << ac->start;
	chunk_candidates_index[ac->start] = ac->extent; //for now
	matched_chunks[s.str()]=ac;
	//if(verbose==INFO)
	//{
	//fprintf(stdout,
	//"candidate chunk at %x\n",
	//ac->start);
	//}
      }
    }
  }

  // REPORT ON CHUNK IDs (addresses or enumeration) that seem to contain
  // this type. Also update ac->type_hints
  fprintf(stdout,
	  "there seem to be %d potentially matching chunks\n",
	  chunk_candidates_index.size());
  ct_it = chunk_candidates_index.begin();
  is_type_match = FALSE;
  for(;ct_it!=chunk_candidates_index.end();ct_it++)
  {
    AllocatedChunk* chunk;
    stringstream s;
    m = ADDRINT((ct_it->first));
    s << m;
    chunk = matched_chunks[s.str()];
    s.clear();
    s.str("");

    //does the data at this address match the form of the
    //identified CompositeType?
    is_type_match = HDB_IS_TYPE_STRUCTURE_MATCH(m,
						chunk->extent,
						&type_def_table);

    if(TRUE==is_type_match)
    {
      //add it to any existing "collections", or start a new one
      //addition also entails seeing if chunk C sews together chunks
      //A and B, which might have their own "collection"
      MALLOCSNIFF_AddChunkToCollections(chunk);
    }
  }

  // SEE IF YOU CAN FIND THE "ROOT" of a data structure (i.e., a node
  // with nothing pointing back to it.

  return TRUE;
}



//-----------------------------------------------------------------
//------------------------  Analysis Routines  --------------------
//-----------------------------------------------------------------


VOID
Fini(INT32 code,
     VOID *v)
{
  if(TRUE==m_report_on_nests)
  {
    HDB_DisplayNestReport();
  }
  DumpModel();
  std::cerr << PROGRAM_NAME << " still has " 
	    << m_hmmap.chunks_allocated 
	    << " memory chunks.\n";
  std::cerr << PROGRAM_NAME << " processed "
	    << m_total_memory_operations
	    << " total memory events.\n";
  std::cerr << PROGRAM_NAME << " finished with code " << code << "\n";
}

/* ======================  MemSniff ========================== */

/**
 * Emit a memory write event dynamically (i.e., during runtime).
 */
VOID
ObserveMemoryWriteEvent(ADDRINT eip,
			VOID * ea,
			UINT32 len)
{
  InsEvtTable::iterator it;
  InstructionEvent* ie_ptr = NULL;
  ADDRINT addr;

  addr = VoidStar2Addrint(ea);
  //record this write event for this thread
  //have a Model of write events to this spot
  // std::cerr << "X @ 0x" << hex << eip << dec 
  //           << " W 0x" << hex << addr << dec << " " << len << "\n";
  m_write_count++;
  m_total_memory_operations++;

  if(TRUE==m_report_on_nests)
  {
    it = m_ie_table.find(addr);
    if(it == m_ie_table.end())
    {
      //we are not writing to an instruction that has been
      //previously read in
      //but we may be writing to a place that will eventually
      //be used as an instruction...
    }else{
      //we are writing to a previous instruction
      ie_ptr = (*it).second;
      ie_ptr->write_level++;
    }
  }
}

VOID
ObserveMemoryReadEvent(ADDRINT eip,
                       VOID * ea,
                       UINT32 len)
{
  //ADDRINT addr = VoidStar2Addrint(ea);
  //std::cerr << "X @ 0x" << hex << eip << dec 
  //          << " R 0x" << hex << addr << dec << " " << len << "\n";  
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
  InsEvtTable::iterator it;
  InstructionEvent* ie_ptr = NULL;
  //std::cerr << "F @ 0x" << hex << eip << dec 
  //<< " R 0x" << hex << eip << dec << " " << len << "\n";  
  m_read_count++;
  m_total_memory_operations++;

  if(TRUE==m_report_on_nests)
  {
    it = m_ie_table.find(eip);
    if(it == m_ie_table.end())
    {
      //didn't find an entry with this address
      ie_ptr = (InstructionEvent*)malloc(sizeof(InstructionEvent));
      if(NULL==ie_ptr)
      {
	fprintf(stderr,
		"no memory to watch nested instruction at %x\n",
		eip);
	return;
      }else{
	ie_ptr->eip = eip;
	ie_ptr->read_level = 1;
	ie_ptr->write_level = 0;
	ie_ptr->exec_level = 1;
      }
    }else{
      //leave it alone, already has an entry
    }
  }
}

/* ======================  MallocSniff ========================== */

VOID 
MallocBefore(THREADID tid,
	     ADDRINT ip,   //eip this malloc was called from
	     ADDRINT size) //number of bytes to malloc
{
  AllocatedChunk* ac = NULL;
  stringstream ss;

  m_hmmap.chunks_allocated++;
  m_hmmap.chunk_high_water_mark++;

  ac = (AllocatedChunk*)malloc(sizeof(AllocatedChunk));
  if(NULL==ac)
  {
    fprintf(stderr,
	    "cannot track chunk requested from %x\n",
	    ip);
    return;
  }
  /*
  fprintf(stdout,
	  "AllocatedChunk created\n");
  fflush(stdout);
  */
  ac->start = 0; //NB: _not_ the right value, must be updated 
  ac->extent = size;
  ac->type_hints = new string("");
  ac->is_root = FALSE;
  //ss << "pending-" << ip;
  ss << "pending"; //may lose a chunk if malloc() is re-entrant
  chunk_cache[ss.str()] = ac; //not its final resting place
  return;
}

VOID
ReallocBefore(THREADID tid,
	      ADDRINT ip,   //eip realloc was called from
	      ADDRINT ptr,  //ptr to be resized
	      ADDRINT size) //the new size
{
  //chunk_cache[spot].extent = size;
  return;
}

VOID 
FreeBefore(THREADID tid,
	   ADDRINT ip,      //eip free was called from
	   ADDRINT address) //address to free
{
  stringstream ss;
  AChunkCache::iterator it;

  if(0==address)
  {
    /*
    fprintf(stdout,
	    "free(0)\n");
    */
    return;
  }

  ss << "" << address;
  it = chunk_cache.find(ss.str());

  m_hmmap.chunks_freed++;
  if(m_hmmap.chunks_allocated<=0)
  {
    m_hmmap.chunks_allocated=0;
    return;
  }else{
    m_hmmap.chunks_allocated--;
  }
  
  if(it == chunk_cache.end())
  {
    //didn't find an entry with this address
    fprintf(stderr,
	    "did not find chunk with address to free...\n");
    fflush(stderr);
    return;
  }else{
    AllocatedChunk* ac = (*it).second;
    free(ac);
    ac = NULL;
    chunk_cache.erase(ss.str());
  }
  return;
}

VOID
ReallocAfter(THREADID tid,
	     ADDRINT ret)
{
  //search for entry, jiggle start and extent, absorb any others
  /*
  fprintf(stdout,
	  "finishing chunk record at position %ld with addr %x\n",
	  i,
	  ((unsigned int)ret));
  */
  //chunk_cache[ret].start = ret;  
}

VOID
MallocAfter(THREADID tid,
	    ADDRINT ret) //return value
{
  AChunkCache::iterator it;
  stringstream s1;
  stringstream ss;
  ss << "pending";
  it = chunk_cache.find(ss.str());

  if(it == chunk_cache.end())
  {
    //didn't find a 'pending' entry
    fprintf(stderr,
	    "Warning: did not find a pending malloc()\n");
    fflush(stderr);
    return;
  }else{
    AllocatedChunk* ac = (*it).second;
    s1 << "" << ret;
    /*
    fprintf(stdout,
	    "updating ac->start (%d) to \"0x%x\" "
	    "and reinserting in chunk_cache[%s]\n",
	    ac->start,
	    ret,
	    s1.str().c_str());
    fflush(stdout);
    */
    ac->start = ret;
    chunk_cache[s1.str()] = ac;
    chunk_cache.erase(ss.str());
  }
  return;
}


/* ======================  HeapScan ========================== */

VOID
ScanMemory()
{
  //INT32 rvalue = 0;
  //rvalue = FindHeapBoundaries();
  // if(rvalue<0)
  // {
  //    std::cerr << "problem finding heap boundaries\n";
  //    return;
  // }

   //scan the heap for 0xDEADBEEF, output addresses of this data
   //ADDRINT i = 0;
   //UINT32* ptr = 0;
   //for(i=mg_heap_start;i<mg_heap_end;i++)
   //{
   //   ptr = ((UINT32*)i);
   //   if((*ptr) == 0xDEADBEEF)
   //   {
   //   std::cerr << "Found deadbeef at address: " << hex << i << dec << "\n";
   //   }
   //}
   return;
}

//-----------------------------------------------------------------
//-----------------  Instrumentation Routines  --------------------
//-----------------------------------------------------------------

/* ======================  MemTag  =========================== */

VOID
InjectMemTag(IMG img,
	     VOID *v)
{
  RTN memcpyRtn = RTN_FindByName(img, MEMCPY);
  RTN memmoveRtn = RTN_FindByName(img, MEMMOVE);
  //...

}

/* ======================  MemSniff ========================== */

VOID
InjectMemSniff(INS ins,
	       VOID *v)
{
   USIZE instr_length;
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
                               IARG_MEMORYREAD2_EA,
                               IARG_MEMORYREAD_SIZE,
                               IARG_END);
   }
}

/* ======================  MallocSniff ========================== */

/**
 * This instruments malloc (and varients) itself, not places where
 * malloc is called from. This is done statically as an image is loaded,
 * so it is cheap (rather than doing it JIT during runtime).
 */
VOID
InjectMallocSniff(IMG img,
		  VOID *v)
{
  RTN mallocRtn = RTN_FindByName(img, MALLOC);
  RTN freeRtn = RTN_FindByName(img, FREE);
  RTN reallocRtn = RTN_FindByName(img, REALLOC);

  if(RTN_Valid(mallocRtn))
  {
    RTN_Open(mallocRtn);
    RTN_InsertCall(mallocRtn,
		   IPOINT_BEFORE,
		   (AFUNPTR)MallocBefore,
		   IARG_THREAD_ID,
		   IARG_RETURN_IP,
		   IARG_G_ARG0_CALLEE,
		   IARG_END);
    RTN_InsertCall(mallocRtn,
		   IPOINT_AFTER,
		   (AFUNPTR)MallocAfter,
		   IARG_THREAD_ID,
		   IARG_G_RESULT0,
		   IARG_END);
    RTN_Close(mallocRtn);
  }

  if(RTN_Valid(freeRtn))
  {
    RTN_Open(freeRtn);
    RTN_InsertCall(freeRtn,
		   IPOINT_BEFORE,
		   (AFUNPTR)FreeBefore,
		   IARG_THREAD_ID,
		   IARG_RETURN_IP,
		   IARG_G_ARG0_CALLEE,
		   IARG_END);
    RTN_Close(freeRtn);
  }

  if(RTN_Valid(reallocRtn))
  {
    RTN_Open(reallocRtn);
    RTN_InsertCall(reallocRtn,
		   IPOINT_BEFORE,
		   (AFUNPTR)ReallocBefore,
		   IARG_THREAD_ID,
		   IARG_RETURN_IP,
		   IARG_G_ARG0_CALLEE,
		   IARG_G_ARG1_CALLEE,
		   IARG_END);
    RTN_InsertCall(reallocRtn,
		   IPOINT_AFTER,
		   (AFUNPTR)ReallocAfter,
		   IARG_THREAD_ID,
		   IARG_G_RESULT0,
		   IARG_END);
    RTN_Close(reallocRtn);
  }
  return;
}
  
/* ======================  HeapScan ========================== */

VOID 
InjectCmdShellAtRTN(RTN rtn,
		    VOID *v)
{
  string* rname;
  //m_current_rtn_name = &INVALID_RTN_NAME;
  if(TRUE==m_break_at_each_RTN)
  {
    //drop back into the shell, require 'run' to continue
    //this means injecting a call to "Prompt()" at IPOINT_BEFORE
    if(RTN_Valid(rtn))
    {
      RTN_Open(rtn);
      rname = new string(RTN_Name(rtn));
      RTN_InsertCall(rtn,
                     IPOINT_BEFORE,
		     (AFUNPTR)HDB_SetRTN_EntryContext,
		     IARG_PTR, rname,
		     IARG_THREAD_ID,
		     IARG_CONTEXT,
		     IARG_END);
      RTN_InsertCall(rtn,
                     IPOINT_BEFORE,
		     (AFUNPTR)HDB_Prompt,
		     IARG_END);
      RTN_Close(rtn);
    }
  }

  if(TRUE==m_break_after_each_RTN)
  {
    RTN_Open(rtn);
    RTN_InsertCall(rtn,
		   IPOINT_AFTER,
		   (AFUNPTR)HDB_Prompt,
		   IARG_END);
    RTN_Close(rtn);
  }

  RTN_Open(rtn);
  RTN_InsertCall(rtn,
		 IPOINT_AFTER,
		 (AFUNPTR)HDB_SetRTN_ExitContext,
		 IARG_END);
  RTN_Close(rtn);
}

VOID 
InjectCmdShellAtINS(INS ins,
		    VOID *v)
{
  if(TRUE==m_break_at_each_INS)
  {
    //drop back into the shell, require 'run' to continue
    //this means injecting a call to "Prompt()" at IPOINT_BEFORE
  }
  if(TRUE==m_break_after_each_INS)
  {
    //insert call to Prompt at IPOINT_AFTER
  }
}

/**
 * Heap scan at each routine. 
 *
 * We also need to use the memory R/W events analysis routines to
 * "tag" each data structure we discover with the set of R/W it has
 * experienced
 */
VOID
InjectHeapScanner(RTN rtn,
                  VOID *v)
{
  //string *trigger_function = new string("scan");
  //string *RTN_name = &INVALID_RTN_NAME;
  //m_current_rtn_name = &INVALID_RTN_NAME;
  //if(RTN_Valid(rtn))
  //{
  //RTN_name = new string(RTN_Name(rtn));
  //  m_current_rtn_name = new string(RTN_Name(rtn));
  //}

  // RTN_Open(rtn);
  // if(*trigger_function == *RTN_name)
  // {
  //    std::cout << "HeapScan: injecting into scan() routine\n";

  //    RTN_InsertCall(rtn,
  //                   IPOINT_BEFORE,
  //                  (AFUNPTR)ScanMemory,
  //                  IARG_END);
  // }
  // RTN_Close(rtn);
}

/**
 * A Debugging Routine to print out the ELF sections on Image load;
 * this function only prints out the sections for the main executable.
 */
VOID
ScanSections(IMG img,
             VOID *v)
{
   ADDRINT addr = 0;
   string SEC_name = "<null section name>";
   USIZE SEC_size = 0;

   if(FALSE==IMG_IsMainExecutable(img))
      return;

   for(SEC sec = IMG_SecHead(img); 
       SEC_Valid(sec); 
       sec = SEC_Next(sec))
   {
      if((SEC_Valid(sec)) && (SEC_Mapped(sec)==TRUE))
      {
         addr = SEC_Address(sec);
         SEC_name = SEC_Name(sec);
         SEC_size = SEC_Size(sec);
         m_sections_log << std::right << std::setw(20) << SEC_name << "  0x"
			<< std::left << std::setw(10) 
			<< std::hex << addr << std::dec << "  0x" 
			<< std::setw(6)
			<< std::hex << SEC_size << std::dec << "\n";
	 /*
	 fprintf(stdout,
		 "%20s %10x %6x\n",
		 SEC_name.c_str(),
		 ((UINT32)addr),
		 ((UINT32)SEC_size));
	 */
	 /*
         std::cout << SEC_name << "\t "
                   << hex << addr     << dec << "\t\t "
                   << hex << SEC_size << dec << "\n";
	 */
      }
   }
}

//-----------------------------------------------------------------
//------------------------  Entry Point     -----------------------
//-----------------------------------------------------------------


/**
 * Get global references to registers.
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

static VOID
HDB_Print_Startup_Message()
{
  long configured_for_pthreads = -1;
  long num_procs = -1;
  std::cout << "FreshDefense.net HDB (" << PROGRAM_VERSION << ")\n";
  std::cout << "Copyright (C) 2008-2009 Michael E. Locasto\n";
  std::cout << "All rights reserved.\n";
  std::cout << "There is NO WARRANTY, to the extent permitted by law.\n";

  configured_for_pthreads = sysconf(_SC_THREADS);
  num_procs = sysconf(_SC_NPROCESSORS_ONLN);
  if(configured_for_pthreads!=-1)
  {
    std::cout << "hdb can use pthreads\n";
  }
  if(-1!=num_procs)
  {
    fprintf(stdout,
	    "hdb sees %ld CPU%s\n",
	    num_procs,
	    (num_procs==1) ? "" : "s" );
  }
  m_supervised_pid = getpid();
  std::cout << "hdb supervising process ID: " << m_supervised_pid << "\n";
  //std::cout << "hdb has process ID: " << PIN_GetPid() << "\n";
}


/**
 * Entry point for the tool. The startup phase has three responsibilities:
 *
 *  0. load data definitions (or go into "deduce" mode, currently unsupported)
 *  1. intercept every malloc, realloc, and free (and sbrk)
 *  2. intercept every instr for read/writes to/from addr w/ content & length
 *
 *  During subsequent operation, at each breakpoint (instruction or
 *     function), HeapScan according to the grammar.
 *
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

  SetupRegisters();

  /** Hello. */
  HDB_Print_Startup_Message();

  IMG_AddInstrumentFunction(ScanSections, 0);
  //SEC_AddInstrumentFunction(ScanSections, 0);
  
  /** initial chance to set and select breakpoints and watchpoints */
  HDB_Prompt();
  
  /** Pay attention to each memory event */
  INS_AddInstrumentFunction(InjectMemSniff, 0);
  
  /** monitor malloc, realloc, and free to <i>know</i> where heap data is */
  IMG_AddInstrumentFunction(InjectMallocSniff, 0);

  /** monitor memcpy, memove and friends... */
  IMG_AddInstrumentFunction(InjectMemTag, 0);
  
  /** at function granularity, monitor state of object map in heap */
  RTN_AddInstrumentFunction(InjectHeapScanner, 0);

  /** inject a check for dropping back to HDB shell */
  RTN_AddInstrumentFunction(InjectCmdShellAtRTN, 0);
  /** inject a check for dropping back to HDB shell */
  INS_AddInstrumentFunction(InjectCmdShellAtINS, 0);
  
  /** cleanup shutdown hook */
  PIN_AddFiniFunction(Fini, 0);
  
  // Never returns
  PIN_StartProgram();
  
  return 0;
}
