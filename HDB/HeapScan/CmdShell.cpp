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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pin.H"
#include "CmdShell.hpp"
#include "HeapScan.hpp"

//size_t COMMAND_SIZE = 81;

//control framework for command line interpreter

/** 
 * 1. provide debugger prompt
 * 2. enable setting watchpoints
 * 3. enable output of semantically meaningful identifiers for
 *    code sections or ranges or routines. Support for interacting
 *    with and querying the table of code range -> data structure map
 * 4. enable modification of granularity of "heapscan" (per instr or
 *     per function)
 * 5. enable automated learning of grammar map (unsupported)
 * 6. load new grammar (i.e., data structure definition file .dsd)
 * 7. ???
 */

/** 
 * Set initial break and watch points so we can get back to
 * a prompt and examine all these lovely memory events and
 * data structures.
 *
 * 'enable memsniff'
 * 'enable mallocsniff'
 * 'enable heapscan [granularity]'
 * 'break ins'
 * 'break rtn'
 * 'watch <address>'
 * 'watch (expression)'
 * 'be quiet' //shut off spewing of MemSniff to stdout
 *
 * promp string gives context [prefix] == mode, [prompt], suffix=context
 */
/*
VOID
HDB_Prompt_scanf()
{
  char* command = NULL;
  string commandline = "";
  UINT32 lineNum = 0;
  string prefix = "";
  //string suffix = "";
  //stringstream ss;

  if(FALSE==m_is_initial_prompt)
  {
    if(FALSE==m_break_at_each_RTN)
    {
      return;
    }
    //same for others...
  }
  m_is_initial_prompt = FALSE;

  
  command = (char*)calloc(COMMAND_SIZE, sizeof(char));
  if(NULL==command)
  {
    fprintf(stderr,
	    "failed to allocate space for user input\n");
    return;
  }
  command[COMMAND_SIZE] = '\0';

  //suffix = "-" + m_current_rtn_name;
  
  if(m_current_rtn_name->find(INVALID_RTN_NAME)!=string::npos)
  {
    ss << "-" << m_current_rtn_name;
    suffix = ss.str();
  }

  fflush(stdout);
  for(;;)
  {
    fprintf(stdout,
	    "(%shdb) ",
	    prefix.c_str());
	    //suffix.c_str());

    commandline = ReadLine(std::cin, &lineNum);
    std::cerr << "i read: [" << commandline << "]\n";
    command = commandline.c_str();

    fscanf(stdin,
	   "%s",
	   command);
    command[COMMAND_SIZE] = '\0';    
    

    if("x-"==prefix)
    {
      //read in 'addr', print the value
      unsigned int addr = 0;
      int* addr_ptr = 0;
      fscanf(stdin,
	     "%s",
	     command);
      command[COMMAND_SIZE]='\0';
      addr = atoi(command);
      addr_ptr = (int*)addr;
      fprintf(stdout,
	      "%x contains value: %x\n",
	      addr,
	      *addr_ptr);
      prefix = "";
      free(command);
      command=NULL;
    }

    if(0==strncmp("run",
		  command,
		  3))
    {
      //same as 'cont' or 'continue' to next breakpoint
      free(command);
      command=NULL;
      return;
    }else if(0==strncmp("version",
			command,
			7)){
      fprintf(stdout,
	      "%s %s\n",
	      PROGRAM_NAME.c_str(),
	      PROGRAM_VERSION.c_str());
    }else if(0==strncmp("x",
			command,
			1)){
      //print out memory
      prefix = "x-";
    }else if(0==strncmp("tighten",
			command,
			7)){
      //ignore all set breakpoints. alternatives: fix, cont
      m_break_at_each_INS = FALSE;
      m_break_after_each_INS = FALSE;
      m_break_at_each_RTN = FALSE;
      m_break_after_each_RTN = FALSE;
    }else if(0==strncmp("info(memory)",
			command,
			12)){
      HDB_PrintMemorySummary();
    }else if(0==strncmp("info(mem)",
			command,
			9)){
      HDB_PrintMemorySummary();
    }else if(0==strncmp("info(reg)",
			command,
			9)){
      HDB_PrintRegisters();
    }else if(0==strncmp("info(registers)",
			command,
			15)){
      HDB_PrintRegisters();
    }else if(0==strncmp("info(function)",
			command,
			14)){
      HDB_PrintCurrentFunction();
    }else if(0==strncmp("info(rtn)",
			command,
			9)){
      HDB_PrintCurrentFunction();
    }else if(0==strncmp("break(rtn,before)",
			command,
			17)){
      fprintf(stdout,
	      "hdb will return to prompt before each function entry\n");
      m_break_at_each_RTN = TRUE;
    }else if(0==strncmp("break(ins,before)",
			command,
			17)){
      fprintf(stdout,
	      "hdb will return to prompt before each instruction\n");
      m_break_at_each_INS = TRUE;

    }else if(0==strncmp("break(rtn,after)",
			command,
			16)){
      fprintf(stdout,
	      "hdb will return to prompt after each function (immediately before function exit)\n");
      m_break_after_each_RTN = TRUE;
    }else if(0==strncmp("break(ins,before)",
			command,
			16)){
      fprintf(stdout,
	      "hdb will return to prompt after each instruction\n");
      m_break_after_each_INS = TRUE;
    }else if(0==strncmp("info(sections)",
			command,
			14)){
      HDB_PrintSectionTable();
    }else if(0==strncmp("scan",
			command,
			4)){
      HDB_FindHeapBoundaries();
      //report on actual allocated chunks (this is the search space, not
      // the entire heap --- for most programs...)
      //ReportOnMallocdChunks();
      //ScanForDataStructures();
      //ReportDataStructures();
    }else if(0==strncmp("help",
			command,
			4)){
      fprintf(stdout,
	      "you cannot be helped at this time\n");
    }else if(0==strncmp("\0",
			command,
			1)){
      free(command);
      command=NULL;
      return;
    }
    memset(command, '\0', COMMAND_SIZE);
  }

  free(command);
  command=NULL;
}
*/
