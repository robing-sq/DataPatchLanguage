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

#ifndef __MALLOCSNIFF_HPP_
#define __MALLOCSNIFF_HPP_

#include "pin.H"
#include <map>

#define MALLOC                 "malloc"
#define CALLOC                 "calloc"
#define REALLOC                "realloc"
#define FREE                   "free"

#define BCOPY                  "bcopy"
#define MEMCCPY                "memccpy"
#define MEMCPY                 "memcpy"
#define MEMMOVE                "memmove"
#define MEMSET                 "memset"
#define BZERO                  "bzero"
#define SWAB                   "swab"

#define MEMFROB                "memfrob"
#define STRFRY                 "strfry"

//#define MAX_TRACKED_CHUNKS     1000

/**
 * The heap map keeps track of all the allocated chunks of memory so
 * that HeapScan can search this list rather than iterating over the
 * entire heap itself.
 */
typedef struct _heap_meta_map
{
  ADDRINT heap_start;
  ADDRINT heap_end;
  UINT64 chunks_freed; //cumulative number of chunks ever freed
  UINT64 chunks_allocated; //currently allocated level of chunks
  UINT64 chunk_high_water_mark; //total chunks allocated ever
}HeapMetaMap;

/**
 * An element of a collection representing all chunks that have been
 * allocated on the heap. This collection (of which this type serves to
 * define a node) serves as a cache or hot-list through which to search
 * for resident data strutures. This collection exists as an alternative
 * to enumerating the entire heap (much of which will be unallocated
 * in many situations, forcing us to handle needless SIGSEGVs).
 *
 * Each chunk can be marked up or tagged with a set of type hints; the
 * chunk can hold a "list node type 123456", for example. Type hints
 * are currently maintained in a string delimited by a colon.
 *
 * Upon free() or realloc(), we have to search the collection and update
 * the appropriate AllocatedChunk node. Arranging them in a better
 * structure than a linked list would ease this lookup cost.
 */
typedef struct _alloc_chunk
{
  /** start address of this chunk (not including malloc meta-data) */
  ADDRINT start;
  /** number of bytes to this chunk, not including malloc
   meta-data. TODO: Can differ from the number of bytes
   <i>requested</i> by a malloc caller. This value recorded here is
   the number of bytes actually returned by malloc.*/
  UINT32 extent;
  /** Record, in a colon-delimited list, what types we believe reside here */
  string* type_hints;
  /** Is it likely that this chunk is a starting point for a data structure? */
  BOOL is_root;
}AllocatedChunk;

//'key' is "pending+eip" or just "eip+ret"
typedef std::map<std::string, AllocatedChunk*> AChunkCache;

BOOL MALLOCSNIFF_AddChunkToCollections(AllocatedChunk* ac);

#endif
