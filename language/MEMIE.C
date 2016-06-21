/***************************************************************************
 *  MemImporterExporter
 *  Copyright (C) 2012 Michael E. Locasto and Robin Gonzalez
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
 * $Id: MemImEx.C,v 0.1
 **************************************************************************/
#include <stdio.h>
#include "pin.H"
#include <string.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <mysql.h>
#include <my_global.h>
#include <gelf.h>
#include <libdwarf.h>
#include <dwarf.h>
#include <libelf.h>

MYSQL * conn;
FILE *fp;
int pid;

Dwarf_Debug debug = 0;
int fd;
const char *filepath = "<stdin>";
int res = DW_DLV_ERROR;
Dwarf_Error error;
Dwarf_Handler errhand = 0;
Dwarf_Ptr errarg = 0;

//************************************************************************
//			  DWARF AND ELF PARSING
//		     credits to: open-source libdwarf
//                         and David Anderson
//************************************************************************


struct srcfilesdata {
    char ** srcfiles;
    Dwarf_Signed srcfilescount;
    int srcfilesres;
};

Dwarf_Die get_structure_type(Dwarf_Die return_sibling, Dwarf_Debug dbg);
int isStructure(Dwarf_Debug dbg, Dwarf_Off offset);
VOID lookup_struct(Dwarf_Die print_me, Dwarf_Debug dbg);
VOID mysql_tables_GDdebug_STRUCT(MYSQL * conn, char * name);
VOID mysql_fill_GDdebug_STRUCT(MYSQL * conn, char * data_type, char * data_name);
VOID mysql_fill_GDdebug_CHAR(MYSQL * conn, char * data_type, char * data_name, const char * type, Dwarf_Unsigned bytesize);
VOID mysql_fill_GDdebug_INT(MYSQL * conn, char * data_type, char * data_name, const char * type, Dwarf_Unsigned bytesize);
VOID lookup_type(Dwarf_Debug dbg, Dwarf_Off offset, char * name_var, Dwarf_Off re_off);
VOID mysql_fill_GDdebug(MYSQL * conn, char * data_type, char * data_name, const char * type, Dwarf_Unsigned bytesize);
static void read_cu_list(Dwarf_Debug dbg);
static void print_die_data(Dwarf_Debug dbg, Dwarf_Die print_me,int level,
   struct srcfilesdata *sf);
static void get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die,int in_level, struct srcfilesdata *sf);
static void resetsrcfiles(Dwarf_Debug dbg,struct srcfilesdata *sf);


VOID
dwarf_parse()
{
    Dwarf_Debug dbg = 0;
    int fd = -1;
    const char *filepath = "<stdin>";
    int res = DW_DLV_ERROR;
    Dwarf_Error error;
    Dwarf_Handler errhand = 0;
    Dwarf_Ptr errarg = 0;

    
    fd = open("/home/robingonzalez/Downloads/pin/source/tools/MEMIE/process",O_RDONLY);

    if(fd < 0) {
        printf("Failure attempting to open \"%s\"\n",filepath);
    }
    res = dwarf_init(fd,DW_DLC_READ,errhand,errarg, &dbg,&error);
    if(res != DW_DLV_OK) {
        printf("Giving up, cannot do DWARF processing\n");
        exit(1);
    }
    
    read_cu_list(dbg);
    res = dwarf_finish(dbg,&error);
    if(res != DW_DLV_OK) {
        printf("dwarf_finish failed!\n");
    }
    close(fd);
}

static void 
read_cu_list(Dwarf_Debug dbg)
{
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Unsigned next_cu_header = 0;
    Dwarf_Error error;
    int cu_number = 0;

    for(;;++cu_number) {
        struct srcfilesdata sf;
        sf.srcfilesres = DW_DLV_ERROR;
        sf.srcfiles = 0;
        sf.srcfilescount = 0;
        Dwarf_Die no_die = 0;
        Dwarf_Die cu_die = 0;
        int res = DW_DLV_ERROR;
        res = dwarf_next_cu_header(dbg,&cu_header_length,
            &version_stamp, &abbrev_offset, &address_size,
            &next_cu_header, &error);

        if(res == DW_DLV_ERROR) {
            printf("Error in dwarf_next_cu_header\n");
            exit(1);
        }
        if(res == DW_DLV_NO_ENTRY) {
            /* Done. */
            return;
        }
        /* The CU will have a single sibling, a cu_die. */
        res = dwarf_siblingof(dbg,no_die,&cu_die,&error);
        if(res == DW_DLV_ERROR) {
            printf("Error in dwarf_siblingof on CU die \n");
            exit(1);
        }
        if(res == DW_DLV_NO_ENTRY) {
            /* Impossible case. */
            printf("no entry! in dwarf_siblingof on CU die \n");
            exit(1);
        }
        get_die_and_siblings(dbg, cu_die, 0, &sf);
        dwarf_dealloc(dbg,cu_die,DW_DLA_DIE);
        resetsrcfiles(dbg,&sf);
    }
}

static void
get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die, int in_level, struct srcfilesdata *sf)
{
    //Dwarf_Off return_offset;
    int res = DW_DLV_ERROR;
    Dwarf_Die cur_die=in_die;
    Dwarf_Die child = 0;
    Dwarf_Error error;

    print_die_data(dbg,in_die,in_level,sf);

    for(;;) {	

        Dwarf_Die sib_die = 0;
        res = dwarf_child(cur_die,&child,&error);
	
        if(res == DW_DLV_ERROR) {
            printf("Error in dwarf_child , level %d \n",in_level);
            exit(1);
        }
        if(res == DW_DLV_OK) {
            get_die_and_siblings(dbg,child,in_level+1,sf);
        }
        /* res == DW_DLV_NO_ENTRY */
        res = dwarf_siblingof(dbg,cur_die,&sib_die,&error);
        if(res == DW_DLV_ERROR) {
            printf("Error in dwarf_siblingof , level %d \n",in_level);
            exit(1);
        }
        if(res == DW_DLV_NO_ENTRY) {
            /* Done at this level. */
            break;
        }
        /* res == DW_DLV_OK */
        if(cur_die != in_die) {
            dwarf_dealloc(dbg,cur_die,DW_DLA_DIE);
        }
        cur_die = sib_die;
        print_die_data(dbg,cur_die,in_level,sf);
    }
    return;
}

static void
resetsrcfiles(Dwarf_Debug dbg,struct srcfilesdata *sf)
{
    Dwarf_Signed sri = 0;
    for (sri = 0; sri < sf->srcfilescount; ++sri) {
        dwarf_dealloc(dbg, sf->srcfiles[sri], DW_DLA_STRING);
    }
    dwarf_dealloc(dbg, sf->srcfiles, DW_DLA_LIST);
    sf->srcfilesres = DW_DLV_ERROR;
    sf->srcfiles = 0;
    sf->srcfilescount = 0;
}

static void
print_die_data(Dwarf_Debug dbg, Dwarf_Die print_me,int level,
    struct srcfilesdata *sf)
{
    char *name = 0;
    Dwarf_Error error = 0;
    Dwarf_Half tag = 0;
    const char *tagname = 0;
    int localname = 0;
    Dwarf_Off return_offset;

    Dwarf_Signed atcnt;
    Dwarf_Attribute * atlist;

    int res = dwarf_diename(print_me,&name,&error);

    if(res == DW_DLV_ERROR) {
        printf("Error in dwarf_diename , level %d \n",level);
        exit(1);
    }
    if(res == DW_DLV_NO_ENTRY) {
        name = "<no DW_AT_name attr>";
        localname = 1;
    }
    res = dwarf_tag(print_me,&tag,&error);
    if(res != DW_DLV_OK) {
        printf("Error in dwarf_tag , level %d \n",level);
        exit(1);
    }
   
    res = dwarf_get_TAG_name(tag,&tagname);
    if(res != DW_DLV_OK) {
        printf("Error in dwarf_get_TAG_name , level %d \n",level);
        exit(1);
    }    

    if(tag == 52){ //VARIABLES
        res = dwarf_attrlist(print_me, &atlist, &atcnt, &error);
        if(res == DW_DLV_OK){
	        for(int i = 0; i < atcnt; ++i){
	            res = dwarf_global_formref(atlist[i], &return_offset, &error);
		        if(res == DW_DLV_OK){
                    	    lookup_type(dbg, return_offset, name, 0);
                    	    dwarf_dealloc(dbg, atlist[i], DW_DLA_ATTR);
                        }
                }
	}
        dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
    }
    /*
    if(tag == 22){ //TYPEDEF
        structure_type = get_structure_type(print_me, dbg);
        if (structure_type != NULL) {
	    res = dwarf_tag(structure_type,&tag_struct,&error);
            if(res != DW_DLV_OK) {
                printf("Error");
                exit(1);
            }
	    cout << tag_struct << "\n";
            if(tag_struct == 19)
	        lookup_struct(structure_type, dbg);
        }
    }

    if(tag == 19){
	lookup_struct(print_me, dbg);
    }*/

    if(!localname) {
        dwarf_dealloc(dbg,name,DW_DLA_STRING);
    }
}

VOID 
lookup_type(Dwarf_Debug dbg, Dwarf_Off offset, char * name_var, Dwarf_Off return_offset){
    int res2;
    Dwarf_Unsigned bytesize = 0;
    char *name = 0;
    Dwarf_Die prev_die = 0;
    Dwarf_Die next_die = 0;
    Dwarf_Error error;
    int res;
    Dwarf_Half tag = 0;
    const char * tagname;

    Dwarf_Signed atcnt;
    Dwarf_Attribute * atlist;

//THIS PART IS TO BE ABLE TO GRAB THE FIRST TYPE ENCOUNTERED (PTR, CONST, etc)
    res = dwarf_offdie(dbg, offset, &prev_die, &error);
    
    if(return_offset == 0){
	res = dwarf_offdie(dbg, offset, &next_die, &error);
    }
    else{
        res = dwarf_offdie(dbg, offset, &next_die, &error);    
    }

    res = dwarf_tag(prev_die,&tag,&error);
    if(res != DW_DLV_OK) {
        printf("Error");
        exit(1);
    }
  
    res = dwarf_get_TAG_name(tag,&tagname);
    if(res != DW_DLV_OK) {
        printf("Error");
        exit(1);
    }

    if(res == DW_DLV_OK){
        res = dwarf_diename(next_die,&name,&error); 
        res2 = dwarf_bytesize(next_die, &bytesize, &error);

        if(res == DW_DLV_NO_ENTRY) {
           res = dwarf_attrlist(next_die, &atlist, &atcnt, &error);
           if(res == DW_DLV_OK){
	      for(int i = 0; i < atcnt; ++i){
	          res = dwarf_global_formref(atlist[i], &return_offset, &error);
		  if(res == DW_DLV_OK){	 
			lookup_type(dbg, return_offset, name_var, 1);
		  }
                  dwarf_dealloc(dbg, atlist[i], DW_DLA_ATTR);
	      }
	   }
           dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
   	}

        else if(res == DW_DLV_OK){
                mysql_fill_GDdebug(conn, name_var, name, tagname, bytesize);
	}
    }
}

VOID
lookup_struct(Dwarf_Die print_me, Dwarf_Debug dbg){
    Dwarf_Die get_type;
    Dwarf_Die return_kid;
    Dwarf_Error error;
    Dwarf_Half tag;
    const char * tagname = 0;
    Dwarf_Die return_sibling;
    char * name_sib = 0;
    char * name_child = 0;
    int i = 1;
    Dwarf_Off offset;
    int is_structure;
    Dwarf_Signed atcnt;
    Dwarf_Attribute * atlist;
    char * name = 0;

    res = dwarf_diename(print_me,&name,&error);
    
    int res = dwarf_child(print_me, &return_kid, &error);  
    if(res == DW_DLV_OK){
        res = dwarf_tag(return_kid, &tag, &error);
        if(res != DW_DLV_OK) {
            printf("Error in dwarf_tag");
            exit(1);
        }
        res = dwarf_get_TAG_name(tag, &tagname);
        if(res != DW_DLV_OK) {
             printf("Error in dwarf_get_TAG_name");
             exit(1);
        }
	res = dwarf_diename(return_kid,&name_child,&error);
        int res2 = dwarf_siblingof(dbg, return_kid, &return_sibling, &error);
        if(res2 == DW_DLV_OK){
	    do{
	        i++; //NUMBER OF CHILDREN
 	        res2 = dwarf_siblingof(dbg, return_sibling, &return_sibling, &error);
	        res = dwarf_diename(return_sibling,&name_sib,&error);
	        //mysql_fill_GDdebug_STRUCT(conn, name, name3);
	        res = dwarf_attrlist(return_sibling, &atlist, &atcnt, &error);
                if(res == DW_DLV_OK){
	            for(int i = 0; i < atcnt; ++i){
	                res = dwarf_global_formref(atlist[i], &offset, &error);
            	        if(res == DW_DLV_OK){
		            is_structure = isStructure(dbg, offset);
			    if(is_structure == 1){
			        get_type = get_structure_type(return_sibling, dbg);
				lookup_struct(get_type, dbg);
		            }
		            dwarf_dealloc(dbg, atlist[i], DW_DLA_ATTR);
                        }
                    }
                    dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
	        }
	    }while(res2 == DW_DLV_OK);
	}	
	cout << "NUMBER OF CHILDREN in " << i << "\n";
    }
}

Dwarf_Die
get_structure_type(Dwarf_Die return_sibling, Dwarf_Debug dbg){
    Dwarf_Attribute * atlist;
    Dwarf_Signed atcnt;
    Dwarf_Off offset = 0;
    Dwarf_Die print_me = NULL;
    int res2;

    res = dwarf_attrlist(return_sibling, &atlist, &atcnt, &error);
    if(res == DW_DLV_OK){
	for(int i = 0; i < atcnt; ++i){
	    res2 = dwarf_global_formref(atlist[i], &offset, &error);
	    if(res2 == DW_DLV_OK){	
	        res = dwarf_offdie(dbg, offset, &print_me, &error);
            }
	    dwarf_dealloc(dbg, atlist[i], DW_DLA_ATTR);
	}
	dwarf_dealloc(dbg, atlist, DW_DLA_LIST);    
    }
    return print_me;
}

int
isStructure(Dwarf_Debug dbg, Dwarf_Off offset){
    Dwarf_Die print_me;    
    Dwarf_Error error;
    int result;
    Dwarf_Half tag;
    const char * tagname = 0;
    char * name = 0;

    res = dwarf_offdie(dbg, offset, &print_me, &error);
    
    res = dwarf_tag(print_me, &tag, &error);
    if(res != DW_DLV_OK) {
        printf("Error in dwarf_tag");
        exit(1);
    }
    res = dwarf_get_TAG_name(tag, &tagname);
    if(res != DW_DLV_OK) {
        printf("Error in dwarf_get_TAG_name");
        exit(1);
    }        
    res = dwarf_diename(print_me,&name,&error);
    if(res != DW_DLV_OK){
	return 0;
    } 
    result = strncmp(tagname, "DW_TAG_structure_type", 100);
    if(result == 0)
        return 1;
    else
	return 0;
}

//************************************************************************
//				ELF PARSING
//************************************************************************


//************************************************************************
//			    MYSQL STATEMENTS     
//                     credits to: Connector API                                             
//************************************************************************

INT32 
Usage()
{
    PIN_ERROR("This tool prints a log of image load and unload events\n"
             + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

VOID 
mysql(MYSQL * conn)
{
   if(mysql_real_connect(conn, "localhost", "root", "trial", NULL, 0, NULL, 0) == NULL){
	printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
   
   else{
	printf("Connection successful\n");
   }

   if (mysql_query(conn, "create database robin")) {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }

   if (mysql_query(conn, "use robin")){
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      exit(1);
   }
  
  /*if (mysql_query(conn, "drop database test")) {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
  }*/
}

VOID
mysql_fill_DS(MYSQL * conn, char * sec_address, const string & sec_name, char * sec_data, USIZE sec_size, SEC_TYPE sec_type, string sec_exec, string sec_read, string sec_write)
{
   std::stringstream ss;
   ss << "INSERT INTO data_structures(section_address, section_name, section_data, section_size, section_type, executable, readable, writable) VALUES('" << sec_address << "', '" << sec_name << "', '" << sec_data << "', '" << sec_size << "', '" << sec_type << "', '" << sec_exec << "', '" << sec_read << "', '"<< sec_write <<"')";
   
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_tables_DS(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE data_structures(section_address VARCHAR(20), section_name VARCHAR(30), section_data VARCHAR(50), section_size VARCHAR(10), section_type VARCHAR(30), executable VARCHAR(4), readable VARCHAR(4), writable VARCHAR(4))")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

//***********************************************************
//		GLOBAL VARIABLES
//***********************************************************

VOID 
mysql_tables_GDdata(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE global_variables_DATA(data_type VARCHAR(50))")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_tables_GDbss(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE global_variables_BSS(data_type VARCHAR(50))")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_tables_GDrodata(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE global_variables_RODATA(data_type VARCHAR(50))")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_tables_GDdebug(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE DEBUG(name VARCHAR(50), type_name VARCHAR(50), type VARCHAR(50), bytesize VARCHAR(5))")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_tables_GDdebug_INT(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE DEBUG_INT(name VARCHAR(50), type_name VARCHAR(50), type VARCHAR(50), bytesize VARCHAR(5))")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_tables_GDdebug_CHAR(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE DEBUG_CHAR(name VARCHAR(50), type_name VARCHAR(50), type VARCHAR(50), bytesize VARCHAR(5))")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_tables_GDdebug_STRUCT(MYSQL * conn, char * name)
{
   std::stringstream ss;
   ss << "CREATE TABLE " << name << "(name VARCHAR(50), type_name VARCHAR(50), type VARCHAR(50), bytesize VARCHAR(5))";
  
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

//******************************************************************
//		FILLING GLOBAL_VARIABLES TABLES
//******************************************************************

VOID 
mysql_fill_GD(MYSQL * conn, int data)
{
   std::stringstream ss;
   ss << "INSERT INTO global_variables(data_type) VALUES('" << data << "')";
   
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_fill_GDdata(MYSQL * conn, char * data)
{
   std::stringstream ss;
   ss << "INSERT INTO global_variables_DATA(data_type) VALUES('" << data << "')";
  
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_fill_GDbss(MYSQL * conn, char * data)
{
   std::stringstream ss;
   ss << "INSERT INTO global_variables_BSS(data_type) VALUES('" << data << "')";
   
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_fill_GDrodata(MYSQL * conn, char * data)
{
   std::stringstream ss;
   ss << "INSERT INTO global_variables_RODATA(data_type) VALUES('" << data << "')";
   
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_fill_GDdebug(MYSQL * conn, char * data_name, char * data_type, const char * type, Dwarf_Unsigned bytesize)
{
   std::stringstream ss;
   ss << "INSERT INTO DEBUG(name, type_name, type, bytesize) VALUES('" << data_name << "', '" << data_type << "', '" << type << "', '" << bytesize << "')";
   
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_fill_GDdebug_INT(MYSQL * conn, char * data_name, char * data_type, const char * type, Dwarf_Unsigned bytesize)
{
   std::stringstream ss;
   ss << "INSERT INTO DEBUG_INT(name, type_name, type, bytesize) VALUES('" << data_name << "', '" << data_type << "', '" << type << "', '" << bytesize << "')";
   
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_fill_GDdebug_PTR(MYSQL * conn, char * data_name, char * data_type, const char * type, Dwarf_Unsigned bytesize)
{
   std::stringstream ss;
   ss << "INSERT INTO DEBUG_PTR(name, type_name, type, bytesize) VALUES('" << data_name << "', '" << data_type << "', '" << type << "', '" << bytesize << "')";
   
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_fill_GDdebug_CHAR(MYSQL * conn, char * data_name, char * data_type, const char * type, Dwarf_Unsigned bytesize)
{
   std::stringstream ss;
   ss << "INSERT INTO DEBUG_CHAR(name, type_name, type, bytesize) VALUES('" << data_name << "', '" << data_type << "', '" << type << "', '" << bytesize << "')";
   
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

//*********************************************************************
//		   MYSQL Searching and Inserting
//*********************************************************************

VOID 
mysql_CREATE_int(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE int_TAB AS (SELECT * FROM DEBUG WHERE type_name = \"int\" AND (type = \"DW_TAG_BASE_TYPE\" OR type = \"DW_TAG_CONST_TYPE\"));")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_CREATE_char(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE char_TAB AS (SELECT * FROM DEBUG WHERE type_name = \"char\" AND (type = \"DW_TAG_BASE_TYPE\" OR type = \"DW_TAG_CONST_TYPE\"));")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_CREATE_ptr(MYSQL * conn)
{
   if (mysql_query(conn, "CREATE TABLE ptr_TAB AS (SELECT * FROM DEBUG WHERE type = \"DW_TAG_POINTER_TYPE\");")) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}

VOID 
mysql_fill_GDdebug_STRUCT(MYSQL * conn, char * name, char * var)
{
   std::stringstream ss;
   ss << "INSERT INTO " << name << "(type_name) VALUES(" << var << ");";
   
   const std::string& temp = ss.str();
   const char* cstr = temp.c_str();
   if (mysql_query(conn,cstr)) 
   {
      printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
   }
}


//***************************************************
//	       PIN TOOL FUNCTIONS
//          credits to: PIN Tools API
//***************************************************

// This function is called when the application exits
// It closes the output file.
VOID 
Fini(INT32 code, VOID *v)
{
    cout << "Thanks for using the program";
}


VOID 
data_reader(ADDRINT sec_address, unsigned int sec_data, const string & sec_name, USIZE sec_size)
{
    ADDRINT sec_da;
    ADDRINT * ptr = NULL;
    int data;
    char buf [50] = {0};

    if (sec_name == ".data" || sec_name == ".rodata" || sec_name == ".bss")
    {
	for (sec_da = sec_address; sec_da < sec_address + sec_size;)
	{
	    ptr = ((ADDRINT *) sec_da);
	    data = *ptr;
	    if(sec_name == ".data"){
		sprintf(buf,"%x", data);
	        mysql_fill_GDdata(conn, buf);
	    }
	    else if(sec_name == ".bss"){
		sprintf(buf,"%x", data);
		mysql_fill_GDbss(conn, buf);
	    }
	    else if(sec_name == ".rodata"){
		sprintf(buf,"%x", data);
		mysql_fill_GDrodata(conn, buf);
	    }
	    ptr++;
	    sec_da++;
	}
    }
} 

VOID
MemoryImporterExporter(IMG img, VOID *v)
{
    char sec_ad [50] = {0};
    char data_st [50] = {0};
    const void * sec_data;
    ADDRINT sec_address;
    USIZE sec_size;
    SEC_TYPE sec_type;
    string sec_readable, sec_writeable, sec_executable;
    unsigned int data_start;
 
    for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
    {
	sec_readable = "NO";
	sec_writeable = "NO";
	sec_executable = "NO";

	sec_address = SEC_Address(sec);
	const string & sec_name = SEC_Name (sec);
	sec_data = SEC_Data(sec);
	sec_size = SEC_Size(sec);
	sec_type = SEC_Type (sec); 

	//PERMISSIONS SETTINGS FOR SECTIONS

	if(SEC_IsExecutable(sec)){
	    sec_executable = "YES";
	}

	if(SEC_IsReadable(sec)){
	    sec_readable = "YES";
	}

	if(SEC_IsWriteable(sec)){
	    sec_writeable = "YES";
	}

	sprintf(sec_ad,"%X", sec_address);

	data_start = ((unsigned int) sec_data);
	sprintf(data_st,"%X", data_start); 

	mysql_fill_DS(conn, sec_ad, sec_name, data_st, sec_size, sec_type, sec_executable, sec_readable, sec_writeable);

	data_reader(sec_address, data_start, sec_name, sec_size); 
    }
}

VOID
routines_parser(){

}

int
get_file_path(int pid)
{
    const char * file_path;
    char * path = new char[1035];
    std::stringstream ss;
    ss << "readlink /proc/" << pid << "/exe";
    const std::string& temp = ss.str();
    const char* cstr = temp.c_str();   


    fp = popen(cstr, "r");
    if (fp == NULL) {
      printf("Failed to run command\n" );
      exit(1);
    }

    while (fgets(path, sizeof(path)-1, fp) != NULL) {
	fputs(path, fp);
    }

    pclose(fp);
    file_path = (const char *) path;

    fd = open("/home/robingonzalez/Downloads/pin/source/tools/MEMIE/process",O_RDONLY);
  
    return fd;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int 
main(int argc, char * argv[])
{

    // Initialize symbol processing
    PIN_InitSymbols();

    conn = mysql_init(NULL);

    pid = PIN_GetPid();
    fd = get_file_path(pid);

    if(conn == NULL){
        printf("ERROR %u: %s\n", mysql_errno(conn), mysql_error(conn));
    }

    mysql(conn);

    mysql_tables_DS(conn);    
    mysql_tables_GDdebug(conn);
    mysql_tables_GDdebug_CHAR(conn);
    mysql_tables_GDdebug_INT(conn);
    mysql_tables_GDdata(conn);
    mysql_tables_GDbss(conn);
    mysql_tables_GDrodata(conn);

    dwarf_parse();
    
    mysql_CREATE_int(conn);
    mysql_CREATE_char(conn);
    mysql_CREATE_ptr(conn);

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    IMG_AddInstrumentFunction(MemoryImporterExporter, 0);

    PIN_AddFiniFunction(Fini, 0);
    
    PIN_StartProgram();
    
    PIN_RemoveFiniFunctions();	
    PIN_Detach();

    return 0;
}
