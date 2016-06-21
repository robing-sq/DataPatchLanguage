##############################################################
#
# Here are some things you might want to configure
#
##############################################################

#TARGET_COMPILER?=ms
TARGET_COMPILER?=gnu
MEMIE_VERSION=0.01

##############################################################
#
# include *.config files
#
##############################################################

ifeq ($(TARGET_COMPILER),gnu)
    include ../makefile.gnu.config
    LINK?=${CXX}
    CXXFLAGS ?= -I/usr/include/mysql -I$(PIN_HOME)/InstLib -fomit-frame-pointer -Wall -Werror -Wno-unknown-pragmas $(DBG) $(OPT) -MMD -I/usr/include/libdwarf
endif

ifeq ($(TARGET_COMPILER),ms)
    include ../makefile.ms.config
    DBG?=
endif

##############################################################
#
# Tools sets
#
##############################################################

TOOL_ROOTS = MEMIE

TOOLS = $(TOOL_ROOTS:%=%$(PINTOOL_SUFFIX))

all: tools
tools: $(TOOLS)
test: $(TEST_TOOLS:%=%.test)
tests-sanity: $(SANITY_TOOLS:%=%.test)

distro: tools
	tar -cf MEMIE-$(MEMIE_VERSION).tar memie MEMIE pin LICENSE README MEMIE.C
	gzip MEMIE-$(MEMIE_VERSION).tar

## build rules

%.o : %.C
	${CXX} ${COPT} $(CXXFLAGS) ${PIN_CXXFLAGS} ${OUTOPT}$@ $< 

$(TOOLS): $(PIN_LIBNAMES)
$(TOOLS): %$(PINTOOL_SUFFIX) : %.o
	${LINK} ${PIN_LDFLAGS} -L/usr/lib -L/usr/include $(LINK_DEBUG) ${LINK_OUT}$@ $< ${PIN_LPATHS} ${PIN_LIBS} $(DBG) -lmysqlclient -ldwarf -lelf

## cleaning
clean:
	-rm -f *.o $(TOOLS) *~ *.out *.tested *.failed *.d *makefile.copy *.exp *.lib

-include *.d

