#---------------------------------------------------------------------------------
# ENVIROMENT
#---------------------------------------------------------------------------------
ENVPREFIX	:= 
CC	:= $(ENVPREFIX)gcc
CXX	:= $(ENVPREFIX)gpp
LD	:= $(ENVPREFIX)ld

#---------------------------------------------------------------------------------
# SUFFIXES
#---------------------------------------------------------------------------------
# TARGET is the name of the output
# BUILD is the directory where object files & intermediate files will be placed
# SOURCES is a list of directories containing source code
# INCLUDE is a list of directories containing header files
#---------------------------------------------------------------------------------
TARGET	:= $(notdir $(CURDIR))
SOURCES	:= source source/polarssl
INCLUDE	:= source
BUILD	:= build

#---------------------------------------------------------------------------------
# OBJECTS
#---------------------------------------------------------------------------------
CFILES	:= $(foreach dir,$(SOURCES),$(wildcard $(dir)/*.c))
OFILES	:= $(CFILES:.c=.o)
OFILES	:= $(foreach f,$(OFILES),$(BUILD)/$(notdir $(f)))
CFLAGS	:= -Wall -std=c99 $(foreach dir,$(INCLUDE),-I$(CURDIR)/$(dir)) -DAPPNAME='"$(TARGET)"'
LDFLAGS	:= 

#---------------------------------------------------------------------------------
# RULES
#---------------------------------------------------------------------------------
.PHONY: all clean

all: $(TARGET)

clean:
	@echo clean ...
	@rm -fr $(BUILD) $(TARGET) $(TARGET).exe

#---------------------------------------------------------------------------------
# TARGETS
#---------------------------------------------------------------------------------
$(BUILD):
	@[ -d $(BUILD) ] || mkdir -p $(BUILD)

$(TARGET): $(BUILD) $(OFILES)
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OFILES)
	@echo buildt... $@

$(BUILD)/%.o: source/%.c
	@echo $(notdir $@) ...
	@$(CC) $(CFLAGS) -o $@ -c $^

$(BUILD)/%.o: source/polarssl/%.c
	@echo $(notdir $@) ...
	@$(CC) $(CFLAGS) -o $@ -c $^

#---------------------------------------------------------------------------------