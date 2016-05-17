#---------------------------------------------------------------------------------
# SUFFIXES
#---------------------------------------------------------------------------------
# TARGET is the name of the output
# BUILD is the directory where object files & intermediate files will be placed
# SOURCES is a list of directories containing source code
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
CFLAGS	:= -Wall -std=c99 $(foreach dir,$(INCLUDE),-I$(CURDIR)/$(dir)) -DAPPNAME='"$(TARGET)"'
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
	@gcc $(CFLAGS) -o $(TARGET) $(foreach f,$(OFILES),$(BUILD)/$(notdir $(f)))
	@echo buildt... $@

%.o: %.c
	@echo $(notdir $@) ...
	@gcc $(CFLAGS) -o $(BUILD)/$(notdir $@) -c $^

#---------------------------------------------------------------------------------