SRC_DIR := src
HEAD_DIR := header
OBJ_DIR := obj
# DEP_DIR := dep
BIN_DIR := bin
# RM = rm -rv
EXE := $(BIN_DIR)/dubC
SRC := $(wildcard $(SRC_DIR)/*.cpp)
HEADR := $(wildcard $(HEAD_DIR)/*.h)
OBJS := $(SRC:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)


CXX=g++
RM=rm -f
CPPFLAGS := -g -Wall
# CPPFLAGS := -g -Wall -std=c++17 -Iinclude -MMD -MP
#CPPFLAGS := -O2 -Wall -std=c++17 -Iinclude -MMD -MP
# CPPFLAGS := -g -Wall -std=c++11 -Iinclude -MMD -MP
# CPPFLAGS := -O2 -Wall -std=c++11 -Iinclude -MMD -MP
# CFLAGS := -Wall
LDFLAGS := -L
#LDFLAGS := -Llib -lbsd -lpthread
LDLIBS := ../lib/


.PHONY: all clean
all: $(EXE)

$(EXE):$(OBJS) | $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	@$(RM) -rv $(BIN_DIR) $(OBJ_DIR)

-include $(OBJS:.o=.d)
# .PHONY: all
# all: ; $(info $$OBJS is [${SRC}])echo Hello
