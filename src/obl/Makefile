CC = gcc
CXX = g++

# release flags
#CFLAGS = -Wall $(INC) -pthread -march=native -mrdrnd -mrdseed -mpopcnt -O2
# debug flags
CFLAGS =  -Wall $(INC) -pthread -march=native -mrdseed -mpopcnt -mavx -mavx2 -O2 -g 
CXXFLAGS = -std=c++11

LDFLAGS = ../../libs/libwolfssl.a -L$(SGX_SDK)/lib64 -lsgx_tcrypto -ltcmalloc 

INCDIR = ../../ ../../includes /usr/include $(SGX_SDK)/include
INC = $(addprefix -I, $(INCDIR))

FILESRCS = $(wildcard ./*.c*)
FILESRCS += ../misc/obl_string.c
OBJECTS = $(addsuffix .o, $(basename $(FILESRCS)))

TESTSRCS = $(wildcard ./tests/*.c*)
TESTOBJ = $(addsuffix .o, $(basename $(TESTSRCS)))
TEST = $(basename $(TESTSRCS))

BENCHSRCS = $(wildcard ./benchmarks/*.c*)
BENCHOBJ = $(addsuffix .o, $(basename $(BENCHSRCS)))
BENCH = $(basename $(BENCHSRCS))

STATICLIB = ../../libs/libobl.a

.PHONY = static objects all clean benchmarks

all: $(TEST) $(BENCH)
	@cp $(TEST) $(BENCH) ../../

test: $(TEST) 
	@cp $(TEST) ../../
	
benchmarks: $(BENCH)
	@cp $(BENCH) ../../

static: $(STATICLIB)

# target specific variables
enclave_static: CFLAGS += -DSGX_ENCLAVE_ENABLED -fPIC
enclave_static: CXXFLAGS += -I/opt/sgxsdk/include/libcxx -I/opt/sgxsdk/include -I/opt/sgxsdk/include/tlibc
enclave_static: $(STATICLIB)

$(STATICLIB): $(OBJECTS)
	@ar rcs $(STATICLIB) $^
	@echo "AR  => $@"

objects: $(OBJECTS)

$(TEST): $(TESTOBJ) $(OBJECTS)
	@$(CXX) $@.o $(OBJECTS) -o $@ $(CFLAGS) $(CXXFLAGS) $(LDFLAGS)
	@echo "LD  => $@"

$(BENCH): $(BENCHOBJ) $(OBJECTS)
	@$(CXX) $@.o $(OBJECTS) -o $@ $(CFLAGS) $(CXXFLAGS) $(LDFLAGS)
	@echo "LD  => $@"

#$(NAME): $(OBJECTS)
#	$(CXX) $^ -o $@ $(CFLAGS) $(CXXFLAGS) $(LDFLAGS)

%.o: %.c
	@$(CC) -c $< -o $@ $(CFLAGS)
	@echo "CC  => $@"

%.o: %.cpp
	@$(CXX) -c $< -o $@ $(CFLAGS) $(CXXFLAGS)
	@echo "CXX => $@"

clean:
	@rm -rfv $(OBJECTS) $(BENCHOBJ) $(TESTOBJ) $(addprefix "../../", $(notdir $(TEST))) $(addprefix "../../", $(notdir $(BENCH))) $(STATICLIB)
	@rm -rfv $(TEST) $(BENCH) 
