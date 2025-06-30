# Percorsi OpenSSL e include locali
INCLUDE_OPENSSL = C:\OpenSSL-Win64\include
INCLUDE_LOCAL   = include
LIBPATH         = C:\OpenSSL-Win64\lib\VC\x64\MD

# Directory
SRC = src
OBJ = obj
BIN = bin

# Opzioni compiler/linker
CLFLAGS = /EHsc /I"$(INCLUDE_OPENSSL)" /I"$(INCLUDE_LOCAL)" /W3
LINKLIBS = libssl.lib libcrypto.lib ws2_32.lib
LINKFLAGS = /link /LIBPATH:"$(LIBPATH)" $(LINKLIBS)

all: dirs server client

dirs:
	if not exist $(OBJ) mkdir $(OBJ)
	if not exist $(BIN) mkdir $(BIN)

$(OBJ)\main.obj: $(SRC)\main.cpp
	cl $(CLFLAGS) /c $(SRC)\main.cpp /Fo$(OBJ)\main.obj

$(OBJ)\dss_server.obj: $(SRC)\dss_server.cpp
	cl $(CLFLAGS) /c $(SRC)\dss_server.cpp /Fo$(OBJ)\dss_server.obj

$(OBJ)\user.obj: $(SRC)\user.cpp
	cl $(CLFLAGS) /c $(SRC)\user.cpp /Fo$(OBJ)\user.obj

$(OBJ)\main_client.obj: $(SRC)\main_client.cpp
	cl $(CLFLAGS) /c $(SRC)\main_client.cpp /Fo$(OBJ)\main_client.obj

$(OBJ)\client.obj: $(SRC)\client.cpp
	cl $(CLFLAGS) /c $(SRC)\client.cpp /Fo$(OBJ)\client.obj

server: $(OBJ)\main.obj $(OBJ)\dss_server.obj $(OBJ)\user.obj
	cl $(OBJ)\main.obj $(OBJ)\dss_server.obj $(OBJ)\user.obj /Fe$(BIN)\server.exe $(LINKFLAGS)

client: $(OBJ)\main_client.obj $(OBJ)\client.obj $(OBJ)\user.obj
	cl $(OBJ)\main_client.obj $(OBJ)\client.obj $(OBJ)\user.obj /Fe$(BIN)\client.exe $(LINKFLAGS)

clean:
	if exist $(OBJ)\*.obj del /Q $(OBJ)\*.obj
	if exist $(BIN)\server.exe del /Q $(BIN)\server.exe
	if exist $(BIN)\client.exe del /Q $(BIN)\client.exe

.PHONY: all dirs server client clean
