# === Percorsi OpenSSL ===
OPENSSL_INC = C:\OpenSSL-Win64\include
OPENSSL_LIB = C:\OpenSSL-Win64\lib\VC\x64\MD

# === Directory progetto ===
SRC  = src
OBJ  = obj
BIN  = bin
INCLUDE_LOCAL = include

# === Compiler & linker ===
CL = cl.exe
LINK = link.exe

# === Flag compilatore ===
CLFLAGS = /nologo /W3 /EHsc /std:c++17 /MD /I"$(OPENSSL_INC)" /I"$(INCLUDE_LOCAL)"
LDFLAGS = /link /LIBPATH:"$(OPENSSL_LIB)" libssl.lib libcrypto.lib ws2_32.lib

# === File oggetto ===
SERVER_OBJS = $(OBJ)\main.obj $(OBJ)\dss_server.obj
CLIENT_OBJS = $(OBJ)\main_client.obj

# === Targets ===
all: dirs server client

dirs:
	if not exist $(OBJ) mkdir $(OBJ)
	if not exist $(BIN) mkdir $(BIN)
	if not exist keys mkdir keys

# === Compilazione Server ===
$(OBJ)\main.obj: $(SRC)\main.cpp
	$(CL) $(CLFLAGS) /c $(SRC)\main.cpp /Fo$(OBJ)\main.obj

$(OBJ)\dss_server.obj: $(SRC)\dss_server.cpp
	$(CL) $(CLFLAGS) /c $(SRC)\dss_server.cpp /Fo$(OBJ)\dss_server.obj

# === Compilazione Client ===
$(OBJ)\main_client.obj: $(SRC)\main_client.cpp
	$(CL) $(CLFLAGS) /c $(SRC)\main_client.cpp /Fo$(OBJ)\main_client.obj

# === Link ===
server: $(SERVER_OBJS)
	$(CL) $(SERVER_OBJS) /Fe$(BIN)\server.exe $(LDFLAGS)

client: $(CLIENT_OBJS)
	$(CL) $(CLIENT_OBJS) /Fe$(BIN)\client.exe $(LDFLAGS)

clean:
	if exist $(OBJ)\*.obj del /Q $(OBJ)\*.obj
	if exist $(BIN)\server.exe del /Q $(BIN)\server.exe
	if exist $(BIN)\client.exe del /Q $(BIN)\client.exe

.PHONY: all dirs clean server client
