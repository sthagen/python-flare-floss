NAME=test-decode-local-stackstrings

SRC=$(NAME).c
LINUX=$(NAME)
WINDOWS=$(NAME).exe
WINDOWS64=$(NAME)64.exe

$(LINUX): $(SRC)
	clang $(SRC) -o $(LINUX)


$(WINDOWS): $(SRC)
	i686-w64-mingw32-clang $(SRC) -o $(WINDOWS)


$(WINDOWS64): $(SRC)
	x86_64-w64-mingw32-clang $(SRC) -o $(WINDOWS64)


clean:
	rm -rf *~ *.bak *.exe *.viv $(LINUX) $(WINODWS) $(WINDOWS64)


all: $(LINUX) $(WINDOWS) $(WINDOWS64)
