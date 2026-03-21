RS_COMPILER = rustc
BINARY = block
INTERFACE = wlp8s0
WEB = atun.com
FILE = webs.txt

all: $(BINARY)

$(BINARY): block.rs
	@$(RS_COMPILER) block.rs -o $(BINARY)

add: all
	@./$(BINARY) $(INTERFACE) $(WEB) add

remove: all
	@./$(BINARY) $(INTERFACE) $(WEB) remove

add-many: all
	@./$(BINARY) $(INTERFACE) $(FILE) file-add

remove-many: all
	@./$(BINARY) $(INTERFACE) $(FILE) file-remove

stop: all
	@./$(BINARY) stop

clean:
	@rm -f $(BINARY)

.PHONY: all clean add add-many remove remove-many stop