SO := libprivasys_pkcs11.so

$(SO): *.go *.c *.h
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(SO) .

.PHONY: clean test
clean:
	rm -f $(SO) libprivasys_pkcs11.h

# Loads the module with pkcs11-tool and lists the slot/token (opensc required).
test: $(SO)
	pkcs11-tool --module ./$(SO) --list-slots
