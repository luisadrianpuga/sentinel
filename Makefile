APP := sentinel
BPF_SRC := bpf/trace.c
BPF_OBJ := bpf/trace.bpf.o

.PHONY: build build-bpf install install-headers run clean

build: $(APP)

$(APP):
	go build -o $(APP) .

build-bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	clang -O2 -g -target bpf -c $(BPF_SRC) -o $(BPF_OBJ)

install:
	sudo apt install -y golang-go clang llvm libbpf-dev

install-headers:
	sudo apt install -y linux-headers-$$(uname -r)

run: build build-bpf
	sudo ./$(APP) run --agent "$(AGENT)"

clean:
	rm -f $(APP) $(BPF_OBJ)
