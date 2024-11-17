#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
// TODO: maybe have an argument for filetype? like -t elf or something
// This allows: in elf mode, we only set executable in DIFF_xxxxxxxx sections that came from in executable-marked sections in the source files
// And: compatibility with raw bins is preserved

typedef struct {
	FILE *a, *b;
	unsigned int start, end;
	unsigned int vram;
	unsigned int instructionAlignment;
} BinDiffArguments;

typedef struct {
	unsigned int addressBytes, lengthBytes;
	unsigned int addressInstrs, lengthInstrs;
} DiffPosition;

typedef struct {
	size_t length, size;
	DiffPosition *arr;
} DiffPositionVec;

void run_bindiff(BinDiffArguments args);
void write_help(FILE *out);
void write_elf(BinDiffArguments args, DiffPositionVec diffPositions);
int main(int argc, char **argv);

unsigned int compare_bytes(uint8_t const *a, uint8_t const *b, unsigned int n);

#define PROG_ADDR 0x100
// extra sections
#define ELF_SECTION_COUNT 2 // null and shstrtab
#define MAX_SHSTR_LEN (32 - 1)

#include <elf.h>

typedef struct {
	unsigned int a, b;
} UIntPair;

void write_elf_header(uint32_t shoff, uint16_t shnum)
{
	uint8_t magic[4] = { 0x7F, 'E', 'L', 'F' };
	uint8_t bitFormat = 1; // 1 = 32, 2 = 64
	uint8_t byteOrder = 1; // 1 = little, 2 = big endian
	uint8_t elfVersion = 1; // 1 = current
	uint8_t abi = 0; // ABI, this means system v but ISA field will make elf understand
	uint8_t abiversion = 0; // again, nonsense
	uint8_t pad = 0;
	uint16_t fileType = ET_REL; // .o is the most accurate
	uint16_t machine = 0x08; // mips!
	uint32_t elfVersion2 = 1; // ??
	uint32_t entry = 0; // entrypoint null here
	uint32_t phoff = 0; // no program header
	uint32_t shOff = shoff; // section header table offset
	uint32_t flags = 0; // ???
	uint16_t elfHeaderSize = 52; // 32 bit has 52 byte header
	uint16_t phentSize = 0; // no program header
	uint16_t phNum = 0; // no program header
	uint16_t shentSize = 0x28; // 0x28 for 32 bit section header entry size
	uint16_t shNum = shnum; // number of section headers
	uint16_t shstridx = 1; // first! (0 is null)
#define WRITE(var) fwrite(&var, sizeof(var), 1, stdout);
	fwrite(magic, 1, 4, stdout);
	WRITE(bitFormat);
	WRITE(byteOrder);
	WRITE(elfVersion);
	WRITE(abi);
	WRITE(abiversion);
	for (int i = 0; i < 7; ++i)
		WRITE(pad);
	WRITE(fileType);
	WRITE(machine);
	WRITE(elfVersion2);
	WRITE(entry);
	WRITE(phoff);
	WRITE(shOff);
	WRITE(flags);
	WRITE(elfHeaderSize);
	WRITE(phentSize);
	WRITE(phNum);
	WRITE(shentSize);
	WRITE(shNum);
	WRITE(shstridx);
	for (size_t i = 0; i < PROG_ADDR - elfHeaderSize; ++i)
		fputc(0, stdout);
}

void write_elf(BinDiffArguments args, DiffPositionVec diffPositions)
{
	fseek(args.a, args.start, SEEK_SET);
	fseek(args.b, args.start, SEEK_SET);

	UIntPair *diffAddrs = malloc(sizeof(UIntPair) * diffPositions.length);
	Elf32_Shdr *sectionHeaders = (Elf32_Shdr *) malloc(sizeof(Elf32_Shdr) * (ELF_SECTION_COUNT + diffPositions.length * 2));
	unsigned int currentAddr = PROG_ADDR;
	for (size_t i = 0; i < diffPositions.length; ++i) {
		Elf32_Shdr shdiffa, shdiffb;
		DiffPosition pos = diffPositions.arr[i];
		shdiffa.sh_name = (2 * i + ELF_SECTION_COUNT) * (MAX_SHSTR_LEN + 1);
		shdiffb.sh_name = (2 * i + ELF_SECTION_COUNT + 1) * (MAX_SHSTR_LEN + 1);
		shdiffa.sh_type = shdiffb.sh_type = SHT_PROGBITS;
		shdiffa.sh_flags = shdiffb.sh_flags = SHF_EXECINSTR | SHF_ALLOC;
		shdiffa.sh_offset = shdiffa.sh_addr = diffAddrs[i].a = currentAddr;
		currentAddr += pos.lengthBytes;
		shdiffb.sh_offset = shdiffb.sh_addr = diffAddrs[i].b = currentAddr;
		currentAddr += pos.lengthBytes;
		shdiffa.sh_size = shdiffb.sh_size = pos.lengthBytes;
		shdiffa.sh_link = shdiffb.sh_link = 0;
		shdiffa.sh_info = shdiffb.sh_info = 0;
		shdiffa.sh_addralign = shdiffb.sh_addralign = 1;
		shdiffa.sh_entsize = shdiffb.sh_entsize = 0;

		sectionHeaders[2 * i + ELF_SECTION_COUNT] = shdiffa;
		sectionHeaders[2 * i + 1 + ELF_SECTION_COUNT] = shdiffb;
	}
	free(diffAddrs); //unused
	// Section Header name table
	Elf32_Shdr shstrtab;
	shstrtab.sh_name = 1;
	shstrtab.sh_type = SHT_STRTAB;
	shstrtab.sh_flags = 0;
	shstrtab.sh_addr = shstrtab.sh_offset = currentAddr;
	shstrtab.sh_size = (diffPositions.length * 2 + ELF_SECTION_COUNT) * (MAX_SHSTR_LEN + 1); // +1 for null term
	char *shstrtabRaw = calloc(shstrtab.sh_size, 1);
	// leave 0 null
	snprintf(&shstrtabRaw[1 * (MAX_SHSTR_LEN + 1)], MAX_SHSTR_LEN, ".shstrtab");
	for (size_t i = 0; i < diffPositions.length; ++i) {
	snprintf(&shstrtabRaw[(2 * i + ELF_SECTION_COUNT) * (MAX_SHSTR_LEN + 1)], // +1 for null term
			MAX_SHSTR_LEN,
			"DIFF_%08x_a",
			diffPositions.arr[i].addressBytes + args.vram);
		snprintf(&shstrtabRaw[(2 * i + ELF_SECTION_COUNT + 1) * (MAX_SHSTR_LEN + 1)], // +1 for null term
			MAX_SHSTR_LEN,
			"DIFF_%08x_b",
			diffPositions.arr[i].addressBytes + args.vram);
	}
	shstrtab.sh_link = 0;
	shstrtab.sh_info = 0;
	shstrtab.sh_addralign = 1;
	shstrtab.sh_entsize = 0;
	Elf32_Shdr shnull;
	shnull.sh_name = 0;
	shnull.sh_type = SHT_NULL;
	shnull.sh_flags = shnull.sh_addr = shnull.sh_offset = shnull.sh_size = shnull.sh_link = shnull.sh_info = shnull.sh_entsize = 0;
	shnull.sh_addralign = 1;
	sectionHeaders[0] = shnull;
	sectionHeaders[1] = shstrtab;
	currentAddr = shstrtab.sh_addr + shstrtab.sh_size;
	fprintf(stderr, "current at: %u 0x%08x\n", currentAddr, currentAddr);

	write_elf_header(currentAddr, 2 * diffPositions.length + ELF_SECTION_COUNT);

	unsigned int realAddr = PROG_ADDR;
	for (size_t i = 0; i < diffPositions.length; ++i) {
		DiffPosition pos = diffPositions.arr[i];
		fseek(args.a, pos.addressBytes, SEEK_SET);
		fseek(args.b, pos.addressBytes, SEEK_SET);
		void *buf = malloc(pos.lengthBytes);
		fread(buf, 1, pos.lengthBytes, args.a);
		realAddr += fwrite(buf, 1, pos.lengthBytes, stdout);
		fread(buf, 1, pos.lengthBytes, args.b);
		realAddr += fwrite(buf, 1, pos.lengthBytes, stdout);
		free(buf);
	}

	fprintf(stderr, "shstrtab at: %u 0x%08x\n", realAddr, realAddr);
	realAddr += fwrite(shstrtabRaw, shstrtab.sh_size, 1, stdout) * shstrtab.sh_size;
	free(shstrtabRaw);
	fprintf(stderr, "section header table at: %u 0x%08x\n", realAddr, realAddr);
	for (size_t i = 0; i < 2 * diffPositions.length + ELF_SECTION_COUNT; ++i) {
		Elf32_Shdr shdr = sectionHeaders[i];
		WRITE(shdr.sh_name);
		WRITE(shdr.sh_type);
		WRITE(shdr.sh_flags);
		WRITE(shdr.sh_addr);
		WRITE(shdr.sh_offset);
		WRITE(shdr.sh_size);
		WRITE(shdr.sh_link);
		WRITE(shdr.sh_info);
		WRITE(shdr.sh_addralign);
		WRITE(shdr.sh_entsize);
	}
	free(sectionHeaders);
}

void run_bindiff(BinDiffArguments args)
{
	uint8_t *instructionA = (uint8_t *) malloc(args.instructionAlignment);
	uint8_t *instructionB = (uint8_t *) malloc(args.instructionAlignment);
	DiffPositionVec diffPositions = {
		.length = 0,
		.size = 4
	};
	diffPositions.arr = (DiffPosition *) malloc(diffPositions.size * sizeof(DiffPosition));
	unsigned int byteCount = args.end - args.start;
	if (byteCount % args.instructionAlignment != 0) {
		free(instructionA);
		free(instructionB);
		fputs("Amount of bytes in [start, end] is not a multiple of instructionAlignment!\n", stderr);
		exit(1);
	}
	unsigned int readCount = byteCount / args.instructionAlignment;
	unsigned int totalByteDiffs = 0;
	bool previousWasDiff = false;
	for (unsigned int insIdx = 0; insIdx < readCount; ++insIdx) {
		unsigned int addressBytes = insIdx * args.instructionAlignment + args.start;
		fread(instructionA, args.instructionAlignment, 1, args.a);
		fread(instructionB, args.instructionAlignment, 1, args.b);
		unsigned int diff = compare_bytes(instructionA, instructionB, args.instructionAlignment);
		if (diff > 0) {
			if (!previousWasDiff) {
				DiffPosition position = {
					.addressBytes = addressBytes,
					.addressInstrs = insIdx,
					.lengthBytes = args.instructionAlignment,
					.lengthInstrs = 1,
				};
				diffPositions.arr[diffPositions.length++] = position;
				size_t prevSize = diffPositions.size;
				while (diffPositions.length >= diffPositions.size)
					diffPositions.size *= 2;
				if (diffPositions.size != prevSize)
					diffPositions.arr = realloc(diffPositions.arr, diffPositions.size * sizeof(DiffPosition));
			} else {
				diffPositions.arr[diffPositions.length - 1].lengthInstrs += 1;
				diffPositions.arr[diffPositions.length - 1].lengthBytes += args.instructionAlignment;
			}
			previousWasDiff = true;
		} else {
			previousWasDiff = false;
		}
		totalByteDiffs += diff;
	}
	fprintf(stderr, "Diff Count: %u\n", totalByteDiffs);
	fprintf(stderr, "Label Diff Count: %lu\n", diffPositions.length);

	write_elf(args, diffPositions);

	free(instructionA);
	free(instructionB);
	free(diffPositions.arr);
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		write_help(stderr);
		return 1;
	}

	FILE *aFile = NULL, *bFile = NULL;
	char *aFilePath = NULL, *bFilePath = NULL;
	unsigned int instructionAlign = 4;
	unsigned int vram = 0x100000;
	char *startStr = "sof", *endStr = "eof";

	bool ignoreOptions = false;
	char **targetString = NULL;
	unsigned int *targetInt = NULL;
	FILE *output = stdout;

	for (int i = 1; i < argc; ++i) {
		char *arg = argv[i];
		if (arg == NULL) continue;
		if (targetString) {
			*targetString = arg;
			targetString = NULL;
			continue;
		}
		if (targetInt) {
			*targetInt = strtol(arg, NULL, 0);
			targetInt = NULL;
			continue;
		}
		if (ignoreOptions || *arg != '-') {
FOUND_INPUT_FILE:;
			if (aFilePath == NULL) {
				aFilePath = arg;
			} else if (bFilePath == NULL) {
				bFilePath = arg;
			} else {
				fputs("too many arguments provided\n\n", stderr);
				write_help(stderr);
				return 1;
			}
			continue;
		}
		if (strcmp(arg, "--") == 0) {
			ignoreOptions = true;
		} else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
			write_help(stdout);
			return 0;
		} else if (strcmp(arg, "-A") == 0 || strcmp(arg, "--instruction-align") == 0) {
			targetInt = &instructionAlign;
		} else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--start") == 0) {
			targetString = &startStr;
		} else if (strcmp(arg, "-e") == 0 || strcmp(arg, "--end") == 0) {
			targetString = &endStr;
		} else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--vram") == 0) {
			targetInt = &vram;
		}
	}

	if (!aFilePath || !bFilePath) {
		fputs("not enough file inputs provided\n\n", stderr);
		write_help(stderr);
		return 1;
	}

	aFile = fopen(aFilePath, "rb");
	if (!aFile)
		error(1, errno, "Failed to open %s", aFilePath);
	bFile = fopen(bFilePath, "rb");
	if (!bFile)
		error(1, errno, "Failed to open %s", bFilePath);

	size_t aSize = 0, bSize = 0;
	fseek(aFile, 0, SEEK_END);
	fseek(bFile, 0, SEEK_END);
	aSize = ftell(aFile);
	bSize = ftell(bFile);
	size_t sizeLimit = (aSize > bSize ? bSize : aSize);

	unsigned int start = 0;
	unsigned int end = sizeLimit;
	if (strcmp(startStr, "sof") != 0)
		start = strtol(startStr, NULL, 0);
	if (strcmp(endStr, "eof") != 0)
		end = strtol(endStr, NULL, 0);

	if (end > sizeLimit)
		end = sizeLimit;
	if (start > sizeLimit)
		start = sizeLimit;

	if (end <= start) {
		fclose(aFile);
		fclose(bFile);
		fprintf(stderr, "invalid start/end sizes: start (0x%08x) >= end (0x%08x)!!!\n\n", start, end);
		write_help(stderr);
		return 1;
	}

	fseek(aFile, start, SEEK_SET);
	fseek(bFile, start, SEEK_SET);

	fprintf(stderr,
		"Diffing %s and %s[0x%08x - 0x%08x], vram_offset: 0x%08x, instruction_alignment: %u\n",
		aFilePath, bFilePath, start, end, vram, instructionAlign);

	BinDiffArguments arguments = {
		.a = aFile,
		.b = bFile,
		.start = start,
		.end = end,
		.vram = vram,
		.instructionAlignment = instructionAlign
	};
	run_bindiff(arguments);
	fclose(aFile);
	fclose(bFile);
	return 0;
}
void write_help(FILE *out)
{
	fputs("usage: bindiff [options] <file path:a> <file path:b>\n", out);
	fputs("[options] values:\n", out);
	fputs("-h | --help: show this help text\n", out);
	fputs("-s <start address> | --start <start address>: where to start diffs (default: 0)\n", out);
	fputs("-e <end address> | --end <end address>: where to end diffs (default: special value \"eof\")\n", out);
	fputs("-v <address> | --vram <address>: offset to all address-named labels, set this to the file offset of 0 if you want file indices, otherwise, set this to vram offset (default: 0x100000)\n", out);
	fputs("-A <number> | --instruction-align: output entire blocks of <number> as instructions (default: 4)\n", out);
}

unsigned int compare_bytes(uint8_t const *a, uint8_t const *b, unsigned int n)
{
	unsigned int ret = 0;
	for (unsigned int i = 0; i < n; ++i) {
		if (a[i] != b[i])
			++ret;
	}
	return ret;
}
