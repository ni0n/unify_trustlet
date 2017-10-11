import sys, os, struct

ELF_HEADER_SIZE = 0x34
E_PHNUM_OFFSET = 0x2C
PHDR_SIZE = 0x20
P_FILESZ_OFFSET = 0x10
P_OFFSET_OFFSET = 0x4

def main():
	#Reading the arguments
	if len(sys.argv) != 3:
		print "USAGE: <input.mdt> <output>"
		return
	
	input_file = sys.argv[1]

	#Reading the ELF header from the ".mdt" file
	mdt = open(input_file, "rb")
	elf_header = mdt.read(ELF_HEADER_SIZE)
	phnum = struct.unpack("<H", elf_header[E_PHNUM_OFFSET:E_PHNUM_OFFSET+2])[0]
	print "[+] Found %d program headers" % phnum
	
	#Reading each of the program headers and copying the relevant chunk
	output_file = open(sys.argv[2], 'wb')
	ife = os.path.splitext(input_file)
	if not ife[1]:
		print "[-] something went wrong; expecting file with extension"
		return

	chunk_prefix = ife[0]
	block_prefix = "B" if chunk_prefix[0].isupper() else "b"
	for i in range(0, phnum):

		#Reading the PHDR
		print "[+] Reading PHDR %d" % i
		phdr = mdt.read(PHDR_SIZE) 	
		p_filesz = struct.unpack("<I", phdr[P_FILESZ_OFFSET:P_FILESZ_OFFSET+4])[0] 
		p_offset= struct.unpack("<I", phdr[P_OFFSET_OFFSET:P_OFFSET_OFFSET+4])[0] 
		print "[+] Size: 0x%08X, Offset: 0x%08X" % (p_filesz, p_offset)

		if p_filesz == 0:
			print "[+] Empty block, skipping"
			continue #There's no backing block

		#Copying out the data in the block
		try:
			block = open(os.path.join("%s.%s%02d" % (chunk_prefix, block_prefix, i)), 'rb').read()
			output_file.seek(p_offset, 0)
			output_file.write(block)
		except IOError as e:
			print "[-] %s" %(str(e))
			return

	mdt.close()
	output_file.close()

if __name__ == "__main__":
	main()
