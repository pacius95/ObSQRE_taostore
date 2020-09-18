#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <cassert>

#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "sais.hpp"

const std::size_t outbuf_size = 65536 * 4; // 256 kB
const int pbkdf2_work_factor = 16384;
const int pbkdf2_salt_size = 16;

void gen_rand(std::uint8_t*, std::size_t);
unsigned int next_two_power(unsigned int);

void* map_file(const char*, off_t&);
void map_uchar(unsigned char*, std::size_t, std::size_t*, int&);

// append encrypted data to the output file
void append_blob(EVP_CIPHER_CTX*, std::filebuf&, std::uint8_t*, std::uint8_t*, std::size_t);

void sa_psi(EVP_CIPHER_CTX*, unsigned char*, std::size_t, int, std::filebuf&, bool);
void nicholas_bwt(EVP_CIPHER_CTX*, unsigned char*, std::size_t, int, std::filebuf&, bool);
void vanilla_bwt(EVP_CIPHER_CTX*, unsigned char*, std::size_t, int, std::filebuf&, std::uint64_t, bool);

int main(int argc, char *argv[])
{
	int algo;
	bool suffix_array_on;
	std::size_t freq[256];

	if(argc < 6)
	{
		std::cerr << "usage: ./prep <input_txt> <output_bin> <passwd>\n\t<algo> <suffix_array:y/n> [sampling_rate]" << std::endl << std::endl;
		std::cerr << "algorithms:" << std::endl;
		std::cerr << "0 => SA-PSI" << std::endl;
		std::cerr << "1 => Nicholas BWT" << std::endl;
		std::cerr << "2 => Sampled vanilla BWT (requires sampling rate)" << std::endl;
		return 1;
	}

	algo = std::atoi(argv[4]);
	suffix_array_on = std::strcmp(argv[5], "y") == 0;

	// key generation - PBKDF2
	std::uint8_t aes_key[16];
	std::uint8_t pbkdf2_salt[pbkdf2_salt_size];

	gen_rand(pbkdf2_salt, pbkdf2_salt_size);
	PKCS5_PBKDF2_HMAC(argv[3], std::strlen(argv[3]),
		pbkdf2_salt, pbkdf2_salt_size,
		pbkdf2_work_factor, EVP_sha256(),
		16, aes_key);

	std::cout << "PBKDF2 key: ";
	for(int i = 0; i < 16; i++)
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)aes_key[i];
	std::cout << std::endl << std::endl;

	// create output files
	// I discovered that those are automatically closed, so I don't need to manage them any more
	std::filebuf outfile;
	outfile.open(argv[2], std::ios::out | std::ios::trunc | std::ios::binary);

	std::filebuf mapfile;
	mapfile.open(std::string(argv[2]).append(".map"), std::ios::out | std::ios::trunc | std::ios::binary);

	// memory map text
	off_t length;
	unsigned char *text = (unsigned char*) map_file(argv[1], length);

	if(text == NULL)
	{
		std::cerr << "error while opening file" << std::endl;
		return 1;
	}
	else if(text == (void*)-1)
	{
		std::cerr << "error while memory mapping file" << std::endl;
		return 1;
	}
	
	// map characters of the text
	int alpha;
	int j = 0;
	
	map_uchar(text, length, freq, alpha);

	std::cout << "String length: " << std::dec << length << std::endl;
	std::cout << "Alphabet size: " << alpha << std::endl << std::endl;
	
	// create map file and compact frequencies
	for(int i = 0; i < 256; i++)
		if(freq[i] != 0)
		{
			char c = (char) i;
			mapfile.sputn(&c, sizeof(unsigned char));
			freq[j] = freq[i];
			++j;
		}
	
	mapfile.close();
	assert(j == alpha);

	// OpenSSL init
	std::uint8_t aes_iv[12];
	gen_rand(aes_iv, 12);

	EVP_CIPHER_CTX *actr = EVP_CIPHER_CTX_new(); // instantiate CTX context
	EVP_CIPHER_CTX_ctrl(actr, EVP_CTRL_GCM_SET_IVLEN, 12, NULL); // set IV=12 for AES128-GCM

	EVP_EncryptInit(actr, EVP_aes_128_gcm(), aes_key, aes_iv);

	// write file header
	std::uint64_t algorithm_def;
	std::uint64_t header[4];

	algorithm_def = algo + (suffix_array_on ? 4 : 0); // algorithm type + suffix_array_on

	if(algo != 1)
		header[0] = length; // string length
	else {
		std::size_t max_occ = 0;
		
		for(int i = 0; i < alpha; i++)
			if(freq[i] > max_occ)
				max_occ = freq[i];
		
		header[0] = max_occ * alpha;
	}
	
	header[1] = alpha;
	header[2] = sizeof(std::uint32_t); // Int type of sais
	header[3] = pbkdf2_salt_size; // salt size for PBKDF2

	outfile.sputn((char*) &algorithm_def, sizeof(std::uint64_t));
	outfile.sputn((char*) header, 4 * sizeof(std::uint64_t)); // write header
	outfile.sputn((char*) aes_iv, 12); // write IV for AES-CTR
	outfile.sputn((char*) pbkdf2_salt, pbkdf2_salt_size); // write salt for PBKDF2

	// authenticate the unencrypted portion of the file
	int out_size;
	EVP_EncryptUpdate(actr, NULL, &out_size, (std::uint8_t*) &algorithm_def, sizeof(std::uint64_t));
	EVP_EncryptUpdate(actr, NULL, &out_size, (std::uint8_t*) header, 4 * sizeof(std::uint64_t));
	EVP_EncryptUpdate(actr, NULL, &out_size, aes_iv, 12);
	EVP_EncryptUpdate(actr, NULL, &out_size, pbkdf2_salt, pbkdf2_salt_size);

	// Up to here, preprocessing is the same for the three algorithms, now differentiate
	int sampling_rate;

	switch(algo)
	{
		case 0:
			sa_psi(actr, text, length, alpha, outfile, suffix_array_on);
			break;
		case 1:
			nicholas_bwt(actr, text, length, alpha, outfile, suffix_array_on);
			break;
		case 2:
			if(argc != 7)
				std::cerr << "error: sampling rate required" << std::endl;
			else {
				sampling_rate = std::atoi(argv[6]);
				vanilla_bwt(actr, text, length, alpha, outfile, sampling_rate, suffix_array_on);
			}
			break;
		default:
			std::cerr << "error: unknown algo" << std::endl;
	}

	// extract gmac
	std::uint8_t gcm_mac[16];
	int res_size;

	EVP_EncryptFinal(actr, gcm_mac, &res_size); // Finalize the cipher
	assert(res_size == 0);
	EVP_CIPHER_CTX_ctrl(actr, EVP_CTRL_GCM_GET_TAG, 16, gcm_mac); // dump the tag

	outfile.sputn((char*) gcm_mac, 16);

	std::cout << "GMAC: ";
	for(int i = 0; i < 16; i++)
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)gcm_mac[i];
	std::cout << std::endl;

	EVP_CIPHER_CTX_free(actr);

	return 0;
}

// copy-pasted from obl
void gen_rand(std::uint8_t *dst, std::size_t len)
{
	unsigned long long int buffer;

	for(unsigned int i = 0; i < len; i++)
	{
		if((i & 7) == 0)
			__builtin_ia32_rdrand64_step(&buffer);
		else
			buffer >>= 8;

		dst[i] = buffer;
	}
}

// Bit Twiddling Hacks
// By Sean Eron Anderson
// seander@cs.stanford.edu
unsigned int next_two_power(unsigned int v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;

	return v;
}

void map_uchar(unsigned char *txt, std::size_t len, std::size_t *C, int &alpha)
{
	std::uint8_t map[256];
	
	alpha = 0;
	
	for(int i = 0; i < 256; i++)
	{
		C[i] = 0;
		map[i] = 0;
	}
	
	// count bytes (character) occurrences
	for(std::uint64_t i = 0; i < len; i++)
	{
		++C[txt[i]];
		map[txt[i]] = 1;
	}
	
	// assign progressive id
	for(int i = 0; i < 256; i++)
		if(map[i] == 1)
		{
			map[i] = alpha;
			++alpha;
		}
	
	// assign new tags to characters
	for(unsigned int i = 0; i < len; i++)
		txt[i] = map[txt[i]];
}

void* map_file(const char *filename, off_t &length)
{
	int fd0;
	void *ptr;

	fd0 = open(filename, O_RDONLY);

	if(fd0 == -1)
		return NULL;

	off_t fd_size = lseek(fd0, 0, SEEK_END);
	ptr = mmap(NULL, fd_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd0, 0);
	length = fd_size;

	close(fd0);

	return ptr;
}

void append_blob(EVP_CIPHER_CTX *actr, std::filebuf &fb, std::uint8_t *data, std::size_t len, std::uint8_t *enc_data, std::size_t enc_buff)
{
	int written_bytes;

	while(len != 0)
	{
		std::size_t curr_len = len > enc_buff ? enc_buff : len;

		EVP_EncryptUpdate(actr, enc_data, &written_bytes, data, curr_len);
		// following Nicholas' stylistic advice
		assert((std::size_t) written_bytes == curr_len);
		fb.sputn((char*) enc_data, written_bytes);

		len -= curr_len;
		data += curr_len;
	}
}

void sa_psi(EVP_CIPHER_CTX *cc, unsigned char *text, std::size_t length, int alphabet_size, std::filebuf &fb, bool sa_on)
{
	std::uint8_t *enc_data = new uint8_t[outbuf_size];

	// preprocessing -- C array
	std::uint32_t *C = new std::uint32_t[alphabet_size + 1];
	bucket_index<unsigned char, std::uint32_t>(text, length, alphabet_size, C);
	std::cout << "Created C array for indexing" << std::endl;

	// preprocessing -- suffix array
	std::uint32_t *buffer1 = new std::uint32_t[length+1];
	sais<unsigned char, std::uint32_t>(text, length, alphabet_size, buffer1);
	std::cout << "Suffix array generated" << std::endl;

	// text no more needed
	munmap(text, length);

	// If you want, write here your suffix array (stored in buffer1)
	if(sa_on)
	{
		append_blob(cc, fb, (std::uint8_t*) buffer1, (length+1) * sizeof(std::uint32_t), enc_data, outbuf_size);
		std::cout << "Suffix-array written to file" << std::endl;
	}

	// write the C array
	append_blob(cc, fb, (std::uint8_t*) C, (alphabet_size + 1) * sizeof(std::uint32_t), enc_data, outbuf_size);
	delete[] C;

	// preprocessing -- psi array
	std::uint32_t *buffer2 = new std::uint32_t[length+1];
	inverse_sa<std::uint32_t>(buffer1, buffer2, length);
	build_psi<std::uint32_t>(buffer1, buffer2, buffer1, length);
	flatten<std::uint32_t>(buffer1, buffer2, 0, length+1);
	std::cout << "PSI array built and flattened" << std::endl << std::endl;

	delete[] buffer1;

	// write the PSI array level by level
	std::int64_t hlen = 1;
	std::uint32_t ll = length + 1;
	while(ll != 0)
	{
		std::size_t ch_s = ll > hlen ? hlen : ll;

		append_blob(cc, fb, (std::uint8_t*) &buffer2[hlen-1], ch_s * sizeof(std::uint32_t), enc_data, outbuf_size);

		// next level of the heap
		ll -= ch_s;
		hlen <<= 1;
	}

	delete[] buffer2;

	delete[] enc_data;
}

void nicholas_bwt(EVP_CIPHER_CTX *cc, unsigned char *text, std::size_t length, int alphabet_size, std::filebuf &fb, bool sa_on)
{
	std::uint8_t *enc_data = new uint8_t[outbuf_size];

	// preprocessing -- C array
	std::uint32_t *C = new std::uint32_t[alphabet_size + 1];
	bucket_index<unsigned char, std::uint32_t>(text, length, alphabet_size, C);

	for(int i = 0; i < alphabet_size; i++)
		C[i] = C[i+1] - C[i];

	// find max occurrence character
	std::uint32_t max_freq = 0;
	for(int i = 0; i < alphabet_size; i++)
		if(C[i] > max_freq)
			max_freq = C[i];

	std::size_t Np = alphabet_size * max_freq + 1;

	// preprocessing -- suffix array
	std::uint32_t *buffer1 = new std::uint32_t[Np];
	sais<unsigned char, std::uint32_t>(text, length, alphabet_size, buffer1);
	std::cout << "Suffix array generated" << std::endl;

	// build BWT
	std::uint32_t terminator_offset = 0; // shut down compiler warnings
	unsigned char *bwt = new unsigned char[length+1];
	build_bwt<unsigned char, std::uint32_t>(text, buffer1, bwt, length, &terminator_offset);
	std::cout << "BWT computed" << std::endl;

	// text no more needed
	munmap(text, length);

	// this is the right time to write the suffix array if you want
	if(sa_on)
	{
		append_blob(cc, fb, (std::uint8_t*) buffer1, Np * sizeof(std::uint32_t), enc_data, outbuf_size);
		std::cout << "Suffix-array written to file" << std::endl;
	}

	delete[] buffer1;

	// write C to file
	append_blob(cc, fb, (std::uint8_t*) C, alphabet_size * sizeof(std::uint32_t), enc_data, outbuf_size);

	std::uint32_t **indices = new std::uint32_t*[alphabet_size];
	for(int i = 0; i < alphabet_size; i++)
	 	indices[i] = new std::uint32_t[max_freq];

	write_index<unsigned char, std::uint32_t>(bwt, length, alphabet_size, terminator_offset, indices);

	// get rid of the useless BWT
	delete[] bwt;

	std::uint32_t *heap = new std::uint32_t[max_freq];

	for(int i = 0; i < alphabet_size; i++)
	{
		flatten<std::uint32_t>(indices[i], heap, 0, C[i]);
		delete[] indices[i];
		append_blob(cc, fb, (std::uint8_t*) heap, max_freq * sizeof(std::uint32_t), enc_data, outbuf_size);
	}
	std::cout << "Indices built and flattened" << std::endl << std::endl;

	delete[] C;
	delete[] indices;
	delete[] heap;

	delete[] enc_data;
}

void vanilla_bwt(EVP_CIPHER_CTX *cc, unsigned char *text, std::size_t length, int alphabet_size, std::filebuf &fb, std::uint64_t s_rate, bool sa_on)
{
	std::uint8_t *enc_data = new uint8_t[outbuf_size];

	// preprocessing -- C array
	std::uint32_t *C = new std::uint32_t[alphabet_size + 1];
	bucket_index<unsigned char, std::uint32_t>(text, length, alphabet_size, C);

	// build suffix array
	std::uint32_t *suffix_array = new std::uint32_t[length+1];
	sais<unsigned char, std::uint32_t>(text, length, alphabet_size, suffix_array);

	// build the bwt
	unsigned char *bwt = new unsigned char[length+1];
	std::uint32_t terminator = 0; // shut down silly compiler warnings
	build_bwt<unsigned char, std::uint32_t>(text, suffix_array, bwt, length, &terminator);

	// text no more needed
	munmap(text, length);

	// if you need to write to file the suffix array, that's a good moment
	if(sa_on)
	{
		append_blob(cc, fb, (std::uint8_t*) suffix_array, (length+1) * sizeof(std::uint32_t), enc_data, outbuf_size);
		std::cout << "Suffix-array written to file" << std::endl;
	}

	delete[] suffix_array;

	// get number of bits to encode each character
	int alpha = alphabet_size;
	int no_bits = __builtin_ctz(next_two_power(alpha+1)); // number of bits for each character and terminator

	std::cerr << "# bits per character: " << no_bits << std::endl;

	// get # of 16-bit words required to hold data
	int compressed_window = s_rate * no_bits;
	int window_text_size = (compressed_window / 16) + (compressed_window % 16 == 0 ? 0 : 1);

	std::cerr << "# 16-bit words per sample: " << window_text_size << std::endl << std::endl;

	// get the total number of samples
	int no_samples = ((length+1) / s_rate) + ((length+1) % s_rate == 0 ? 0 : 1);

	// establish sample size and allocate memory blob
	std::size_t sample_size = sizeof(std::uint16_t) * window_text_size + sizeof(std::uint32_t) * alpha;
	std::size_t blob_size = no_samples * sample_size;
	std::uint8_t *blob = new std::uint8_t[blob_size];
	//std::uint8_t *blob = (std::uint8_t*) malloc(blob_size);

	// preprocess
	sampled_bwt<unsigned char, std::uint32_t>(bwt, length, alpha, terminator, s_rate, no_bits, sample_size, blob);
	delete[] bwt;

	// append further metadata
	int out_size;
	std::uint64_t metadata[3];
	metadata[0] = s_rate;
	metadata[1] = no_bits;
	metadata[2] = sample_size;

	fb.sputn((char*) metadata, sizeof(std::uint64_t) * 3);
	EVP_EncryptUpdate(cc, NULL, &out_size, (std::uint8_t*) metadata, sizeof(std::uint64_t) * 3);

	append_blob(cc, fb, (std::uint8_t*) C, sizeof(std::uint32_t) * (alpha + 1), enc_data, outbuf_size);

	// final copy into file
	append_blob(cc, fb, (std::uint8_t*) blob, blob_size, enc_data, outbuf_size);

	delete[] blob;
	delete[] C;

	delete[] enc_data;
}
