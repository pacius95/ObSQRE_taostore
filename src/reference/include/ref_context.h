#ifndef SUBTOL_CONTEXT_H
#define SUBTOL_CONTEXT_H

#include <ipp/ippcp.h>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <fstream>

struct ref_context_t {
	std::filebuf &fb;
	size_t N;
	unsigned int alpha;
	uint32_t *C;
	IppsAES_GCMState *cc;
	
	uint32_t *suffix_array;
	int64_t current_start_index;
	int64_t current_end_index;
	bool has_sa = false;
		
	ref_context_t(std::filebuf &fb, size_t N, unsigned int alpha, IppsAES_GCMState *cc): fb(fb) {
		this->N = N;
		this->alpha = alpha;
		this->cc = cc;

		C = nullptr;
	}

	virtual ~ref_context_t() {
		if(cc != nullptr)
			std::free(cc);

		if(C != nullptr)
			delete[] C;
	}

	void verify_mac(std::uint8_t *mac) {
		uint8_t final_mac[16];
		ippsAES_GCMGetTag(final_mac, 16, cc);

		assert(std::memcmp(final_mac, mac, 16) == 0);

		std::free(cc);
		cc = nullptr;

		fb.close();
	}

	void load_sa(unsigned int buffer_size); 	
	unsigned int fetch_sa(int num_occ, uint32_t **occ);

	// virtual methods
	virtual void init() = 0;
	virtual void load_index(std::size_t buffer_size) = 0;

	// put the sauce here!!!
	virtual void query(unsigned char *q, int qlen, std::int64_t &start, std::int64_t &end) = 0;
};

#endif // SUBTOL_CONTEXT_H
