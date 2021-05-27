#ifndef SUBTOL_CONFIG_H
#define SUBTOL_CONFIG_H

// oram selection
enum obl_oram_t {
	OBL_CIRCUIT_ORAM = 0,
	OBL_PATH_ORAM,
	CIRCUIT_ORAM,
	PATH_ORAM,
	SHADOW_DORAM_V1,
	SHADOW_DORAM_V2,
	ASYNCH_DORAM,
	MOSE,
	ASYNCHMOSE
};

struct subtol_config_t {
	// general params
	obl_oram_t base_oram;
	unsigned int Z;
	unsigned int stash_size;
	// only for ring oram
	unsigned int S;
	unsigned int A;
	// only for recursive oram
	unsigned int csize;
	unsigned int sa_block;
	unsigned int tnum;
};

#endif // SUBTOL_CONFIG_H
