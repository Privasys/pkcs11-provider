/* C helpers that fill Cryptoki info structs (fixed-size, space-padded fields)
 * so the Go layer never touches blank-padded char arrays directly. */
#ifndef PRIVASYS_HELPERS_H
#define PRIVASYS_HELPERS_H

#include "cryptoki.h"

void privasys_fill_info(CK_INFO_PTR p);
void privasys_fill_slot_info(CK_SLOT_INFO_PTR p);
void privasys_fill_token_info(CK_TOKEN_INFO_PTR p, const char *label);

#endif
