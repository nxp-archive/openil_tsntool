// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018 NXP
 */

#ifndef READINPUT_H_
#define READINPUT_H_

#include "main.h"


#define EDITOR "vi"

void initialize_readline(void);
char *readinput(const char *instruction, const char *tmpfile, FILE *output);

#endif /* READINPUT_H_ */
