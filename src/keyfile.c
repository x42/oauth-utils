/* 
   oauth utils - keyfile - command line oauth

   Copyright (C) 2008 Robin Gareus

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  

*/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>

#include "oauth_common.h"

char *xmalloc ();
char *xrealloc ();
char *xstrdup ();

extern int want_quiet;
extern int want_verbose;

int read_keyfile(char *fn, oauthparam *op) {
  return(-1);
}

int save_keyfile(char *fn, oauthparam *op) {
  char sep = '\n'; // '&'
  FILE *f = fopen(fn, "t");
  if (!f) return -1;
  if(op->c_key) fprintf(f,"oauth_consumer_key=%s%c", op->c_key, sep);
  //...

  return(-1);
}
