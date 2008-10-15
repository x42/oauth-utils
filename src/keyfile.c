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
#include <string.h>
#include <stdlib.h>

#include "oauth_common.h"

char *xmalloc ();
char *xrealloc ();
char *xstrdup ();

extern int want_quiet;
extern int want_verbose;

int parseoption (oauthparam *op, char *item, char *value) {
  int rv =0;
  if      (!strncasecmp(item,"oauth_consumer_key",18)) {
    if(op->c_key) free(op->c_key);
    op->c_key=xstrdup(value); rv|=1;
  }
  else if (!strncasecmp(item,"oauth_consumer_secret",21)) {
    if(op->c_secret) free(op->c_secret);
    op->c_secret=xstrdup(value); rv|=1;
  }
  else if (!strncasecmp(item,"oauth_token_key",15)) {
    if(op->t_key) free(op->t_key);
    op->t_key=xstrdup(value); rv|=1;
  }
  else if (!strncasecmp(item,"oauth_token_secret",18)) {
    if(op->t_secret) free(op->t_secret);
    op->t_secret=xstrdup(value); rv|=1;
  }
  else if (!strncasecmp(item,"oauth_token_secret",18)) {
    if(op->t_secret) free(op->t_secret);
    op->t_secret=xstrdup(value); rv|=1;
  }
  else if (!strncasecmp(item,"oauth_signature_method",22)) {
    if (!strcmp(value, "PLAINTEXT")) {
      op->signature_method = OA_RSA;
      rv|=1;
    } else if (!strcmp(value, "RSA-SHA1")) {
      op->signature_method = OA_RSA;
      rv|=1;
    } else if (!strcmp(value, "HMAC-SHA1")) {
      op->signature_method = OA_HMAC; 
      rv|=1;
    }
  }
  return rv;
}

#define MAX_LINE_LEN (8192)

int read_keyfile(char *fn, oauthparam *op) {
  FILE *fp;
  char line[MAX_LINE_LEN];
  char *token, *item, *value;
  int lineno=0;

  if (!(fp=fopen(fn,"r"))) {
    //fprintf(stderr,"configfile failed: %s (%s)\n",fn,strerror(errno));
    return (-1);
  }

  while( fgets(line, MAX_LINE_LEN-1, fp) != NULL ) {
    lineno++;
    line[MAX_LINE_LEN-1]=0;
    token = strtok(line, "\t =&\n\r") ; 
    if(token != NULL && token[0] != '#' && token[0] != ';') {
      item=strdup(token);
      token = strtok( NULL, "\t =i&\n\r" ) ; 
      if (!token) {
		    free(item);
		    fprintf(stderr, "ERROR parsing config file. %s:%d\n",fn,lineno);
		    exit(1);
      }	
	    value=strdup(token);
      if (!parseoption(op,item,value)) {
        fprintf(stderr, "ERROR parsing config file. %s:%d\n",fn,lineno);
        exit(1);
      }
      free(item); free(value);
    }
  }
  fclose(fp);
  return 0;
}

int save_keyfile(char *fn, oauthparam *op) {
  char sep = '\n'; // '&'
  FILE *f = fopen(fn, "w");
  if (!f) return -1;
  if(op->c_key) fprintf(f,"oauth_consumer_key=%s%c", op->c_key, sep);
  if(op->c_secret) fprintf(f,"oauth_consumer_secret=%s%c", op->c_secret, sep);
  if(op->t_key) fprintf(f,"oauth_token_key=%s%c", op->t_key, sep);
  if(op->t_secret) fprintf(f,"oauth_token_secret=%s%c", op->t_secret, sep);
  switch(op->signature_method) {
    case OA_RSA:
      fprintf(f,"oauth_signature_method=%s%c", "RSA-SHA1", sep);
      break;
    case OA_PLAINTEXT:
      fprintf(f,"oauth_signature_method=%s%c", "PLAINTEXT", sep);
      break;
    case OA_HMAC:
      fprintf(f,"oauth_signature_method=%s%c", "HMAC-SHA1", sep);
      break;
    default:
      break;
    }
  //... url ?!
  return(-1);
}
