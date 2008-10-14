/* 
   oauthsign - command line oauth

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

#include <termios.h>
#include <grp.h>
#include <pwd.h>
*/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <getopt.h>
#include "system.h"

#include "oauth_common.h"

#define EXIT_FAILURE 1

char *xmalloc ();
char *xrealloc ();
char *xstrdup ();

static void usage (int status);

/* The name the program was run with, stripped of any leading path. */
char *program_name;

/* getopt_long return codes */
enum {DUMMY_CODE=129
      ,DRYRUN_CODE
};

/* Option flags and variables */

int want_quiet;			/* --quiet, --silent */
int want_verbose;		/* --verbose */
int want_dry_run;		/* --dry-run */

char *url = NULL;      //< the url to sign
char *c_key = NULL;    //< consumer key
char *c_secret = NULL; //< consumer secret
char *t_key = NULL;    //< token key
char *t_secret = NULL; //< token secret
int mode = 0;          //< mode: 0=GET 1=POST

static struct option const long_options[] =
{
  {"quiet", no_argument, 0, 'q'},
  {"silent", no_argument, 0, 'q'},
  {"verbose", no_argument, 0, 'v'},
  {"dry-run", no_argument, 0, DRYRUN_CODE},
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'V'},
  {"consumer-key", required_argument, 0, 'c'},
  {"consumer-secret", required_argument, 0, 'C'},
  {"token-key", required_argument, 0, 't'},
  {"token-secret", required_argument, 0, 'T'},
  {"CK", required_argument, 0, 'c'},
  {"CS", required_argument, 0, 'C'},
  {"TK", required_argument, 0, 't'},
  {"TS", required_argument, 0, 'T'},
  {"request", required_argument, 0, 'r'},
  {"post", no_argument, 0, 'p'},
  {"base-url", no_argument, 0, 'B'},
  {"base-string", no_argument, 0, 'b'},
  {NULL, 0, NULL, 0}
};


/** Set all the option flags according to the switches specified.
 *  Return the index of the first non-option argument.  
 */
static int decode_switches (int argc, char **argv) {
  int c;

  while ((c = getopt_long (argc, argv, 
			   "q"	/* quiet or silent */
			   "v"	/* verbose */
			   "h"	/* help */
			   "V" 	/* version */
			   "c:" 	/* consumer-key*/
			   "C:" 	/* consumer-secret */
			   "t:" 	/* token-key*/
			   "T:" 	/* token-secret */
			   "r:" 	/* request */
			   "p" 	/* post */
			   "B" 	/* base-URL*/
			   "b",	/* base-string*/
			   long_options, (int *) 0)) != EOF) {
      switch (c) {
	case 'q':		/* --quiet, --silent */
	  want_quiet = 1;
	  break;
	case 'v':		/* --verbose */
	  want_verbose = 1;
	  break;
	case DRYRUN_CODE:	/* --dry-run */
	  want_dry_run = 1;
	  break;
	case 'V':
	  printf ("oauth_urils %s\n", VERSION);
	  exit (0);

	case 'b':
    mode&=~(8|16);
    mode|=8;
    break;
	case 'B':
    mode&=~(8|16);
    mode|=16;
    break;
	case 'p':
    mode|=1; // XXX
    break;
	case 'r':
    break;
	case 't':
	case 'T':
	case 'c':
	case 'C':
    break;
	case 'h':
	  usage (0);

	default:
	  usage (EXIT_FAILURE);
	}
    }
  return optind;
}


static void
usage (int status)
{
  printf (_("%s - \
command line utilities for oauth\n"), program_name);
  printf (_("Usage: %s [OPTION]... URL [CKey] [CSec] [TKey] [Tsec]\n"), program_name);
  printf (_("\
Options:\n\
  --dry-run                   take no real actions\n\
  -q, --quiet, --silent       inhibit usual output\n\
  --verbose                   print more information\n\
  -h, --help                  display this help and exit\n\
  -V, --version               output version information and exit\n\
  -b, --base-string      \n\
  -r, --request               HTTP request type (POST, GET)\n\
  -p, --post                  same as -r POST\n\
  -c, --CK, --consumer-key     \n\
  -C, --CS, --consumer-secret   \n\
  -t, --TK, --token-key        \n\
  -T, --TS, --token-secret     \n\
"));
  exit (status);
}


int main (int argc, char **argv) {
  int i;

  program_name = argv[0];

  i = decode_switches (argc, argv);

  /* do the work */

  exit (0);
}

/* vim: set sw=2 ts=2 sts=2 et : */
