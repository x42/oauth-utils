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

int want_quiet   = 0; /* --quiet, --silent */
int want_verbose = 0; /* --verbose */
int want_dry_run = 0; /* --dry-run */

int mode         = 1; ///< mode: 0=GET 1=POST
int request_mode = 0; ///< mode: 0=print info only; 1:perform HTTP request

int want_write   = 0;
int   oauth_argc = 0;
char **oauth_argv = NULL;
char *datafile   = NULL;
oauthparam op;

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

  {"data", required_argument, 0, 'd'},

//{"method", no_argument, 0, 'm'}, // oauth signature method

//{"file", required_argument, 0, 'f'},
//{"write", no_argument, 0, 'w'},  // only if '-f' given.
//{"writefile", required_argument, 0, 'W'}, //alike `-f XX -w -f YY`
  {NULL, 0, NULL, 0}
};

void reset_oauth_param(oauthparam *op) {
  if (op->t_key) free(op->t_key);
  if (op->t_secret) free(op->t_secret);
  if (op->c_key) free(op->c_key);
  if (op->c_secret) free(op->c_secret);
  memset(op,0,sizeof(oauthparam));
  op->signature_method=OA_HMAC;
}

void reset_oauth_token(oauthparam *op) {
  if (op->t_key) free(op->t_key);
  if (op->t_secret) free(op->t_secret);
  op->t_key=NULL;
  op->t_secret=NULL;
}

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
			   "c:" /* consumer-key*/
			   "C:" /* consumer-secret */
			   "t:" /* token-key*/
			   "T:" /* token-secret */
			   "r:" /* request */
			   "e"  /* erase token */
			   "E"  /* erase token and conusmer */
			   "p" 	/* post */
			   "B"  /* base-URL*/
			   "b"  /* base-string*/
			   "d:" /* URL-query parameter data eg.
               * '-d name=daniel -d skill=lousy'->'name=daniel&skill=lousy' */
			   "f:" /* read key/data file */
			   "F:" /* set key/data filename */
			   "w" 	/* write to key/data file, save request/access token state */
			   "x",	/* execute */
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
        mode&=~(1|2);
        mode|=2;
        break;
      case 'r':
        mode&=~(1|2|4);
        if (!strncasecmp(optarg,"GET",3))
          mode|=1;
     // else if (!strncasecmp(optarg,"POSTREQUEST",4))
     //   mode|=4;
        else if (!strncasecmp(optarg,"POST",4))
          mode|=2;
        else 
          usage (EXIT_FAILURE);
        break;
      case 't':
        if (op.c_key) free(op.c_key);
        op.c_key=xstrdup(optarg); 
      case 'T':
        if (op.c_secret) free(op.c_secret);
        op.c_secret=xstrdup(optarg); 
      case 'c':
        if (op.t_key) free(op.t_key);
        op.t_key=xstrdup(optarg); 
      case 'C':
        if (op.t_secret) free(op.t_secret);
        op.t_secret=xstrdup(optarg); 
        break;
      case 'd': // XXX
        add_param_to_array(&oauth_argc, &oauth_argv,optarg);
        break;
      case 'f':
        read_keyfile(optarg, &op);
      case 'F':
        if (datafile) free(datafile);
        datafile=xstrdup(optarg);
        break;
      case 'w':
        want_write=1;
        break;
      case 'x':
        request_mode=1;
        break;
      case 'e':
        reset_oauth_token(&op);
        break;
      case 'E':
        reset_oauth_param(&op);
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
  -v, --verbose               print more information\n\
  -h, --help                  display this help and exit\n\
  -V, --version               output version information and exit\n\
  -b, --base-string      \n\
  -r, --request               HTTP request type (POST, GET)\n\
  -p, --post                  same as -r POST\n\
  -c, --CK, --consumer-key     \n\
  -C, --CS, --consumer-secret   \n\
  -t, --TK, --token-key        \n\
  -T, --TS, --token-secret     \n\
  ... \n\
  other flags: e,E,r,x,b,B,d,f,F,w ...\n\
"));
  exit (status);
}


int main (int argc, char **argv) {
  int i;

  program_name = argv[0];
  memset(&op,0,sizeof(oauthparam));
  reset_oauth_param(&op);

  i = decode_switches (argc, argv);
  if (i>=argc) usage(1);
  op.url=xstrdup(argv[i++]);

  if (argc>i) { if (op.c_key) free(op.c_key); op.c_key=xstrdup(argv[i++]); }
  if (argc>i) { if (op.c_secret) free(op.c_secret); op.c_secret=xstrdup(argv[i++]); }
  if (argc>i) { if (op.t_key) free(op.c_key); op.t_key=xstrdup(argv[i++]); }
  if (argc>i) { if (op.t_secret) free(op.t_secret); op.t_secret=xstrdup(argv[i++]); }
  if (argc>i) 
      usage(EXIT_FAILURE);

  if (!op.c_key || strlen(op.c_key)<1) {
    fprintf(stderr, "Error: consumer key not set\n");
    exit(1);
  }

  // TODO:
  // error if  "-w" and no file-name "-f" or "-F"
  // warning if "-w" no actual request performed... "-x" 


  // do the work.
 
  if (0 && want_write) save_keyfile(datafile, &op); // TODO save current state

  if(request_mode) {
    // if (!want_dry_run) // TODO honor this here ?! 
    oauthrequest(mode&2, &op);
    // TODO: 
    // split this up - don't use oauthrequest() - walk thru oauthsign_ext() 
    // make the request, parse and save.. or output if not quiet.
    // LATER: provide a dedicated standalone executables that does a direct 
    // POST, GET request alike current oauthrequest() without all the 
    // '-b', '-B' options. - eg. oauthrawpost, oauthget etc.
  } else {
    char *sign;
    sign = oauthsign_ext(mode, &op, oauth_argc, oauth_argv);
    if (sign) free(sign);
    //oauthsign(mode, &op);
    //oauthsign_alt(mode&3, &op);
  }
 
  if (0 && want_write) save_keyfile(datafile, &op); // TODO save final state

  exit (0);
}

/* vim: set sw=2 ts=2 sts=2 et : */
