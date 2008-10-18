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
      ,CURLOUT_CODE
};

/* Option flags and variables */

int no_warnings  = 0; /* --no-warn */ // TODO 
int want_quiet   = 0; /* --quiet, --silent */
int want_verbose = 0; /* --verbose */
int want_dry_run = 0; /* --dry-run */

int mode         = 1; ///< mode: 1=GET 2=POST; general operation-mode - bit coded 
                      //  bit0 (1)  : enable ?! (also see want_dry_run)
                      //  bit1 (2)  : HTTP POST enable (no GET) 
                      //  bit2 (4)  : (unused ; old oauthrequest() compat)
                      //  bit3 (8)  : -b base-string and exit
                      //  bit4 (16) : -B base-url and exit
                      //  bit5 (32) :  print secrets along with base-string(8)
                      //  bit6 (64) :  print signature after generating it. (unless want_verbose is set: it's printed anyway)
                      //  bit7 (128):  parse reply (request token, access token)
                      //  bit8 (256):  toggle ouput Parameter escape. (dont escape GETs and escape POST params with format_array(..)
                      //  bit9 (512):  curl-output
                      //
int request_mode = 0; ///< mode: 0=print info only; 1:perform HTTP request

int print_as_get = 0; 
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
  {"signature-method", no_argument, 0, 'm'}, //  oauth signature method

  {"request", required_argument, 0, 'r'}, // HTTP request method (GET, POST)
  {"post", no_argument, 0, 'p'},
//{"escape-post-param", no_argument, 0, 'P'}, // TODO: rename ''--print-escaped''
  {"curl", no_argument, 0, CURLOUT_CODE}, // TODO: rename '--print-curl'
  {"data", required_argument, 0, 'd'},
  {"base-url", no_argument, 0, 'B'},
  {"base-string", no_argument, 0, 'b'},

  {"file", required_argument, 0, 'f'},
  {"write", no_argument, 0, 'w'}, 
//{"writefile", required_argument, 0, 'F'}, 
//{"execute", no_argument, 0, 'x'}, 
//{"oauthrequest", no_argument, 0, 'X'}, 
  {NULL, 0, NULL, 0}
};

/** Set all the option flags according to the switches specified.
 *  Return the index of the first non-option argument.  
 */
static int decode_switches (int argc, char **argv) {
  int c;

  while ((c = getopt_long (argc, argv, 
			   "h"	/* help */
			   "V" 	/* version */
			   "q"	/* quiet or silent */
			   "v"	/* verbose */
			   "b"  /* base-string*/
			   "B"  /* base-URL*/
			   "r:" /* HTTP Request method */
			   "p" 	/* post */
			   "d:" /* URL-query parameter data eg.
               * '-d name=daniel -d skill=lousy'->'name=daniel&skill=lousy' */
			   "m:" /* oauth signature Method */
			   "P" 	/* print escaped post parameters */
			   "G" 	/* always print as (escaped) GET parameters */ // FIXME: 'g' 'G' 'P' modifiers

			   "c:" /* consumer-key*/
			   "C:" /* consumer-secret */
			   "t:" /* token-key*/
			   "T:" /* token-secret */

			   "f:" /* read key/data file */
			   "w" 	/* write to key/data file, save request/access token state */
			   "F:" /* set key/data filename */
			   "x" 	/* execute */
			   "X" 	/* execute and parse reply */
			   "e"  /* erase token */
			   "E", /* erase token and conusmer */
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
      case CURLOUT_CODE:	/* --curl */
        mode|= 512;
        break;
      case 'V':
        printf ("%s %s (%s)", PACKAGE, VERSION, OS);
        #ifdef LIBOAUTH_VERSION
        printf (" liboauth/%s", LIBOAUTH_VERSION);
        #endif
        printf ("\n");
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
        if (op.t_key) free(op.t_key);
        op.t_key=xstrdup(optarg); 
        break;
      case 'T':
        if (op.t_secret) free(op.t_secret);
        op.t_secret=xstrdup(optarg); 
        break;
      case 'c':
        if (op.c_key) free(op.c_key);
        op.c_key=xstrdup(optarg); 
        break;
      case 'C':
        if (op.c_secret) free(op.c_secret);
        op.c_secret=xstrdup(optarg); 
        break;
      case 'd': 
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
      case 'X':
        mode|=128; // parse reply and enter request mode..
      case 'x':
        request_mode=1;
        break;
      case 'e':
        reset_oauth_token(&op);
        break;
      case 'E':
        reset_oauth_param(&op);
        break;
      case 'G':
        print_as_get=1;
        break;
      case 'P':
        mode|=256;
        break;
      case 'm':
        if (parse_oauth_method(&op, optarg)) usage(1);
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
  -h, --help                  display this help and exit\n\
  -V, --version               output version information and exit\n\
  -q, --quiet, --silent       inhibit usual output\n\
  -v, --verbose               print more information\n\
  \n\
  -b, --base-string           print OAuth base-string and exit\n\
  -B, --base-url              print OAuth base-URL and exit\n\
"/*
  --curl                      format output as `curl` commandline\n\
*/"\
  -r, --request <type>        HTTP request type (POST, GET [default])\n\
  -p, --post                  same as -r POST\n\
  -d, --data <key>[=<val>]    add url query parameters.\n\
  -m, --signature-method <m>  oauth signature method (PLAINTEXT,\n\
                              RSA-SHA1, HMAC-SHA1 [default])\n\
"/*
  -P,                         print URL-escaped POST parameters\n\ 
*/"\
  \n\
  -c, --CK, --consumer-key    <text> \n\
  -C, --CS, --consumer-secret <text> \n\
  -t, --TK, --token-key       <text> \n\
  -T, --TS, --token-secret    <text> \n\
  \n\
  -f, --file <filename>       read tokens and secrets from config-file\n\
  -w                          write tokens to config-file\n\
  -F <filename>               set config-file name w/o reading the file.\n\
  -x                          make HTTP request and return the replied content\n\
  -X                          make HTTP request and parse the reply for tokens\n\
                              use '-X -w' to request and store tokens.\n\
  -e, --erase-token           clear [access|request] tokens.\n\
  -E, --erase-all             wipe all tokens and reset method to HMAC-SHA1.\n\
  --dry-run                   take no real actions (with -x, -w or -X)\n\
  \n\
  The position of parameters -d, -f, -F, -e, -E and all tokens matters!\n\
  \n\
  Tokens are read from file at the moment the -f option is parsed overriding \n\
  the current value(s). Optional trailing key/secret params are parsed last.\n\
  eg.\n\
    '-f config.txt -e -C secret -F out.txt -w' reads the settings from file,\n\
  then deletes the access/request tokens and finally overrides the consumer-\n\
  secret. Only the consumer-key is left from config.txt and will be saved \n\
  to out.txt along with the new secret. If -X is given and the HTTP request\n\
  succeeds, the received token and secret will be stored as well.\n\
  \n\
  The request URL is constructed by first parsing all query-parameters from\n\
  the URL; then -d parameters are added, and finally oauth_XYZ params \n\
  appended.\n\
  \n\
"));
  exit (status);
}


int main (int argc, char **argv) {
  int i;
  int exitval=0;
  int oaargc =0;
  char **oaargv= NULL;
  char *sign = NULL;

  // initialize 

  program_name = argv[0];
  memset(&op,0,sizeof(oauthparam));
  reset_oauth_param(&op);

  // parse command line

  i = decode_switches (argc, argv);

  if (i>=argc) usage(1);
  op.url=xstrdup(argv[i++]);

  if (argc>i) { if (op.c_key) free(op.c_key); op.c_key=xstrdup(argv[i++]); }
  if (argc>i) { if (op.c_secret) free(op.c_secret); op.c_secret=xstrdup(argv[i++]); }
  if (argc>i) { if (op.t_key) free(op.c_key); op.t_key=xstrdup(argv[i++]); }
  if (argc>i) { if (op.t_secret) free(op.t_secret); op.t_secret=xstrdup(argv[i++]); }
  if (argc>i) 
      usage(EXIT_FAILURE);

  // check settings 

  if (!op.c_key || strlen(op.c_key)<1) {
    fprintf(stderr, "ERROR: consumer key not set.\n");
    exit(1);
  }

  if (want_write && !datafile || (datafile && strlen(datafile)<1)) {
    want_write=0;
    fprintf(stderr, "ERROR: no filename given. use -F or -f.\n");
    exit(1);
  }

  if (!(mode&2) && print_as_get) {
    if (!no_warnings)
      fprintf(stderr, "WARNING: -G is redundant with GET requests.\n");
  } else if (!want_quiet && print_as_get) {
    if (!no_warnings)
      fprintf(stderr, "WARNING: non standard output format.\n");
  }
  if ((mode&256) && !want_quiet) {
    if (!no_warnings)
      fprintf(stderr, "WARNING: non standard parameter escape settings.\n");
  }

  if (want_write && !want_dry_run) { // save current state
    if (save_keyfile(datafile, &op)) {
      want_write=0; // XXX 
      if (!no_warnings)
        fprintf(stderr, "WARNING: saving state to file '%s' failed.\n", datafile);
    } else if (want_verbose) {
      fprintf(stderr, "saved state to %s\n", datafile);
    }
  }
  
  sign = oauthsign_ext(mode, &op, oauth_argc, oauth_argv, &oaargc, &oaargv);

  if (sign && want_verbose) 
    fprintf(stderr, "oauth_signature=%s\n", sign);

  if(!request_mode) {
    if (sign) { 
      add_kv_to_array(&oaargc, &oaargv, "oauth_signature", sign);
      free(sign);
    }
    if (print_as_get) mode&=~2; // print as GET !
    format_array(mode, oaargc, oaargv);
  } else { // request_mode 
    char *reply;
    if (!sign) { 
      if (!no_warnings && !want_quiet) 
        fprintf(stderr,"WARNING: could not generate oAuth signature.\n");
      exitval|=8;
    }

    if (!want_dry_run) {
      reply = oauthrequest_ext(mode, &op, oaargc, oaargv, sign);
    } else { 
      if (!want_quiet || want_verbose) 
        fprintf(stderr, "DRY-RUN. not making any HTTP request.\n"); 
      if (sign) add_kv_to_array(&oaargc, &oaargv, "oauth_signature", sign);
      if (print_as_get) mode&=~2; // print as GET !
      format_array(mode, oaargc, oaargv);
      reply=NULL;
    }

    if (!reply) { 
      if (!exitval || want_verbose) fprintf(stderr,"ERROR: no reply from HTTP request.\n");
      exitval|=2;
    } else if (want_verbose || (mode&128)==0) {
      if(want_verbose) fprintf(stderr, "------HTTP reply------\n");
      fprintf(want_verbose?stderr:stdout, "%s\n", reply);
      if(want_verbose) fprintf(stderr, "----------------------\n");
    }

    if (!want_dry_run && (mode&128)) {
      reset_oauth_token(&op);
      if (parse_reply(reply, &(op.t_key), &(op.t_secret))) { 
        if (!exitval || want_verbose) fprintf(stderr,"ERROR: could not parse reply.\n");
        exitval|=4;
      } else if (!want_quiet) {
        printf ("token=%s\n",op.t_key);
        printf ("token_secret=%s\n",op.t_secret);
      }
    }

    if (sign) free(sign);
    if (reply) free(reply);
  }
 
  if (exitval==0 && want_write && !want_dry_run) { // save final state
    if (save_keyfile(datafile, &op)) {
      want_write=0;
      if (!no_warnings)
        fprintf(stderr, "WARNING: saving state to file '%s' failed.\n", datafile);
    } else if (want_verbose) {
      fprintf(stderr, "saved state to %s\n", datafile);
    }
  }
 
  free_array(oaargc, oaargv);
  free_array(oauth_argc, oauth_argv);
  return (exitval);
}

/* vim: set sw=2 ts=2 sts=2 et : */
