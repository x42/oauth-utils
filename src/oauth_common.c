/* 
   oauth_common - command line oauth

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
#include <stdlib.h>
#include <string.h>
#include <oauth.h>

#include "oauth_common.h"

extern int want_quiet;
extern int want_verbose;


int oauthsign_alt (int mode, oauthparam *op) {
  if (mode==1) { // GET
    char *geturl = NULL;
    geturl = oauth_sign_url(op->url, NULL, OA_HMAC, op->c_key, op->c_secret, op->t_key, op->t_secret);
    if(geturl) {
      printf("%s\n", geturl);
      free(geturl);
    }
  } else { // POST
    char *postargs = NULL, *post = NULL;
    post = oauth_sign_url(op->url, &postargs, OA_HMAC, op->c_key, op->c_secret, op->t_key, op->t_secret);
    if (!post || !postargs) {
    	return (1);
    }
    if (mode==2) { // print postargs only
      if (postargs) printf("%s\n", postargs);
    } else if (mode==3) { // print url and postargs
      if (post && postargs) printf("%s\n%s\n", post, postargs);
    } else if (post && postargs) {
      char *reply = oauth_http_post(post,postargs);
      if(reply){
      	//write(STDOUT, reply, strlen(reply))
        printf("%s\n", reply);
      	free(reply);
      }
    }
    if(post) free(post);
    if(postargs) free(postargs);
  }
  return (0);
}

/**
 * split and parse URL parameters replied by a oauth-server
 * into <em>oauth_token</em> and <em>oauth_token_secret</em>.
 */
int parse_reply(const char *reply, char **token, char **secret) {
  int rc;
  int ok=1;
  char **rv = NULL;
  rc = oauth_split_url_parameters(reply, &rv);
  qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
  if( rc==2 
      && !strncmp(rv[0],"oauth_token=",11)
      && !strncmp(rv[1],"oauth_token_secret=",18) ) {
    ok=0;
    if (token)  *token =strdup(&(rv[0][12]));
    if (secret) *secret=strdup(&(rv[1][19]));
#if 1
    printf("key:    '%s'\nsecret: '%s'\n",*token, *secret); // XXX 
#endif
  }
  if(rv) free(rv);
  return ok;
}

int url_to_array(int *argcp, char ***argvp, int mode, char *url) {
  if (mode&1) // GET
    (*argcp) = oauth_split_url_parameters(url, argvp);  // same as oauth_split_post_paramters(url, &argv, 1);
  else if (mode&2) // POST
    (*argcp) = oauth_split_post_paramters(url, argvp, 2); // bit0(1): replace '+', bit1(2): don't replace '\001' -> '&'
  else {
    fprintf(stderr, "WARNING: don't know how to parse request\n"); // XXX
    (*argcp) = 0;
  }
  return (*argcp);
// reverse:
//result = oauth_serialize_url(argc, (postargs?1:0), argv);
}

void add_param_to_array(int *argcp, char ***argvp, char *addparam) {
#if 0
#define ADD_TO_ARGV \
  argv=(char**) xrealloc(argv,sizeof(char*)*(argc+1)); \
  argv[argc++]=xstrdup(oarg); 
  // append signature to query args.
  snprintf(oarg, 1024, "oauth_signature=%s",sign);
  ADD_TO_ARGV;
#endif
  (*argvp)=(char**) xrealloc(*argvp,sizeof(char*)*((*argcp)+1));
  (*argvp)[(*argcp)++]= (char*) xstrdup(addparam); 
}

void add_kv_to_array(int *argcp, char ***argvp, char *key, char *val) {
  char *param = (char*) xmalloc(sizeof(char)*(strlen(key)+strlen(val)+2)); 
  param[0]='\0';
  if (strchr(key,'=')) fprintf(stderr, "WARNING: '=' in parameter-keys MUST be url-escaped.\n");
  strcat(param,key); 
  strcat(param,"=");
  strcat(param,val);
#if 0
  char *t = oauth_url_escape(key);
  if (t) { strcat(param,t); free(t); }
  strcat(param,"=");
  t = oauth_url_escape(val);
  if (t) { strcat(param,t); free(t); }
#endif
  add_param_to_array(argcp, argvp, param);
  free(param);
}

char *process_array(int argc, char **argv, int mode, oauthparam *op) {
  char *base_url;
  char *okey, *odat, *sign;

  // sort parameters
  qsort(&argv[1], argc-1, sizeof(char *), oauth_cmpstringp);
  // serialize URL
  base_url= oauth_serialize_url_parameters(argc, argv);

  if (mode&16 || want_verbose) fprintf(stdout, "base-url=%s\n",base_url); // base-url
  if (mode&16) exit(0);

  // generate signature
  okey = oauth_catenc(2, op->c_secret, op->t_secret);
  odat = oauth_catenc(3, mode&2?"POST":"GET", argv[0], base_url);
  if (mode&8  || want_verbose) fprintf(stdout, "base-string=%s\n",odat); // base-string
  if (mode&32 || want_verbose) fprintf(stdout, "secrets=%s\n",okey); 
  if (mode&8) exit(0);

  switch(op->signature_method) {
    case OA_RSA:
      sign = oauth_sign_rsa_sha1(odat,okey);
    	break;
    case OA_PLAINTEXT:
      sign = oauth_sign_plaintext(odat,okey);
    	break;
    default:
      sign = oauth_sign_hmac_sha1(odat,okey);
  }
  free(odat); 
  free(okey);
  if (mode&128 || want_verbose) fprintf(stdout, "oauth_signature=%s\n",sign); 
  return sign; // needs to be free()d
}

int oauthsign (int mode, oauthparam *op) {
  int argc;
  char **argv = NULL;
  url_to_array(&argc, &argv, mode, op->url);

  char *tmp;
  // add oAuth arguments
	if (!oauth_param_exists(argv,argc,"oauth_nonce")) {
    add_kv_to_array(&argc, &argv, "oauth_nonce", (tmp=oauth_gen_nonce()));
		free(tmp);
	}

	if (!oauth_param_exists(argv,argc,"oauth_timestamp")) {
    char tmp2[128];
		snprintf(tmp2, 128, "%li", time(NULL));
    add_kv_to_array(&argc, &argv, "oauth_timestamp", tmp2);
	}

	if (op->t_key) {
    add_kv_to_array(&argc, &argv, "oauth_token", op->t_key);
  }

  add_kv_to_array(&argc, &argv, "oauth_consumer_key", op->c_key);
  add_kv_to_array(&argc, &argv, "oauth_signature_method", op->signature_method==OA_HMAC?"HMAC-SHA1":op->signature_method==OA_RSA?"RSA-SHA1":"PLAINTEXT");
	if (!oauth_param_exists(argv,argc,"oauth_version")) {
    add_kv_to_array(&argc, &argv, "oauth_version", "1.0");
  }

  char *sign=NULL;
  if ((sign=process_array(argc, argv, mode, op))) { 
    add_kv_to_array(&argc, &argv, "oauth_signature", sign);
    free(sign);
  }

  // array to url() 
  char *result; 
  result = oauth_serialize_url(argc, (mode&2?1:0), argv);
  printf("%s\n", result); // XXX post/get..
  free(result);

  return (0);
}

/* vim: set sw=2 ts=2 sts=2 et : */
