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

int oauthsign (int mode, oauthparam *op) {
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

int xxxxxy(int argc, char **argv) {
  int mode=0; // HTTP methode
  OAuthMethod signmethod=0;
  char *base_url;
  char *okey, *odat, *sign;
  oauthparam *op;

#if 0
    argc = oauth_split_post_paramters(url, &argv, 2); // bit0(1): replace '+', bit1(2): don't replace '\001' -> '&'
    argc = oauth_split_post_paramters(url, &argv, 0);
    argc = oauth_split_url_parameters(url, &argv);  // same as oauth_split_post_paramters(url, &argv, 1);
#endif

  // sort parameters
  qsort(&argv[1], argc-1, sizeof(char *), oauth_cmpstringp);
  // serialize URL
  base_url= oauth_serialize_url_parameters(argc, argv);
  // generate signature
  okey = oauth_catenc(2, op->c_secret, op->t_secret);
  odat = oauth_catenc(3, mode&1?"POST":"GET", argv[0], base_url);
#if 1
  fprintf (stdout, "base_string='%s'\n", odat);
  fprintf (stdout, "key='%s'\n", okey);
#endif
  switch(signmethod) {
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
#if 0

#define ADD_TO_ARGV \
  argv=(char**) xrealloc(argv,sizeof(char*)*(argc+1)); \
  argv[argc++]=xstrdup(oarg); 

  // append signature to query args.
  snprintf(oarg, 1024, "oauth_signature=%s",sign);
  ADD_TO_ARGV;
#endif
  free(sign);

  // build URL params
//result = oauth_serialize_url(argc, (postargs?1:0), argv);
  return argc;
}

void add_param(int *argcp, char ***argvp, char *addparam) {
  (*argvp)=(char**) xrealloc(*argvp,sizeof(char*)*((*argcp)+1));
  (*argvp)[(*argcp)++]= (char*) xstrdup(addparam); 
}

void add_arg(int *argcp, char ***argvp, char *key, char *val) {
  char *param = (char*) xmalloc(sizeof(char)*(strlen(key)+strlen(val+2))); 
  param[0]='\0';
  strcat(param,key); // XXX must not contain '='
  strcat(param,"=");
  strcat(param,val);
#if 0
  char *t = oauth_url_escape(key);
  if (t) { strcat(param,t); free(t); }
  strcat(param,"=");
  t = oauth_url_escape(val);
  if (t) { strcat(param,t); free(t); }
#endif
  add_param(argcp, argvp, param);
}
