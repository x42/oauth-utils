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
