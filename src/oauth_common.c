#include <stdio.h>
#include <stdlib.h>
#include <oauth.h>

int oauthsign ( 
  int mode,       //< mode: 0=GET 1=POST
  char *url,      //< the url to sign
  char *c_key,    //< consumer key
  char *c_secret, //< consumer secret (or NULL)
  char *t_key,    //< token key (or NULL)
  char *t_secret) //< token secret (or NULL)
{ 

  if (mode==1) { // GET
    char *geturl = NULL;
    geturl = oauth_sign_url(url, NULL, OA_HMAC, c_key, c_secret, t_key, t_secret);
    if(geturl) {
      printf("%s\n", geturl);
      free(geturl);
    }
  } else { // POST
    char *postargs = NULL, *post = NULL;
    post = oauth_sign_url(url, &postargs, OA_HMAC, c_key, c_secret, t_key, t_secret);
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
