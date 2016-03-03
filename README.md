idunno.Authentication.Basic
===========================

This project contains an implementation of [Basic Authentication](https://tools.ietf.org/html/rfc1945#section-11) for ASP.NET Core. 

It is meant as a demonstration of how to write authentication middleware and **not** as something you would seriously consider using.

### Notes

Basic Authentication sends credentials unencrypted. You should only use it over [HTTPS](https://en.wikipedia.org/wiki/HTTPS). 

It may also have performance impacts, credentials are sent and validated with every request. As you should not be storing passwords in clear text your validation procedure will have to hash and compare values
with every request, or cache results of previous hashes (which could lead to data leakage). 

Remember that hash comparisons should be time consistent to avoid [timing attacks](https://en.wikipedia.org/wiki/Timing_attack).