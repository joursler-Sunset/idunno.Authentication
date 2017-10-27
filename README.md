# idunno.Authentication

This repository contains a collection of various authentication mechanisms for ASP.NET Core, including

* [Basic Authentication](src/idunno.Authentication.Basic/readme.md)
* [Certificate Authentication](src/idunno.Authentication.Certificate/readme.md)

Basic Authentication started as a demonstration of how to write authentication middleware and was not 
as something you would seriously consider using, but some people want Basic Authentication and 
Certificate Authentication is a common request on the ASP.NET Core Security repo, so I am releasing my own versions of them.

All work is targetted at ASP.NET Core 2.0.

This is **not** an official Microsoft project, this is an "In my spare time, entirely unsupported"™ effort.

## Are these available as nuget packages?

nuget packages are available for the ASP.NET Core 2.0 versions of the authentication handlers.


## What about older versions of ASP.NET Core?

Older versions of Basic Authentication are available in the appropriate branch.
Certificate authentication is only available for ASP.NET Core 2.0.

| ASP.NET Core MVC Version | Branch                                                           |
|--------------------------|------------------------------------------------------------------|
| 1.1                      | [rel/1.1.1](https://github.com/blowdart/idunno.Authentication/tree/rel/1.1.1) |
| 1.0                      | [rel/1.0.0](https://github.com/blowdart/idunno.Authentication/tree/rel/1.0.0) |

## Notes

Each handler requires you to authenticate the credentials passed. 
You are responsible for hardening this authentication and ensuring it performs under load.
