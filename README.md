# AAF Rapid Connect

[![Build Status][BS img]][Build Status]
[![Dependency Status][DS img]][Dependency Status]
[![Code Climate][CC img]][Code Climate]
[![Coverage Status][CS img]][Code Climate]

[Build Status]: https://codeship.com/projects/91224
[Dependency Status]: https://gemnasium.com/ausaccessfed/rapidconnect
[Code Climate]: https://codeclimate.com/github/ausaccessfed/rapidconnect

[BS img]: https://img.shields.io/codeship/314a53c0-0cd9-0133-9f8f-7aae0ba3591b/develop.svg
[DS img]: https://img.shields.io/gemnasium/ausaccessfed/rapidconnect.svg
[CC img]: https://img.shields.io/codeclimate/github/ausaccessfed/rapidconnect.svg
[CS img]: https://img.shields.io/codeclimate/coverage/github/ausaccessfed/rapidconnect.svg

Author: Bradley Beddoes and Shaun Mangelsdorf

Copyright 2013-2015, Australian Access Federation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Overview

The AAF Rapid Connect service will allow us to translate SAML assertions which are verified by a standard Shibboleth SP into formats which may be more palatable for use by services with restricted environments or no need to access some of the more advanced parts of the AAF offering.

### Benefits

* There is no need to install a Shibboleth SP on your webserver;
* It natively integrates into commonly used development languages;
* PaaS solutions like Heroku, Google App Engine and Pagoda become suitable deployment targets for AAF services;
* Attributes are already defined in logical sets, there is no approval process for attributes; and
* Integration code is minimal, simple to write and easy to test.

## JWT
The following is sourced from [the JWT specification](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred between two parties.  The claims in a JWT are encoded as a JavaScript Object Notation (JSON) object that is used as the payload of a JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure, enabling the claims to be digitally signed or MACed and/or encrypted.

The suggested pronunciation of JWT is the same as the English word "jot".

### Relationship of JWTs to SAML Assertions

SAML 2.0 provides a standard for creating
security tokens with greater expressivity and more security options
than supported by JWTs.  However, the cost of this flexibility and
expressiveness is both size and complexity.  SAML's use of XML
and XML DSIG contributes to the
size of SAML assertions; its use of XML and especially XML
Canonicalization contributes to their
complexity.

JWTs are intended to provide a simple security token format that is
small enough to fit into HTTP headers and query arguments in URIs.
It does this by supporting a much simpler token model than SAML and
using the JSON object encoding syntax.  It also supports
securing tokens using Message Authentication Codes (MACs) and digital
signatures using a smaller (and less flexible) format than XML DSIG.

Therefore, while JWTs can do some of the things SAML assertions do,
JWTs are not intended as a full replacement for SAML assertions, but
rather as a token format to be used when ease of implementation or
compactness are considerations.

SAML Assertions are always statements made by an entity about a
subject.  JWTs are often used in the same manner, with the entity
making the statements being represented by the "iss" (issuer) claim,
and the subject being represented by the "sub" (subject) claim.
However, with these claims being optional, other uses of the JWT
format are also permitted.

## Documentation
Documentation for application developers is provided as part of the web application e.g [https://rapid.aaf.edu.au/developers] (https://rapid.aaf.edu.au/developers)

Documentation for deployers of the Rapid Connect server software are provided in the documentation directory above along with example configurations in configuration.
