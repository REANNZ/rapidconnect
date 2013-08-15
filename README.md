# AAF Rapid Connect

Author: Bradley Beddoes

Status: Currently in public beta


## Overview

The AAF Rapid Connect service will allow us to translate SAML assertions which are verified by a standard Shibboleth SP into formats which may be more palitable for use by services with restricted environments or no need to access some of the more advanced parts of the AAF offering.

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
See the documentation directory for futher technical guides on setting up AAF Rapid Connect and connecting to it from remote services.