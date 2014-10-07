## JSON Web Token (JWT)
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

### Provided claims
The following claims are provided by Rapid Connect:

* **iss**: Identifies the principal that issued the JWT. For Rapid Connect this is always *https://rapidconnect.tuakiri.ac.nz* in the production environment, and *https://rapidconnect.staging.tuakiri.ac.nz* in the test environment.
* **iat**: Identifies the time at which the JWT was issued.
* **jti**: Provides a unique identifier for the JWT that can be used to prevent the JWT from being replayed.
* **nbf**: Identifies the time before which the JWT MUST NOT be accepted for processing
* **exp**: Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing
* **typ**: Declare a type for the contents of this JWT Claims Set in an application-specific manner in contexts where this is useful to the application
* **aud**: Identifies the audiences that the JWT is intended for. Each principal intended to process the JWT MUST identify itself with a value in audience claim.
* **sub**: Identifies the principal that is the subject of the JWT.
* **https://aaf.edu.au/attributes**: Contains a set of personally identifiable information associated with *sub* as provided by the remote AAF connected identity provider.

Timestamps are defined by the specification as **IntDate** values, which are: *A JSON numeric value representing the number of seconds from 1970-01-01T0:0:0Z UTC until the specified UTC date/time.*

## Integrating with Rapid Connect

### Before you get started
Before you get started with Rapid Connect ensure you **MUST** meet *all* of the following high level requirements:

1. You **MUST** be using **HTTPS** on your webserver for all JWT related endpoints. You **SHOULD** be using HTTPS for your entire application;
2. The organisation which owns the service you're registering must be an existing Tuakiri subscriber; and
3. You must have an existing account with a Tuakiri connected Identity Provider which you use to access Tuakiri services.

### Standard flow
1. The user accesses your application and is provided access to any public content you wish them to see
2. When authentication is required users need to be directed to a specific URL within Rapid Connect unique to your application which is provided as part of registration. This can be achieved by:
    1. Presenting the unique URL as a link on your authentication page for the user to click on;
    2. Code within your application provides the user's browser with a 302 response directing the browser to the unique URL.
3. The user will authenticate to their institution's Identity Provider via their usual means. This will sometimes require selecting their Identity Provider from a list of providers at the Tuakiri Discovery Service
4. Rapid Connect will validate the user's identity information and generate a unique and signed JWT (JWS) for your application using the secret you define when you register your service
5. The generated JWT (JWS) will be sent via HTTP **POST** to the callback endpoint for your application which you define when you register your service.


### Create an endpoint for your application to process JWT

#### AAF Examples
The following AAF developed example code may assist your understanding when writing your own integration code:

* [Ruby](https://gist.github.com/bradleybeddoes/6154072)
* [Python](https://gist.github.com/bradleybeddoes/5b64a39e96298b4811d7)
* [PHP](https://gist.github.com/bradleybeddoes/7051824753235cde90b8)

#### Integration Steps

##### 1. Select a JWT library
To get started with Rapid Connect integration select a suitable JWT library from the following for your application. These libraries will assist developers in quickly implementing JWT support. Libraries are not listed in any particular order and not endorsed by us. You should evaluate them individually to determine which best suits your needs. Found a useful JWT library not listed here? [Please let us know about it](mailto:support@aaf.edu.au?subject=New JWT library).

###### Ruby
* Devise and omniauth: [https://github.com/jbarona/omniauth-jwt/tree/flexible-options](https://github.com/jbarona/omniauth-jwt/tree/flexible-options). Contributed by **James Barona** from the *South Australian Health and Medical Research Institute*. A specific integration example is available within the following gist [https://gist.github.com/jbarona/7574703](https://gist.github.com/jbarona/7574703)
* [https://github.com/progrium/ruby-jwt](https://github.com/progrium/ruby-jwt)
* [https://github.com/nov/json-jwt](https://github.com/nov/json-jwt)

###### Java
* [https://bitbucket.org/nimbusds/nimbus-jose-jwt/wiki/Home](https://bitbucket.org/nimbusds/nimbus-jose-jwt/wiki/Home)
* [https://code.google.com/p/jsontoken/](https://code.google.com/p/jsontoken/)
* [http://docs.oracle.com/cd/E23943_01/security.1111/e10037/jwt.htm#CIHFBCBG](http://docs.oracle.com/cd/E23943_01/security.1111/e10037/jwt.htm#CIHFBCBG)

###### Python
* [https://github.com/magical/jwt-python](https://github.com/magical/jwt-python)
* [https://github.com/progrium/pyjwt](https://github.com/progrium/pyjwt)

###### PHP
* [https://github.com/cfrett/JWT-PHP](https://github.com/cfrett/JWT-PHP)
* [https://github.com/luciferous/jwt](https://github.com/luciferous/jwt)

###### Node
* [https://github.com/hokaccha/node-jwt-simple](https://github.com/hokaccha/node-jwt-simple)

###### .NET
* [https://github.com/johnsheehan/jwt](https://github.com/johnsheehan/jwt)
* [https://nuget.org/packages/JWT](https://nuget.org/packages/JWT)

###### Go
* [https://github.com/mendsley/gojwt](https://github.com/mendsley/gojwt)

###### Perl
* Example Perl code by 
Michael Lynch from EResearch Support Group, Information Technology Division, University of Technology, Sydney. [https://github.com/spikelynch/Osiris/blob/master/Osiris/lib/Osiris/AAF.pm](https://github.com/spikelynch/Osiris/blob/master/Osiris/lib/Osiris/AAF.pm)

###### Haskell
* [https://hackage.haskell.org/package/jwt](https://hackage.haskell.org/package/jwt)
* Example Haskell application by Dr Carlo Hamalainen, Centre for Advanced Imaging, University of Queensland

    * [http://carlo-hamalainen.net/blog/2014/8/3/haskell-yesod-aaf-rapid-connect-demo](http://carlo-hamalainen.net/blog/2014/8/3/haskell-yesod-aaf-rapid-connect-demo)
    * [https://github.com/carlohamalainen/rapid-connect-yesod-demo](https://github.com/carlohamalainen/rapid-connect-yesod-demo)

##### 2. Create a secret
The first step in integrating your code is to compute a secret that will be shared between your applicaition and Rapid Connect for signing and verifying JWT.

Recommended secret generation method on *nix hosts, **32 characters long**:

    openssl rand -base64 24

This value should never be publicly disclosed. Once created be sure to store it securely. *This value will be required during service registration*.

##### 3. Provide a web accessible endpoint
Your application MUST define a https endpoint which accepts *only* a HTTP **POST** request.

The endpoint must acquire the data provided in the parameter **assertion** for further processing.

##### 4. Validate the signed JWT (JWS) your application has received
Should any stage of the below validation fail your application **MUST** discard the token and present the user with a suitable error message.

1. Verify that the signature for the signed JWT you have received is valid by using your locally stored secret value
2. Ensure that the **iss** claim has the value *https://rapid.aaf.edu.au* when in the production environment, or *https://rapid.test.aaf.edu.au* when in the test environment
3. Ensure that the **aud** claim has the value of your application's primary URL (provided as part of service registration)
4. Ensure that the current time is *later* then the time provided in the **nbf** claim
5. Ensure that the current time is *before* then the time provided in the **exp** claim
6. Ensure that the value of the **jti** claim does not exist in a local storage mechanism of **jti** claim values you have accepted. If it doesn't (this **SHOULD** be the case) add the **jti** claim value to your local storage mechanism for future protection against replay attacks

All applications connecting to Tuakiri must adhere to all relevant Tuakiri rules and policies, available at the [Tuakiri website](https://tuakiri.ac.nz/). Prior to approving the connection of your service to the federation, Tuakiri may request to review your JWT related code and test your running endpoint to verify that an application's JWT handling conforms to the above requirements.

##### 5. Make use of the user's personal information
Your application now has a fully verified JWT provided by Rapid Connect.

By looking at the claim **https://aaf.edu.au/attributes** you will be able to access information about the user which most Research and Scholarly applications require. The following core [Tuakiri attributes](https://tuakiri.ac.nz/confluence/display/Tuakiri/Attributes) **SHOULD** be available:

1. cn
2. mail
3. displayname
4. edupersontargetedid
5. edupersonscopedaffiliation

The following optional [Tuakiri attributes](https://tuakiri.ac.nz/confluence/display/Tuakiri/Attributes) **MAY** be available at the discretion of the user's Identity Provider:

1. eduPersonPrincipalName: The "NetID" of the person for the purposes of inter-institutional authentication. 
2. givenname: A person's first name or preferred name
3. surname: A person's surname

You can now use this data to create a local account suitable for internal use by your application, for customisation and other purposes. It is **highly** recommended that you use the data provided in **edupersontargetedid** to uniquely identify users (the same value will be provided for this attribute for all subsequent vists to your application by this user).

### Register your service

Access the [Rapid Connect website](/) and click on the button for "Register a service". This is on the right hand side in a blue color under the current version information. At that point you will be asked to select your Identity Provider and authenticate. Once this process is complete you will be returned to the service registration page.

To complete registration please provide:

1. Organisation - The Tuakiri subscribed organisation which is sponsoring this service.
1. Name - A descriptive name for your service.
2. URL - The primary URL of your application which users would enter in the browser to visit your application. This value is provided to your application as the **aud** claim.
3. Callback URL - The secure URL within your application that Rapid Connect should **POST** completed responses to. We described this endpoint as part of the *Integration Steps* above.
4. Secret - Must be random and securely stored by the service. This value should never be publicly disclosed and is used by the service to verify signed tokens from Rapid Connect. We generated this as part of the *Integration Steps* shown above.


#### If you're registering in the production federation
Once submitted the Tuakiri will review and contact you with any questions. You should expect a response via email within 2 business days which will include a unique URL within Rapid Connect for your application to start the authentication process as we discussed in *Standard Flow* above.

#### If you're registering in the test federation
Your application will be **automatically approved**. The completion screen will show the unique URL for your application to initiate login. You can use this immediently with your application to start the authentication process as we discussed in *Standard Flow* above.

## Buttons
Tuakiri provides buttons in several sizes which your application **should** use to let your users know they can login via Tuakiri. These buttons are used in marketing and help documentation which is provided to end user support desks and makes the process of logging in seem familiar for users across multiple applications.

You may hotlink or rehost these images. Please use in accordance with the [AAF logo use policy](http://www.aaf.edu.au/wp-content/uploads/2010/05/AAF_LogoUsePolicy_05_10.pdf) <small>(PDF)</small>.

**110x26** <br>
![AAF tiny login](/aaf_service_110x26.png "AAF Login")
		
**223x54** <br>
![AAF tiny login](/aaf_service_223x54.png "AAF Login")
		
**439x105** <br>
![AAF tiny login](/aaf_service_439x105.png "AAF Login")
		
**866x193** <br>
![AAF tiny login](/aaf_service_866x193.png "AAF Login")

## Help
To get help with Rapid Connect simply [email Tuakiri support on support@tuakiri.ac.nz](mailto:support@tuakiri.ac.nz?subject=Help with integrating Rapid Connect)
