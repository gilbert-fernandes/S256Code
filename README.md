# S256Code
OpenID/OAuth2 tool to generate codeVerifier+challenge or get challenge from custom codeVerifier (relating to using PKCE in authentications)

Tool to generate a pair of codeVerifier + challenge from codeVerifier by applying S256 method to codeVerifier. This is compliant with PKCE RFC 7636 and enforced both the minimum and maximum entropy values, and length. A regexp pattern is also used to check the codeVerifier is compliant with section 2.3 RFC 3986. You can also enter a custom codeVerifier and get the S256(codeVerifier) expected for OpenID/OAuth2 clients. This is a basic Eclipse projet + Java API only1
 
https://tools.ietf.org/html/rfc7636
https://tools.ietf.org/html/rfc3986
 
This code is in the public domain. Do whatever you want with it.
If you really want a license let's say it's BSD without attribution.
