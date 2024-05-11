# LDAP Authentication

*Originally posted April 8, 2010 by James at https://txcowboycoder.wordpress.com/2010/04/08/ldap-authentication/*

Recently I needed a way to build authentication into a Flex application.

Instead of using a model baked into the Flex code that need recompilation, or other security concerns with flat files, I built a simple LDAP authentication java file, paired with a .properties file and is called via RemoteObject in flex.

I’ve posted code that uses simple authentication (no encryption over the wire) as this is an internal application, but it can be enhanced to do so.

The constructor builds an object that can connect to a LDAP source, all LDAP configuration is managed via the .properties file.

The heavy lifting is done by an authenticate method, returns a hash table (serialized as an object in flex). This allows me to see a) if they are authenticated, and b) what groups they are in using dot notation.

```actionscript3
// Pseudocode -- remote object has a handler method, doesn't actually return an object (java code returns HashTable, serialized as object)
ldapAuthObj:Object = remoteObject.authenticate("username","password");
 
// now we can look at the object
if (ldapAuthObj.authenticated) { /** user was validated */ }
if (ldapAuthObj.GROUP_<name>) { /** user was in group */ }
```

[AuthenticationService.java](AuthenticationService.java)

[ldap.properties](ldap.properties)
