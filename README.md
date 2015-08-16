# kanar-ldap

LDAP support for Kanar. 

## Usage

Unfortunately, packages are not (yet) available in clojars repository. You need to compile and install manually both 
`kanar-core` and `kanar-ldap` projects.

Add the following dependency to `project.clj`: 


    [kanar/kanar-ldap "0.1-SNAPSHOT"] 



LDAP configuration data should look like this:

```
(def ldap-conf
 {:host "10.80.13.111"
  :bind-dn "cn=kanar,ou=mydept,o=myorg"
  :password "MyPassw0rd1"
  :num-connections 10
  :base-dn "ou=users,ou=mydept,o=myorg"
  :user-query "(cn=%s)"
  :user-re #"\w+"
 }
```



Also, most of functions require connection:

```
(def ldap-conn (clj-ldap.client/connect ldap-conf))
```

The `kanar.ldap` module contains functions that create various types of authenticators related to LDAP:

```
(kanar.ldap/ldap-auth-fn ldap-conn ldap-conf kl/edir-err-defs)
```

Returns authentication function that will look for `:username` and `:password` keys in request parameters and
return principal object with `:id` and `:dn` keys if authentication succeeds. 

```
(kanar.ldap/ldap-lookup-fn ldap-conn ldap-conf kl/edir-err-defs)
```

Returns authentication function that will expect a principal `:id` and return principal with `:dn` key added.

```
(kanar.ldap/ldap-attr-fn ldap-conn ATTR-MAP)
```

Returns authentication function that will expect a principal with `:dn` and will add mapped attributes from LDAP 
record to `:attributes`. 

```
(kanar.ldap/ldap-roles-fn ldap-conn :groupMembership :roles #"cn=([^,]+),.*")
```

Extracts LDAP groups and maps them as roles.

## License

Copyright © 2015 Rafal Lewczuk <rafal.lewczuk@jitlogic.com>

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
