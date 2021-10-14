# LDAPBrowserInPega
This piece of java code can be used to create a simple function / activity in Pega which is capable of **running a LDAP Query** and **mapping the results in to a Clipboard Page** in Pega

The activity takes in the following **parameters**

* AuthService - string (required)
* LDAPSearchQuery - string
* LDAPSearchMaxResultCount - integer
* LDAPSearchTimeOut - integre
* ResultPage - Page Name

It utilized the following **local variables** 

* errorMessage - string
* preExistingOper - boolean
* Message - string
* attributesObj - object

The parameter **LDAPSearchQuery** the the one which will allow LDAP reqries to be Passed Example : 
> example (&(objectClass=organizationalPerson)(CN=*)(memberOf=CN=Pega Dev Users,OU=Role,OU=Standard,OU=my Groups,DC=xxx,DC=com,DC=au))
