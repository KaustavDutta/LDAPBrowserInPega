/*
The auth service record takes in search filter - example (&(objectClass=organizationalPerson)(CN=*)(memberOf=CN=Pega Dev Users,OU=Role,OU=Standard,OU=my Groups,DC=xxx,DC=com,DC=au))
Create a activity with the following params 
AuthService - string (required)
LDAPSearchQuery - string
LDAPSearchMaxResultCount - integer
LDAPSearchTimeOut - integre
ResultPage - Page Name
and Local Variables
errorMessage - string
preExistingOper - boolean
Message - string
attributesObj - object
then have 2 page news one for step page (Code-Security) and one for Param.ResultPage (Code-Pega-List)
*/


/*
//step 3 have the folowing java
String key = tools.getParamValue("AuthService");
ClipboardPage cbp = tools.createPage("Data-Admin-AuthService", "");
cbp.putString("pyName", key);
Database db = tools.getDatabase();
ClipboardPage aspage = null;
try {
  aspage = db.open(cbp, false);
  aspage.rename("AuthService");
}
catch(DatabaseException e) {
  errorMessage = "Failed to open Data-Admin-AuthService: " + key + ", reason: " + e.getMessage();
oLog.error(errorMessage);
}
if (aspage == null) {
  errorMessage = "Failed to open Data-Admin-AuthService: " + key + ", record not found";
oLog.error(errorMessage);
}
*/

/* step 4 */

boolean isLdapS = false;
ServiceUtils svcUtil = tools.getServiceUtils();
// initialization
preExistingOper = true;
boolean auth = false;
ClipboardPage asPage = tools.findPage("AuthService");
errorMessage = "Could not bind to directory";

// get credentials
String userid = tools.getParamValue("UserIdentifier");

String password = tools.getParamValue("Password");
// bind info
String initialContextFactory = asPage.getString("pyInitialContextFactory");
String url = asPage.getString("pyProviderURL");
String bindUser = asPage.getString("pyBindDN");
bindUser.replace("\\", "\\\\");
String ePW = asPage.getString("pyBindPW");

// determine if url is reference to jndi entry
if (!url.startsWith("ldap")) {
    String jndi = url;
    String tmpurl = com.pegarules.generated.pega_rules_utilities.getJNDIEntry(jndi);
    if (tmpurl.length() == 0) {
        errorMessage = "A provider url could not be found for JNDI entry " + jndi;
        oLog.error(errorMessage);
    }
    url = tmpurl;
}

//get the trust store's (key store) data instance name
String trustStore = asPage.getString("pyTrustStore");
String sslProtocol = asPage.getString("pySSLProtocol");
String trustStorePass = null;
byte[] trustStoreBytes = null;
String trustStoreType = null;
ClipboardPage trustStorePage = null;
java.security.KeyStore trustStoreObject = null;

//validates whether Trust Store name is provided when ldaps is used as protocol
if (url.startsWith("ldaps")) {
    isLdapS = true;
    if (trustStore.length() == 0) {
        errorMessage = "A trust store is required when using ldaps";
        oLog.error(errorMessage);
    }
}

// decrypt password
String bindPW = tools.getPRCrypto().decrypt(ePW);

// filter info
String dirContext = asPage.getString("pyDirectoryContext");
String search = asPage.getString("pySearchFilter");
String filter = null;
filter = "(&(objectClass=organizationalPerson)(memberOf=CN=Pega Dev Users,OU=Role,OU=Standard,OU=SEWL Groups,DC=sewl,DC=com,DC=au))";
if (search.length() > 0) filter = search;
if (tools.getParamValue("LDAPSearchQuery").length() > 0) filter = tools.getParamValue("LDAPSearchQuery");

oLog.debug("Executing LDAP Search in LDAP Server" + url + " using search query " + filter);

java.util.Properties p = new java.util.Properties();
p.setProperty(javax.naming.Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
p.setProperty(javax.naming.Context.PROVIDER_URL, url);
p.setProperty(javax.naming.Context.SECURITY_PRINCIPAL, bindUser);
p.setProperty(javax.naming.Context.SECURITY_CREDENTIALS, bindPW);

//look for trust store only in case of ldaps
if (isLdapS) {
    //open the trust store data instance
    if (!trustStore.equals("")) {
        KeyStoreUtils keystoreUtils = pega.getKeyStoreUtils();
        try {
            trustStorePage = keystoreUtils.getKeystoreInstance(trustStore);
        } catch (Exception ex) {
            oLog.error(ex);
            throw new PRRuntimeException("Failed to open keystore instance");
        }

        trustStoreObject = keystoreUtils.getKeystore(trustStorePage);
        String pass = trustStorePage.getString("pyKeystorePassword");
        trustStorePass = svcUtil.decodePassword(pass);
        trustStoreType = trustStorePage.getString("pyKeystoreType");
    }

    try {
        if (trustStorePage != null) {
            //set the ThreadLocal variables so that PegaSSLProtocolSocketFactory can use truststore specified within the thread's execution scope
            com.pega.apache.commons.pega.PegaSSLProtocolSocketFactory.setTlTrustStore(trustStoreObject);
            com.pega.apache.commons.pega.PegaSSLProtocolSocketFactory.setTlTrustStorePassword(trustStorePass);
            com.pega.apache.commons.pega.PegaSSLProtocolSocketFactory.setTlSSLProtocol(sslProtocol);
        }
    } catch (Throwable e) {
        throw new ConnectorException("here Couldn't create ldaps connection" + e.getMessage());
    }
    //set the custom socket factory as required by jndi ldap api
    p.setProperty("java.naming.ldap.factory.socket", "com.pega.apache.commons.pega.PegaSSLProtocolSocketFactory");
    //Added to cater to socket time out
    p.setProperty("com.sun.jndi.ldap.read.timeout", "2000");
}


// bind to the directory server
javax.naming.directory.DirContext context = null;

try {
    // connect to the server
    context = new javax.naming.directory.InitialDirContext(p);

    javax.naming.directory.SearchControls searchControls = new javax.naming.directory.SearchControls();
    searchControls.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);

    searchControls.setReturningAttributes(null);
    String[] returnAttributes = {
        "nsRole",
        "uid",
        "objectClass",
        "givenName",
        "description",
        "sn",
        "cn",
        "title",
        "mail",
        "manager",
        "department",
        "telephoneNumber",
        "memberOf"
    };
    ClipboardProperty listProp = asPage.getProperty("pyPropertyMappings");

    java.util.HashMap < String, String > attrPropMap = new java.util.HashMap < > ();

    for (int i = 1; i <= listProp.size(); i++) {
        ClipboardPage mapPage = listProp.getPageValue(i);
        returnAttributes[i] = mapPage.getString("pyExternalAttributeName");
        attrPropMap.put(mapPage.getString("pyExternalAttributeName"), mapPage.getString("pyPropertyName").substring(1));
    }

    searchControls.setReturningAttributes(returnAttributes);

    long LDAPSearchMaxResultCount;
    LDAPSearchMaxResultCount = tools.getParamAsInteger(PropertyInfo.TYPE_INTEGER, "LDAPSearchMaxResultCount");
    if (LDAPSearchMaxResultCount == 0)
        LDAPSearchMaxResultCount = 20;
    searchControls.setCountLimit(LDAPSearchMaxResultCount);

    int LDAPSearchTimeOut;
    LDAPSearchTimeOut = tools.getParamAsInteger(PropertyInfo.TYPE_INTEGER, "LDAPSearchTimeOut");
    if (LDAPSearchTimeOut == 0)
        LDAPSearchTimeOut = 2000;
    searchControls.setTimeLimit(LDAPSearchTimeOut);

    searchControls.setReturningObjFlag(true);
    javax.naming.NamingEnumeration res = context.search(dirContext, filter, searchControls);
    auth = true;
    //Code block initialize map attributes
    java.util.Map allAttribs = new java.util.HashMap();
    attributesObj = allAttribs;

    int count = 0;

    String OptputPage = "";

    

    while (res.hasMoreElements()) {
        count++;
        javax.naming.directory.SearchResult se = (javax.naming.directory.SearchResult) res.nextElement();
        javax.naming.directory.Attributes userAttrs = se.getAttributes();
        oLog.debug("#Result#" + count + "# " + userAttrs);

        ClipboardPage ResultPage = tools.createPage("Data-Admin-Operator-ID", "");

       // Code block for mapping LDAP reasults to clipboard page

        for (java.util.Map.Entry < String, String > entry: attrPropMap.entrySet()) {
            //oLog.infoForced(userAttrs.get(entry.getKey()).get(0));

            javax.naming.directory.Attribute attr = null;
            attr = userAttrs.get(entry.getKey());
            if (attr != null)
                if (attr.size() == 1) {
                    Object tmp = attr.get();
                    String val = (tmp != null) ? tmp.toString() : null;
                    ResultPage.getProperty(entry.getValue()).setValue(val);
                }
            else {
                ClipboardProperty CPT = ResultPage.getProperty(entry.getValue());
                CPT.clearValue();
                for (int j = 0; j < attr.size(); j++) {
                    Object tmp = attr.get(j);
                    String val = (tmp != null) ? tmp.toString() : null;
                    if (CPT.getMode() == 'l')
                        CPT.add(val);
                    if (CPT.getMode() == 's')
                        ResultPage.putString(entry.getValue(), val);

                }
            } else
                continue;
            //oLog.infoForced(attr.getID() + attr.size());
        }

        OptputPage = tools.getParamValue("ResultPage") + ".pxResults";
        tools.getProperty(OptputPage).add(ResultPage);
    }
    OptputPage = tools.getParamValue("ResultPage") + ".pxResultCount";
    tools.getProperty(OptputPage).setValue(count);
    oLog.debug("#Total Nummer of Results returned is #" + count);

    java.util.Map userAttrs = (java.util.Map) attributesObj;

} catch (javax.naming.PartialResultException pre) {
    // probably due to invalid user id specified in context.search()
    // based on testing done so far...
    errorMessage = "User not found in directory";
} catch (javax.naming.NamingException ne) {
    oLog.error("External authentication failed: ", ne);
    errorMessage = "Unexpected exception: " + ne.getMessage();
} finally {


    if (context != null) {
        try {
            context.close();
        } catch (javax.naming.NamingException e) {
            // ignore
        }
    }
}

if (auth) {
    errorMessage = "";
}

if (errorMessage.length() > 0) {
    errorMessage = "Authentication failed: " + errorMessage;
    oLog.error(errorMessage);
}
