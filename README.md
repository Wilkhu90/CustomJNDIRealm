# CustomJNDIRealm
A Custom JNDI Realm for authenticating users without setting plain-text connectionPassword in server.xml

# Key things to make sure
1) JCE files from Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files are present in $JAVA_HOME/jre/lib/security
2) commons-codec.jar file is copied to $CATALINA_HOME/lib