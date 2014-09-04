package com;

import javax.naming.*;
import javax.naming.directory.*;

import java.util.Hashtable;
import java.util.Properties;
import java.util.Enumeration;
import java.util.Map;
import java.util.HashMap;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * This class to be used for authenticating against an LDAP server
*/
public class AuthenticationService {
	
	/** import these attributes from the config file */
	private static String INITIAL_CONTEXT_FACTORY;
	private static String PROVIDER_URL;
	private static String PROVIDER_TYPE;
	private static String SECURITY_AUTHENTICATION;
	private static String BASE_DN;
	private static String AD_DOMAIN;
	private static String USERS_LOC;
	private static String GROUPS_LOC;
	private static boolean LDAP_OVERRIDE;
	private static String LDAP_OVERRIDE_UNAME;
	private static String LDAP_OVERRIDE_PWORD;
	private static String AD_ANON_BIND_UNAME;
	private static String AD_ANON_BIND_PWORD;
	private static String ATTRIBUTE_NAME_KEYFOB_ID;
	private static String ATTRIBUTE_NAME_UNAME;
	
	// attributes are case-insensitive, but we type them as they appear in AD directory listing anyways
	public static String MY_ATTRS[] = { "cn", "memberOf", "givenName", "name", "sn", "sAMAccountName", "serialNumber" };
	private static Map<String, String> groups;
	
	/** to allow connections from multiple methods */
	private DirContext ctx;
	
	/** track error messages */
	private String errorStack =""; // init to not null
	
	/** default constructor
	  * reads in the configuration file and parses values
	  * */
	
	public AuthenticationService() {
		// read in the properties file
		try {
			// go get the properties for this LDAP connection
			Properties configFile = new Properties();
			// load the file from the class path (moved there by ant task)
			configFile.load(this.getClass().getClassLoader().getResourceAsStream("./ldap.properties"));
			
			// send ouput to console
		//	enumerateContents(configFile.propertyNames());
			
			this.INITIAL_CONTEXT_FACTORY = configFile.getProperty("INITIAL_CONTEXT_FACTORY");
			
			this.SECURITY_AUTHENTICATION = configFile.getProperty("SECURITY_AUTHENTICATION");
						
			this.PROVIDER_TYPE = configFile.getProperty("PROVIDER_TYPE");
			
			if(this.PROVIDER_TYPE.equals("AD")) {
				this.PROVIDER_URL = configFile.getProperty("AD_PROVIDER_URL");
				this.AD_DOMAIN = configFile.getProperty("AD_DOMAIN");
				this.BASE_DN = configFile.getProperty("AD_BASE_DN");
				this.GROUPS_LOC = configFile.getProperty("AD_GROUPS_LOC");
				this.USERS_LOC = configFile.getProperty("AD_USERS_LOC");
				this.AD_ANON_BIND_UNAME = configFile.getProperty("AD_ANON_BIND_UNAME");
				this.AD_ANON_BIND_PWORD = configFile.getProperty("AD_ANON_BIND_PWORD");
				this.ATTRIBUTE_NAME_KEYFOB_ID = configFile.getProperty("ATTRIBUTE_NAME_KEYFOB_ID");
				this.ATTRIBUTE_NAME_UNAME = configFile.getProperty("ATTRIBUTE_NAME_UNAME");
			}
			else if (this.PROVIDER_TYPE.equals("LDAP")) {
				this.PROVIDER_URL = configFile.getProperty("LDAP_PROVIDER_URL");
				this.BASE_DN = configFile.getProperty("LDAP_BASE_DN");
				this.GROUPS_LOC = configFile.getProperty("LDAP_GROUPS_LOC");
				this.USERS_LOC = configFile.getProperty("LDAP_USERS_LOC");
			}
			else {
				throw new Exception("Provider type not found.");
			}
			
			// get override info
			this.LDAP_OVERRIDE = Boolean.parseBoolean(configFile.getProperty("LDAP_OVERRIDE"));
			this.LDAP_OVERRIDE_UNAME = configFile.getProperty("LDAP_OVERRIDE_UNAME");
			this.LDAP_OVERRIDE_PWORD = configFile.getProperty("LDAP_OVERRIDE_PWORD");
			
			// init the array list
			groups = new HashMap<String, String>();
			// load the groups into a String array
			for (Enumeration e = configFile.propertyNames() ; e.hasMoreElements() ;) {
				String key = e.nextElement().toString();
				if (key.indexOf("GROUP_") == 0) { // ie key in key=value pair matches "GROUP_"
					// append the group name to the array list for checking later
					groups.put(key,configFile.getProperty(key));
				}
			}
			
		}
		catch (FileNotFoundException e) {
		//	e.printStackTrace();
			System.err.println("FileNotFoundException: "+e.getMessage());
			errorStack+=e.getMessage()+"\n";
		}
		catch (IOException e) {
			/** @TODO set defaults, or just give up? */
		//	e.printStackTrace();
			System.err.println("IOException: "+e.getMessage());
			errorStack+=e.getMessage()+"\n";
		}
		catch (Exception e) {
			//	e.printStackTrace();
			System.err.println("Exception: "+e.getMessage());
			errorStack+=e.getMessage()+"\n";
		}
		
	}
	
	/**
	 * This method will test if a user has access to the LDAP, if so
	 * it will then check the list of groups and check for is access
	 * 
	 * @param String username as named via a uid in the LDAP
	 * @param String password clear text in LDAP
	 * @return Hashtable authenticate object
	*/
	public Hashtable authenticate (String username, String password, String keyfob_id) {
		
		Hashtable authHT = new Hashtable();
		
		if(keyfob_id != null) {
			System.out.println("attempted keyfob value: " + keyfob_id);
			// we need to bind with our anon bind user
			username = this.AD_ANON_BIND_UNAME;
			password = this.AD_ANON_BIND_PWORD;
		}
		
		// assume they will not pass the test
		boolean authenticated = false;
		
		// first check to see if we even need to hit LDAP (not overridden)
		if (this.LDAP_OVERRIDE) {
			System.out.println("Override Authentication");
			// just check against stored username/password, put in all groups
			if (username.equals(this.LDAP_OVERRIDE_UNAME) && password.equals(this.LDAP_OVERRIDE_PWORD)) {
				authenticated = true;
				// just add then to each group
				for(String key : groups.keySet()) {
					// push the name of the group and access to it boolean
					authHT.put(key,true); // method throws NamingException
				}
			}
			
		}
		else { 
			// authenticate agianst creditials server
			System.err.println("Trying "+this.PROVIDER_TYPE+" authentication by: " + username);
			
			try {
				
				// build a hash table to pass as a bindable event
				// Set up environment for creating initial context
				Hashtable<String,String> env = new Hashtable<String,String>(); 

				env.put(Context.INITIAL_CONTEXT_FACTORY,this.INITIAL_CONTEXT_FACTORY);

				env.put(Context.SECURITY_AUTHENTICATION, this.SECURITY_AUTHENTICATION);
				// we take the uid to authenticate, pair it with the username, and append the base location
				env.put(Context.PROVIDER_URL, this.PROVIDER_URL);
				
				if(this.PROVIDER_TYPE.equals("AD")) {
					env.put(Context.SECURITY_PRINCIPAL, username + "@" + this.AD_DOMAIN);
				}
				else if (this.PROVIDER_TYPE.equals("LDAP")) {
					env.put(Context.SECURITY_PRINCIPAL, "uid="+username+","+this.USERS_LOC+this.BASE_DN);
				} // we don't need to throw errors here because first try/catch finds it

				env.put(Context.SECURITY_CREDENTIALS, password);

				// send env assigments to console
				// enumerateContents(env.elements());
				
				/**
				  * now that we have our hash values lets go authenticate
				  * */
				
				// first we want to connect to the LDAP Server and create initial context
				// making sure the user name and password are valid
			    ctx = new InitialDirContext(env); // Throws AuthenticationException if not valid username/password
				// WE NEVER GO PAST HERE IF AuthenticationException THROWN
				System.err.println("connection and creditials valid");
				
				/** we just split the two paths of AD and LDAP authentication because the LDAP way worked
				  * and we are migrating to AD. However we want to be able to easily switch back until the LDAP
				  * service is discontinued. Theoretically both services should be 'searchable' the same way
				  * at some point the LDAP code should be removed or universal code written
				  * */
				if(this.PROVIDER_TYPE.equals("AD")) {
					/** AD way, get the group list, if they match add */
					SearchControls constraints = new SearchControls();
					constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
					
					// either search by user name or by keyfob id. either way will return a user if one is found
					NamingEnumeration results = null;
					if(keyfob_id != null) {
						// we don't challenge on keyfob. assumed if you have keyfob you are that user
						System.out.println("searching for keyfob id: >"+keyfob_id+"<");
						results = ctx.search(this.USERS_LOC+this.BASE_DN, "("+this.ATTRIBUTE_NAME_KEYFOB_ID+"="+keyfob_id+")", constraints);
						authHT.put("keyfob_id",keyfob_id); // pass it back as proof positive we found it
					}
					else {
						results = ctx.search(this.USERS_LOC+this.BASE_DN, "("+this.ATTRIBUTE_NAME_UNAME+"="+username+")", constraints);
					}
					
					while (results != null && results.hasMore()) {
						SearchResult sr = (SearchResult) results.next();
						String dn = sr.getName() + ", " + this.USERS_LOC+this.BASE_DN;
												
						Attributes ar = ctx.getAttributes(dn, MY_ATTRS);
						if (ar == null) {
							// we need the user to have attributes
							throw new Exception("Entry " + dn + " has none of the specified attributes\n");
						}
						for (int i = 0; i < MY_ATTRS.length; i++) {
							Attribute attr = ar.get(MY_ATTRS[i]);
							if (attr == null) {
								continue;
							}
							System.out.println(MY_ATTRS[i] + ":");
							for (Enumeration vals = attr.getAll(); vals.hasMoreElements();) {
								String temp_next_element = vals.nextElement().toString(); // returns generic Object
								System.out.println("\t" + temp_next_element);
								
								// push the attributes to the auth HT
								if (!(authHT.containsKey(MY_ATTRS[i]))) {
									// push the name of the group and access to it boolean
									authHT.put(MY_ATTRS[i],temp_next_element);
								}
								
								// see if this element value matches any of my groups
								for(String key : groups.keySet()) {
									if (temp_next_element.toLowerCase().startsWith("cn="+groups.get(key).toLowerCase())) {
										// push the name of the group and access to it boolean
										authHT.put(key,true);
										
										// if user is found in ANY of the predefined groups they are 'authenticated' to login.
										// RolemManager.as handles ACL
										authenticated = true;
									}
								}
								
							}
						}
					}
					
					// now for any groups not found, set them to false
					for(String key : groups.keySet()) {
						if (!(authHT.containsKey(key))) {
							// push the name of the group and access to it boolean
							authHT.put(key,false);
						}
					}
					
					// end AD WAY

				}
				else if (this.PROVIDER_TYPE.equals("LDAP")) {
					// authenticated only in the sense they are a valid AD user
					authenticated = true;
					
					// now that we have verified they are a valid user, lets see what type of access they have
					// groups are specified in the config file as "GROUP_<name>" key=value pairs where value is the LDAP group name
					// and key is what we are looking for in the scheduling app
				    for(String key : groups.keySet()) {
						// push the name of the group and access to it boolean
						authHT.put(key,new Boolean(userInGroup(username,groups.get(key)))); // method throws NamingException
					}
				}
				else {
					throw new Exception("Provider type not found.");
				}

			    // Close the context when we're done
			    ctx.close();
			}
			catch (AuthenticationException e) {
				// binding to LDAP server with provided username/password failed
				// e.printStackTrace();
				System.err.println("AuthenticationException: "+e.getMessage()); // outputs -> [LDAP: error code 49 - Invalid Credentials]
				errorStack+=e.getMessage()+"\n";
			} 
			catch (NamingException e) {
				// catches invalid DN. Should not be thrown unless changes made to DN
				// Could also fail from the context of the called method userInGroup
				System.err.println("NamingException: "+e.getMessage());
				//e.printStackTrace();
				errorStack+=e.getMessage()+"\n";
			}
			catch (Exception e) {
				e.printStackTrace();
				System.err.println("Exception: "+e.getMessage());
				errorStack+=e.getMessage()+"\n";
			} 	
			finally { // make sure our connection is closed if relevant
				if (ctx != null) {
					try {
						ctx.close();
					} catch (NamingException e) {
						throw new RuntimeException(e);
					}
				}
			}
			
		}
		
		// push whether or not it was authenticated
		authHT.put("authenticated",new Boolean(authenticated));
		
		// spill contents to catalina.out file
		enumerateContents(authHT.keys());
		enumerateContents(authHT.elements());
		
		return(authHT);
	}
	
	/** return any failure codes. Since we only return boolean from
	 * authenticate method. Good idea to have way to see error
	 */
	public String getAuthenticateError () {
		System.err.println(errorStack); // send to catalina.out log file
		return errorStack;
	}
	
	/**
	 * after a user has successfully logged in we want to build
	 * an access object for use in the scheduling system
	 *
	 * @param String username
	 * @param String group a group name to check for username in (via memberUid string)
	 * @return boolean yes or no in the group
	 * @throws NamingException when the search fails by DN this will be thrown
	 */
	private boolean userInGroup (String username, String group) throws NamingException {
		// assume they are not
		boolean inGroup = false;
		
		// Specify the attributes to match
		Attributes matchAttrs = new BasicAttributes(true); // ignore attribute name case
		// set the common name for the group using defined prefix ie 'cn' or 'ou'
		matchAttrs.put(new BasicAttribute(this.GROUPS_LOC.substring(0,this.GROUPS_LOC.indexOf("=")),group)); // named group for access rights

		// Search for objects that have those matching attributes in the specified group location
		NamingEnumeration answer = ctx.search(this.GROUPS_LOC+this.BASE_DN, matchAttrs);
		
		// search for that user id in the member list
		while (answer.hasMore()) {
		    SearchResult sr = (SearchResult)answer.next();
		    if ((sr.getAttributes().get("memberuid").toString()).indexOf(username) >= 0) {
				// this user is in the specified group
				inGroup = true;
			}
		}
		System.err.println(username + " in " + group + ": "+new Boolean(inGroup).toString());
		return inGroup;
	}
	
	/** useful for diagnostic infomration, spit out a set of elements
	  * say in a hashtable or properties file
	  */
	private void enumerateContents(Enumeration e) {
		while (e.hasMoreElements()) {
			System.err.println(e.nextElement());
		}
	}
}