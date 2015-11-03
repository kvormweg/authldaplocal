# LDAP+local authentication backend for Dokuwiki

## Scenario
This backend can be used if you want to use Dokuwiki together with a corporate LDAP, but you do not have any control over the structure of the LDAP. It allows you to keep all the access data for your wiki in Dokuwiki´s plain text files and still use the corporate LDAP for authentication so your contributers will not need to memorize yet another user name and password.

## History
As I am in the same situation as describe above I have used for more than two years a self-developed patch for Dokuwiki´s LDAP authentication backend. And I did file a wishlist bug for inclusion of that patch into Dokuwiki base. This wishlist bug was rejected and so the next logical step was creating a separate backend for this scenario, even though the authentication process is a mix between LDAP and plain.

Ths mix shows if you have a look at the code. The backend is inherited from the LDAP backend. It overwrites most of the functions with simple variants. Additionally it contains a lot of functions from the Plain backend, again with small variations in most of these.

## License
This authentication backend is published under the GPL V2.

## Installation
Unpack the file into the `/lib/plugins` directory of your Dokuwiki installation. It will create a directory named 'authldaplocal' there.

## Configuration
As of Dokuwiki release 2013-05-10 (Weatherwax) auth plugins are treated almost in the same way as normal plugins. They are installed in the plugin directory and have a configuration dialog. Configuration of the backend is done through the dokuwiki configuration dialog:

Mark 'Use Access Control Lists', select 'authldaplocal' as the authentication backend:

![Screenshot 1 of configuration page](https://github.com/kvormweg/ldaplocal/tree/master/ldaplocal1.jpg "Screenshot 1 of configuration page")

configure your LDAP server:

![Screenshot 2 of configuration page](https://github.com/kvormweg/ldaplocal/tree/master/ldaplocal2.jpg "Screenshot 2 of configuration page")

````
# Use access control
$conf['useacl'] = 1;
#  Authentication type LDAP using local ACLs
$conf['authtype']     = 'authldaplocal';
# LDAP server URL (required)
$conf['plugin']['authldaplocal']['server']      = 'ldap://ldap.example.com:389';
# port (required but may be zero)
$conf['plugin']['authldaplocal']['port']   = 0;
# root dn for the user tree (required)
$conf['plugin']['authldaplocal']['usertree']    = 'ou=People, dc=example, dc=com';
# filter for users, %{user} will be replaced by user id (required)
$conf['plugin']['authldaplocal']['userfilter']  = '(&(uid=%{user})(objectClass=posixAccount))';
# ldap version is optional but may be required for your server
$conf['plugin']['authldaplocal']['version']    = 3;
````
## Functions
The backend will try to authenticate every login against the configured LDAP server. In addition it will look up every user in your local /conf/users.auth.php. When both conditions are met, the user is logged in.

Groups may be acquired from the LDAP but it is recommended to create and use local groups.

The user manager can be used to add, delete or edit users. User information is pulled from the LDAP when necessary or convenient. It is not possible to add users not in the LDAP via the user manager.

## ToDo
Reuse of code from other authentication backends has to be improved.

