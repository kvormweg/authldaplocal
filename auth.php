<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
 * LDAP authentication backend with local ACL
 *
 * @license   GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author    Andreas Gohr <andi@splitbrain.org>
 * @author     Chris Smith <chris@jalakai.co.uk>
 * @author    Jan Schumann <js@schumann-it.com>
 * @author    Klaus Vormweg <klaus.vormweg@gmx.de>
 */
class auth_plugin_authldaplocal extends DokuWiki_Auth_Plugin {
    /* @var resource $con holds the LDAP connection*/
    protected $con = null;

    /* @var int $bound What type of connection does already exist? */
    protected $bound = 0; // 0: anonymous, 1: user, 2: superuser

    /* @var array $users User data cache */
    protected $users = null;

    /* @var array $_pattern User filter pattern */
    protected $_pattern = null;

    /**
     * Constructor
    */
    public function __construct() {
        parent::__construct();
        global $config_cascade;

        global $conf;
        if(!@is_readable($config_cascade['plainauth.users']['default'])) {
          $this->success = false;
        } else {
            if(@is_writable($config_cascade['plainauth.users']['default'])) {
            $this->cando['addUser']      = true;
            $this->cando['delUser']      = true;
            $this->cando['modLogin']     = true;
            $this->cando['modGroups']    = true;
          }
          $this->cando['getUsers']      = true;
          $this->cando['getGroups']     = true;
          $this->cando['getUserCount']  = true;
          $this->cando['logout']        = true;
        }
        // ldap extension is needed
        if(!function_exists('ldap_connect')) {
            $this->_debug("LDAP err: PHP LDAP extension not found.", -1, __LINE__, __FILE__);
            $this->success = false;
            return;
        }

    }

    /**
     * Check user+password
     *
     * Checks if the given user exists and the given
     * plaintext password is correct by trying to bind
     * to the LDAP server
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Klaus Vormweg <klaus.vormweg@gmx.de>
     * @param string $user
     * @param string $pass
     * @return  bool
     */
    public function checkPass($user, $pass) {
        // reject empty password
        if(empty($pass)) return false;
        if(!$this->_openLDAP()) return false;

        // check if local user exists
        if($this->users === null) $this->_loadUserData();
        if(!isset($this->users[$user])) return false;

        // indirect user bind
        if($this->getConf('binddn') && $this->getConf('bindpw')) {
            // use superuser credentials
            if(!@ldap_bind($this->con, $this->getConf('binddn'), $this->getConf('bindpw'))) {
                $this->_debug('LDAP bind as superuser: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
                return false;
            }
            $this->bound = 2;
        } else if($this->getConf('binddn') &&
            $this->getConf('usertree') &&
            $this->getConf('userfilter')
        ) {
            // special bind string
            $dn = $this->_makeFilter(
                $this->getConf('binddn'),
                array('user'=> $user, 'server'=> $this->getConf('server'))
            );

        } else if(strpos($this->getConf('usertree'), '%{user}')) {
            // direct user bind
            $dn = $this->_makeFilter(
                $this->getConf('usertree'),
                array('user'=> $user, 'server'=> $this->getConf('server'))
            );

        } else {
            // Anonymous bind
            if(!@ldap_bind($this->con)) {
                msg("LDAP: can not bind anonymously",-1);
                $this->_debug('LDAP anonymous bind: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
                return false;
            }
        }

        // Try to bind to with the dn if we have one.
        if(!empty($dn)) {
            // User/Password bind
            if(!@ldap_bind($this->con,$dn,$pass)) {
                $this->_debug("LDAP: bind with $dn failed", -1, __LINE__, __FILE__);
                $this->_debug('LDAP user dn bind: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
                return false;
            }
            $this->bound = 1;
            return true;
        } else {
            // See if we can find the user
            $info = $this->getUserData($user,true);
            if(empty($info['dn'])) {
                return false;
            } else {
                $dn = $info['dn'];
            }

            // Try to bind with the dn provided
            if(!@ldap_bind($this->con,$dn,$pass)) {
                $this->_debug("LDAP: bind with $dn failed", -1, __LINE__, __FILE__);
                $this->_debug('LDAP user bind: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
                return false;
            }
            $this->bound = 1;
            return true;
        }
        return false;
    }

    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email addres of the user
     * grps array   list of groups the user is in
     *
     * This LDAP specific function returns the following
     * addional fields:
     *
     * dn     string  distinguished name (DN)
     * uid    string  Posix User ID
     * inbind bool    for internal use - avoid loop in binding
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Trouble
     * @author  Dan Allen <dan.j.allen@gmail.com>
     * @author  <evaldas.auryla@pheur.org>
     * @author  Stephane Chazelas <stephane.chazelas@emerson.com>
     * @author  Klaus Vormweg <klaus.vormweg@gmx.de>
     *
     * @param   string $user
     * @param   bool   $inbind authldap specific, true if in bind phase
     * @return  array containing user data or false
     */
    public function getUserData($user, $inbind = false) {
        global $conf;
        if(!$this->_openLDAP()) return false;

        // force superuser bind if wanted and not bound as superuser yet
        if($this->getConf('binddn') && $this->getConf('bindpw') && $this->bound < 2) {
            // use superuser credentials
            if(!@ldap_bind($this->con, $this->getConf('binddn'), $this->getConf('bindpw'))) {
                $this->_debug('LDAP bind as superuser: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
                return false;
            }
            $this->bound = 2;
        }elseif($this->bound == 0 && !$inbind) {
            // in some cases getUserData is called outside the authentication workflow
            // eg. for sending email notification on subscribed pages. This data might not
            // be accessible anonymously, so we try to rebind the current user here
            list($loginuser,$loginsticky,$loginpass) = auth_getCookie();
            if($loginuser && $loginpass) {
                $loginpass = PMA_blowfish_decrypt($loginpass, auth_cookiesalt(!$loginsticky));
                $this->checkPass($loginuser, $loginpass);
            }
        }

        $info['user']   = $user;
        $info['server'] = $this->getConf('server');

        //get info for given user
        $base = $this->_makeFilter($this->getConf('usertree'), $info);
        if($this->getConf('userfilter')) {
            $filter = $this->_makeFilter($this->getConf('userfilter'), $info);
        } else {
            $filter = "(ObjectClass=*)";
        }

        $sr     = $this->_ldapsearch($this->con, $base, $filter, $this->getConf('userscope'));
        $result = @ldap_get_entries($this->con, $sr);
        $this->_debug('LDAP user search: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
        $this->_debug('LDAP search at: '.htmlspecialchars($base.' '.$filter), 0, __LINE__, __FILE__);

        // Don't accept more or less than one response
        if(!is_array($result) || $result['count'] != 1) {
            return false; //user not found
        }

        $user_result = $result[0];
        ldap_free_result($sr);

        // general user info
        $info['dn']   = $user_result['dn'];
        $info['gid']  = $user_result['gidnumber'][0];
        $info['mail'] = $user_result['mail'][0];
        $info['name'] = $user_result['cn'][0];
        $info['grps'] = array();

        // overwrite if other attribs are specified.
        if(is_array($this->getConf('mapping'))) {
            foreach($this->getConf('mapping') as $localkey => $key) {
                if(is_array($key)) {
                    // use regexp to clean up user_result
                    list($key, $regexp) = each($key);
                    if($user_result[$key]) foreach($user_result[$key] as $grp) {
                        if (preg_match($regexp,$grp,$match)) {
                            if($localkey == 'grps') {
                                $info[$localkey][] = $match[1];
                            } else {
                                $info[$localkey] = $match[1];
                            }
                        }
                    }
                } else {
                    $info[$localkey] = $user_result[$key][0];
                }
            }
        }
        $user_result = array_merge($info,$user_result);

        //get groups for given user if grouptree is given
        if($this->getConf('grouptree') || $this->getConf('groupfilter')) {
            $base   = $this->_makeFilter($this->getConf('grouptree'), $user_result);
            $filter = $this->_makeFilter($this->getConf('groupfilter'), $user_result);
            $sr     = $this->_ldapsearch($this->con, $base, $filter, $this->getConf('groupscope'), array($this->getConf('groupkey')));
            $this->_debug('LDAP group search: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
            $this->_debug('LDAP search at: '.htmlspecialchars($base.' '.$filter), 0, __LINE__, __FILE__);

            if(!$sr) {
                $this->_debug("LDAP: Reading group memberships failed", 0,__LINE__,__FILE__);
                $this->_debug('LDAP group search: '.htmlspecialchars(ldap_error($this->con)), 0,__LINE__,__FILE__);
            }
            $result = ldap_get_entries($this->con, $sr);
            ldap_free_result($sr);

            if(is_array($result)) foreach($result as $grp) {
                if(!empty($grp[$this->getConf('groupkey')][0])) {
                    $this->_debug('LDAP usergroup: '.htmlspecialchars($grp[$this->getConf('groupkey')][0]), 0, __LINE__, __FILE__);
                    $info['grps'][] = $grp[$this->getConf('groupkey')][0];
                }
            }
        }
        // merge local groups into group list
        if($this->users === null) $this->_loadUserData();
        if(is_array($this->users[$user]['grps'])) {
            foreach($this->users[$user]['grps'] as $group) {
                if(in_array($group,$info['grps'])) continue;
                $info['grps'][] = $group;
            }
        }
        // add the default group to the list of groups if list is empty
        if(!count($info['grps'])) {
            $info['grps'][] = $conf['defaultgroup'];
        }
        return $info;
    }

    /**
     * Create a new User
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user will be added to the default group by this
     * function if grps are not specified (default behaviour).
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Chris Smith <chris@jalakai.co.uk>
     *
     * @param string $user
     * @param string $pwd
     * @param string $name
     * @param string $mail
     * @param array  $grps
     * @return bool|null|string
     * @author  Klaus Vormweg <klaus.vormweg@gmx.de>
     */
    public function createUser($user, $pwd, $name, $mail, $grps = null) {
      global $conf;
      global $config_cascade;

      // local user mustn't already exist
      if($this->users === null) $this->_loadUserData();
      if(isset($this->users[$user])) {
      	msg('The user '.$user.' does already exist',-1);
      	return false;
      }
      // but the user must exist in LDAP
      $info = $this->getUserData($user,true);
      if(empty($info['dn'])) {
      	msg('The user '.$user.' does not exist in LDAP',-1);
        return false;	
      }
      // fetch real name and email from LDAP
      $name = $info['name'];
      $mail = $info['mail'];
      $pass = '';

      // set default group if no groups specified
      if (!is_array($grps)) $grps = array($conf['defaultgroup']);

      // prepare user line
      $groups = join(',',$grps);
      $userline = join(':',array($user,$pass,$name,$mail,$groups))."\n";

      if (io_saveFile($config_cascade['plainauth.users']['default'],$userline,true)) {
        $this->users[$user] = compact('pass','name','mail','grps');
        return TRUE;
      }

        msg(
            'The '.$config_cascade['plainauth.users']['default'].
                ' file is not writable. Please inform the Wiki-Admin', -1
        );
      return null;
    }

    /**
     * Modify user data
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @param   string $user      nick of the user to be changed
     * @param   array  $changes   array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    public function modifyUser($user, $changes) {
      global $ACT;
      global $config_cascade;

      // sanity checks, user must already exist and there must be something to change
      if (($userinfo = $this->getUserData($user)) === false) return false;
      if (!is_array($changes) || !count($changes)) return true;

      // update userinfo with new data, remembering to encrypt any password
      $newuser = $user;
      foreach ($changes as $field => $value) {
        if ($field == 'user') {
          $newuser = $value;
          continue;
        }
        if ($field == 'pass') $value = auth_cryptPassword($value);
        $userinfo[$field] = $value;
      }

      $groups = join(',',$userinfo['grps']);
      $userline = join(':',array($newuser, $userinfo['pass'], $userinfo['name'], $userinfo['mail'], $groups))."\n";

      if (!$this->deleteUsers(array($user))) {
        msg('Unable to modify user data. Please inform the Wiki-Admin',-1);
        return false;
      }

      if (!io_saveFile($config_cascade['plainauth.users']['default'],$userline,true)) {
        msg('There was an error modifying your user data. You should register again.',-1);
        // FIXME, user has been deleted but not recreated, should force a logout and redirect to login page
            $ACT = 'register';
        return false;
      }

      $this->users[$newuser] = $userinfo;
      return true;
    }

    /**
     *  Remove one or more users from the list of registered users
     *
     *  @author  Christopher Smith <chris@jalakai.co.uk>
     *  @param   array  $users   array of users to be deleted
     *  @return  int             the number of users deleted
     */
    public function deleteUsers($users) {
      global $config_cascade;

      if (!is_array($users) || empty($users)) return 0;

      if ($this->users === null) $this->_loadUserData();

      $deleted = array();
      foreach ($users as $user) {
        if (isset($this->users[$user])) $deleted[] = preg_quote($user,'/');
      }

      if (empty($deleted)) return 0;

      $pattern = '/^('.join('|',$deleted).'):/';

      if (io_deleteFromFile($config_cascade['plainauth.users']['default'],$pattern,true)) {
        foreach ($deleted as $user) unset($this->users[$user]);
        return count($deleted);
      }

      // problem deleting, reload the user list and count the difference
      $count = count($this->users);
      $this->_loadUserData();
      $count -= count($this->users);
      return $count;
    }

    /**
     * Return a count of the number of user which meet $filter criteria
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     *
     * @param array $filter
     * @return int
     */
    public function getUserCount($filter = array()) {

      if($this->users === null) $this->_loadUserData();

      if (!count($filter)) return count($this->users);

      $count = 0;
      $this->_constructPattern($filter);

      foreach ($this->users as $user => $info) {
          $count += $this->_filter($user, $info);
      }

      return $count;
    }

    /**
     * Bulk retrieval of user data
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     *
     * @param   int   $start index of first user to be returned
     * @param   int   $limit max number of users to be returned
     * @param   array $filter array of field/pattern pairs
     * @return  array userinfo (refer getUserData for internal userinfo details)
     */
    public function retrieveUsers($start = 0, $limit = 0, $filter = array()) {

      if ($this->users === null) $this->_loadUserData();

      ksort($this->users);

      $i = 0;
      $count = 0;
      $out = array();
      $this->_constructPattern($filter);

      foreach ($this->users as $user => $info) {
        if ($this->_filter($user, $info)) {
          if ($i >= $start) {
            $out[$user] = $info;
            $count++;
            if (($limit > 0) && ($count >= $limit)) break;
          }
          $i++;
        }
      }

      return $out;
    }

    /**
     * Only valid pageid's (no namespaces) for usernames
     *
     * @param string $user
     * @return string
     */
    public function cleanUser($user) {
        global $conf;
        return cleanID(str_replace(':',$conf['sepchar'],$user));
    }

    /**
     * Only valid pageid's (no namespaces) for groupnames
     *
     * @param string $group
     * @return string
     */
    public function cleanGroup($group) {
        global $conf;
        return cleanID(str_replace(':',$conf['sepchar'],$group));
    }

    /**
     * Load all user data
     *
     * loads the user file into a datastructure
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     */
    protected function _loadUserData() {
      global $config_cascade;

      $this->users = array();

      if(!@file_exists($config_cascade['plainauth.users']['default'])) return;

      $lines = file($config_cascade['plainauth.users']['default']);
      foreach($lines as $line){
        $line = preg_replace('/#.*$/','',$line); //ignore comments
        $line = trim($line);
        if(empty($line)) continue;

        $row    = explode(":",$line,5);
        $groups = array_values(array_filter(explode(",",$row[4])));

        $this->users[$row[0]]['pass'] = $row[1];
        $this->users[$row[0]]['name'] = urldecode($row[2]);
        $this->users[$row[0]]['mail'] = $row[3];
        $this->users[$row[0]]['grps'] = $groups;
      }
    }

   /**
     * Make LDAP filter strings.
     *
     * Used by auth_getUserData to make the filter
     * strings for grouptree and groupfilter
     *
     * @author  Troels Liebe Bentsen <tlb@rapanden.dk>
     * @param   string $filter ldap search filter with placeholders
     * @param   array  $placeholders placeholders to fill in
     * @return  string
     */
    protected function _makeFilter($filter, $placeholders) {
        preg_match_all("/%{([^}]+)/", $filter, $matches, PREG_PATTERN_ORDER);
        //replace each match
        foreach($matches[1] as $match) {
            //take first element if array
            if(is_array($placeholders[$match])) {
                $value = $placeholders[$match][0];
            } else {
                $value = $placeholders[$match];
            }
            $value  = $this->_filterEscape($value);
            $filter = str_replace('%{'.$match.'}', $value, $filter);
        }
        return $filter;
    }

    /**
     * return true if $user + $info match $filter criteria, false otherwise
     *
     * @author Chris Smith <chris@jalakai.co.uk>
     *
     * @param string $user User login
     * @param array  $info User's userinfo array
     * @return bool
     */
    protected  function _filter($user, $info) {
        foreach($this->_pattern as $item => $pattern) {
            if($item == 'user') {
                if(!preg_match($pattern, $user)) return false;
            } else if($item == 'grps') {
                if(!count(preg_grep($pattern, $info['grps']))) return false;
            } else {
                if(!preg_match($pattern, $info[$item])) return false;
            }
        }
        return true;
    }

    /**
     * construct a filter pattern
     *
     * @param array $filter
     */
    protected function _constructPattern($filter) {
        $this->_pattern = array();
        foreach($filter as $item => $pattern) {
            $this->_pattern[$item] = '/'.str_replace('/', '\/', $pattern).'/i'; // allow regex characters
        }
    }

    /**
     * Escape a string to be used in a LDAP filter
     *
     * Ported from Perl's Net::LDAP::Util escape_filter_value
     *
     * @author Andreas Gohr
     * @param  string $string
     * @return string
     */
    protected function _filterEscape($string) {
        return preg_replace(
            '/([\x00-\x1F\*\(\)\\\\])/e',
            '"\\\\\".join("",unpack("H2","$1"))',
            $string
        );
    }

    /**
     * Opens a connection to the configured LDAP server and sets the wanted
     * option on the connection
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     */
    protected function _openLDAP() {
        if($this->con) return true; // connection already established

        $this->bound = 0;

        $port    = $this->getConf('port');
        $bound   = false;
        $servers = explode(',', $this->getConf('server'));
        foreach($servers as $server) {
            $server    = trim($server);
            $this->con = @ldap_connect($server, $port);
            if(!$this->con) {
                continue;
            }

            /*
             * When OpenLDAP 2.x.x is used, ldap_connect() will always return a resource as it does
             * not actually connect but just initializes the connecting parameters. The actual
             * connect happens with the next calls to ldap_* funcs, usually with ldap_bind().
             *
             * So we should try to bind to server in order to check its availability.
             */

            //set protocol version and dependend options
            if($this->getConf('version')) {
                if(!@ldap_set_option(
                    $this->con, LDAP_OPT_PROTOCOL_VERSION,
                    $this->getConf('version')
                )
                ) {
                    msg('Setting LDAP Protocol version '.$this->getConf('version').' failed', -1);
                    $this->_debug('LDAP version set: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
                } else {
                    //use TLS (needs version 3)
                    if($this->getConf('starttls')) {
                        if(!@ldap_start_tls($this->con)) {
                            msg('Starting TLS failed', -1);
                            $this->_debug('LDAP TLS set: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
                        }
                    }
                    // needs version 3
                    if($this->getConf('referrals')) {
                        if(!@ldap_set_option(
                            $this->con, LDAP_OPT_REFERRALS,
                            $this->getConf('referrals')
                        )
                        ) {
                            msg('Setting LDAP referrals to off failed', -1);
                            $this->_debug('LDAP referal set: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
                        }
                    }
                }
            }

            //set deref mode
            if($this->getConf('deref')) {
                if(!@ldap_set_option($this->con, LDAP_OPT_DEREF, $this->getConf('deref'))) {
                    msg('Setting LDAP Deref mode '.$this->getConf('deref').' failed', -1);
                    $this->_debug('LDAP deref set: '.htmlspecialchars(ldap_error($this->con)), 0, __LINE__, __FILE__);
                }
            }
            /* As of PHP 5.3.0 we can set timeout to speedup skipping of invalid servers */
            if(defined('LDAP_OPT_NETWORK_TIMEOUT')) {
                ldap_set_option($this->con, LDAP_OPT_NETWORK_TIMEOUT, 1);
            }
            $bound = @ldap_bind($this->con);
            if($bound) {
                break;
            }
        }

        if(!$bound) {
            msg("LDAP: couldn't connect to LDAP server", -1);
            return false;
        }

        $this->cando['getUsers'] = true;
        return true;
    }

    /**
     * Wraps around ldap_search, ldap_list or ldap_read depending on $scope
     *
     * @author Andreas Gohr <andi@splitbrain.org>
     * @param resource $link_identifier
     * @param string   $base_dn
     * @param string   $filter
     * @param string   $scope can be 'base', 'one' or 'sub'
     * @param null     $attributes
     * @param int      $attrsonly
     * @param int      $sizelimit
     * @param int      $timelimit
     * @param int      $deref
     * @return resource
     */
    protected function _ldapsearch($link_identifier, $base_dn, $filter, $scope = 'sub', $attributes = null,
                         $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER) {
        if(is_null($attributes)) $attributes = array();

        if($scope == 'base') {
            return @ldap_read(
                $link_identifier, $base_dn, $filter, $attributes,
                $attrsonly, $sizelimit, $timelimit, $deref
            );
        } elseif($scope == 'one') {
            return @ldap_list(
                $link_identifier, $base_dn, $filter, $attributes,
                $attrsonly, $sizelimit, $timelimit, $deref
            );
        } else {
            return @ldap_search(
                $link_identifier, $base_dn, $filter, $attributes,
                $attrsonly, $sizelimit, $timelimit, $deref
            );
        }
    }

    /**
     * Wrapper around msg() but outputs only when debug is enabled
     *
     * @param string $message
     * @param int    $err
     * @param int    $line
     * @param string $file
     * @return void
     */
    protected function _debug($message, $err, $line, $file) {
        if(!$this->getConf('debug')) return;
        msg($message, $err, $line, $file);
    }
}

//Setup VIM: ex: et ts=4 enc=utf-8 :
