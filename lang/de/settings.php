<?php
$lang['server']      = 'Ihr LDAP Server. Entweder der Rechnername (<code>localhost</code>) oder eine volle URL (<code>ldap://server.tld:389</code>)';
$lang['port']        = 'LDAP Server Port, wenn oben keine volle URL angeben wurde';
$lang['usertree']    = 'Basis-DN der Benutzer. Z.B. <code>ou=People, dc=server, dc=tld</code>';
$lang['grouptree']   = 'Basis-DN der Gruppen. Z.B. <code>ou=Group, dc=server, dc=tld</code>';
$lang['userfilter']  = 'LDAP Filter für die Suche nach Benutzern. Z.B. <code>(&amp;(uid=%{user})(objectClass=posixAccount))</code>';
$lang['groupfilter'] = 'LDAP Filter für die Suche nach Gruppen. Z.B. <code>(&amp;(objectClass=posixGroup)(|(gidNumber=%{gid})(memberUID=%{user})))</code>';
$lang['version']     = 'LDAP Protokoll Version. Muss u.U. auf <code>3</code> gesetzt werden';
$lang['starttls']    = 'TLS Verbindung benutzen?';
$lang['debug']       = 'Debug Informationen ausgeben (auf Produktionsservern unbedingt abschalten)';
