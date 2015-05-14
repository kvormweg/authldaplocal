<?php

/**
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * 
 * @author Matthias Schulte <dokuwiki@lupo49.de>
 * @author christian studer <cstuder@existenz.ch>
 */
$lang['server']                = 'Adresse zum LDAP-Server. Entweder als Hostname (<code>localhost</code>) oder als FQDN (<code>ldap://server.tld:389</code>).';
$lang['port']                  = 'Port des LDAP-Servers, falls kein Port angegeben wurde.';
$lang['usertree']              = 'Zweig, in dem die die Benutzeraccounts gespeichert sind. Zum Beispiel: <code>ou=People, dc=server, dc=tld</code>.';
$lang['grouptree']             = 'Zweig, in dem die Benutzergruppen gespeichert sind. Zum Beispiel:  <code>ou=Group, dc=server, dc=tld</code>.';
$lang['userfilter']            = 'LDAP-Filter, um die Benutzeraccounts zu suchen. Zum Beispiel: <code>(&amp;(uid=%{user})(objectClass=posixAccount))</code>.';
$lang['groupfilter']           = 'LDAP-Filter, um die Benutzergruppen zu suchen. Zum Beispiel:  <code>(&amp;(objectClass=posixGroup)(|(gidNumber=%{gid})(memberUID=%{user})))</code>.';
$lang['version']               = 'Zu verwendende Protokollversion von LDAP.';
$lang['starttls']              = 'Verbindung über TLS aufbauen?';
$lang['binddn']                = 'DN eines optionalen Benutzers, wenn der anonyme Zugriff nicht ausreichend ist. Zum Beispiel: <code>cn=admin, dc=my, dc=home</code>.';
$lang['bindpw']                = 'Passwort des angegebenen Benutzers.';
$lang['userscope']             = 'Die Suchweite nach Benutzeraccounts.';
$lang['groupscope']            = 'Die Suchweite nach Benutzergruppen.';
$lang['groupkey']              = 'Gruppieren der Benutzeraccounts anhand eines beliebigen Benutzerattributes z. B. Telefonnummer oder Abteilung, anstelle der Standard-Gruppen).';
$lang['debug']                 = 'Debug-Informationen beim Auftreten von Fehlern anzeigen?';
