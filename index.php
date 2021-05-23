<?php
//{"lang":"","fm_root":"","timezone":"","date_format":"Y\/m\/d H:i","auth_pass":"d41d8cd98f00b204e9800998ecf8427e","error_reporting":1}
/*-------------------------------------------------
| PHP FILE MANAGER
+--------------------------------------------------
| phpFileManager 1.7.9
| By Fabricio Seger Kolling
| Copyright (c) 2004-2021 Fabrício Seger Kolling
| E-mail: dulldusk@gmail.com
| URL: http://phpfm.sf.net
| Last Changed: 2021-02-09
+--------------------------------------------------
| It is the AUTHOR'S REQUEST that you keep intact the above header information
| and notify it only if you conceive any BUGFIXES or IMPROVEMENTS to this program.
+--------------------------------------------------
| LICENSE
+--------------------------------------------------
| Licensed under the terms of any of the following licenses at your choice:
| - GNU General Public License Version 2 or later (the "GPL");
| - GNU Lesser General Public License Version 2.1 or later (the "LGPL");
| - Mozilla Public License Version 1.1 or later (the "MPL").
| You are not required to, but if you want to explicitly declare the license
| you have chosen to be bound to when using, reproducing, modifying and
| distributing this software, just include a text file titled "LICENSE" in your version
| of this software, indicating your license choice. In any case, your choice will not
| restrict any recipient of your version of this software to use, reproduce, modify
| and distribute this software under any of the above licenses.
+--------------------------------------------------
| CONFIGURATION AND INSTALATION NOTES
+--------------------------------------------------
| This program does not include any instalation or configuration
| notes because it simply does not require them.
| Just throw this file anywhere in your webserver and enjoy !!
+--------------------------------------------------*/
// +--------------------------------------------------
// | Config
// +--------------------------------------------------
$version = '1.7.9';
$charset = 'UTF-8';
$debug_mode = false;
$max_php_recursion = 200;
$resolve_ids = 0;
$quota_mb = 0;
$upload_ext_filter = array();
$download_ext_filter = array();
$cookie_cache_time = 60*60*24*30; // 30 Days
$fm_color = array();
$fm_color['Bg'] = "EEEEEE";
$fm_color['Text'] = "000000";
$fm_color['Link'] = "0A77F7";
$fm_color['Entry'] = "FFFFFF";
$fm_color['Over'] = "C0EBFD";
$fm_color['Mark'] = "A7D2E4";
// https://pt.wikipedia.org/wiki/Lista_de_portas_dos_protocolos_TCP_e_UDP
$services = array();
//$services['13:UDP'] = "DAYTIME";
$services['21'] = "FTP";
$services['22'] = "SSH";
$services['23'] = "TELNET";
$services['25'] = "SMTP";
//$services['53:UDP'] = "DNS";
//$services['67:UDP'] = "DHCP";
//$services['68:UDP'] = "BOOTP";
//$services['69:UDP'] = "TFTP";
$services['80'] = "HTTPD";
$services['110'] = "POP3";
//$services['123:UDP'] = "NTP";
//$services['137:UDP'] = "NETBIOS-NS";
//$services['138:UDP'] = "NETBIOS-DATA";
$services['139'] = "NETBIOS-SESSION";
$services['143'] = "IMAP";
$services['161'] = "SNMP";
$services['389'] = "LDAP";
$services['445'] = "SMB-AD";
//$services['445:UDP'] = "SMB-FS";
$services['465'] = "SMTPS-SSL";
$services['512'] = "RPC";
$services['514'] = "RSH";
//$services['514:UDP'] = "SYSLOG";
$services['515'] = "LPD-PRINTER";
//$services['520:UDP'] = "RIP-ROUTER";
$services['530'] = "RPC";
$services['540'] = "UUCP";
$services['544'] = "KSHELL";
$services['556'] = "REMOTE-FS";
$services['587'] = "SMTPS-TLS";
$services['593'] = "HTTP-RPC";
$services['631'] = "IPP";
$services['636'] = "LDAPS";
$services['993'] = "IMAPS";
$services['995'] = "POP3S";
$services['990'] = "FTPS";
$services['992'] = "TELNETS";
$services['1433'] = "MSSQL";
$services['1521'] = "ORACLE";
$services['3306'] = "MYSQL/MARIADB";
$services['3389'] = "RDESKTOP";
$services['5900'] = "VNC";
$services['7778'] = "KLOXO-ADMIN";
$services['8080'] = "HTTPD-ALT";
$services['8200'] = "GOTOMYPC";
$services['10000'] = "VIRTUALMIN-ADMIN";
$services['27017'] = "MONGODB";
$services['50000'] = "DB2";
// +--------------------------------------------------
// | Header and Globals
// +--------------------------------------------------
@ob_start(); // For ChromePhp Debug and JSONRPC to Work!
function getmicrotime(){
   list($usec, $sec) = explode(" ", microtime());
   return ((float)$usec + (float)$sec);
}
$script_init_time = getmicrotime();
function log_script_time(){
    global $script_init_time;
    fb_log(number_format((getmicrotime()-$script_init_time), 3, '.', '')."s");
}
$is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
$max_php_recursion_counter = 0;
if(!isset($_SERVER['PATH_INFO']) && isset($_SERVER['ORIG_PATH_INFO'])) {
    $_SERVER['PATH_INFO'] = $_SERVER['ORIG_PATH_INFO'];
}
function fix_directory_separator($str){
    global $is_windows;
    if ($is_windows) $str = str_replace('/',DIRECTORY_SEPARATOR,$str);
    else $str = str_replace('\\',DIRECTORY_SEPARATOR,$str);
    return $str;
}
if(!isset($_SERVER['DOCUMENT_ROOT'])) {
    if (isset($_SERVER['SCRIPT_FILENAME'])) $path = $_SERVER['SCRIPT_FILENAME'];
    elseif (isset($_SERVER['PATH_TRANSLATED'])) $path = str_replace('\\\\', '\\', $_SERVER['PATH_TRANSLATED']);
    $_SERVER['DOCUMENT_ROOT'] = substr($path, 0, 0-strlen($_SERVER['PHP_SELF']));
}
$_SERVER['DOCUMENT_ROOT'] = fix_directory_separator($_SERVER['DOCUMENT_ROOT']);
if (!function_exists('get_magic_quotes_gpc') || get_magic_quotes_gpc()) {
    function stripslashes_deep($value){
        return is_array($value)? array_map('stripslashes_deep', $value):$value;
    }
    $_POST = array_map('stripslashes_deep', $_POST);
    $_GET = array_map('stripslashes_deep', $_GET);
    $_COOKIE = array_map('stripslashes_deep', $_COOKIE);
}
// Register Globals (its an old script..)
$blockKeys = array('_SERVER','_SESSION','_GET','_POST','_COOKIE');
foreach ($_GET as $key => $val) if (array_search($key,$blockKeys) === false) $$key=$val;
foreach ($_POST as $key => $val) if (array_search($key,$blockKeys) === false) $$key=$val;
foreach ($_COOKIE as $key => $val) if (array_search($key,$blockKeys) === false && $key != 'fm_current_dir' && $key != 'ace_wrap') $$key=$val;
// PHP_VERSION_ID is available as of PHP 5.2.7, if our version is lower than that, then emulate it
if (!defined('PHP_VERSION_ID')) {
    $php_version = explode('.', PHP_VERSION);
    define('PHP_VERSION_ID', ($php_version[0] * 10000 + $php_version[1] * 100 + $php_version[2]));
    if (PHP_VERSION_ID < 50207) {
        define('PHP_MAJOR_VERSION',   $php_version[0]);
        define('PHP_MINOR_VERSION',   $php_version[1]);
        define('PHP_RELEASE_VERSION', $php_version[2]);
    }
}
// Server Vars
function curl_server_online_check(){
    if (function_exists('curl_init')){
        @$ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "http://phpfm.sf.net");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        @curl_exec($ch);
        $errnum = curl_errno($ch);
        @curl_close($ch);
    }
    return ($errnum == "0");
}
function socket_get_lan_ip($dest='64.0.0.0', $port=80) {
    $addr = '';
    if (function_exists('socket_create')){
        $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        socket_connect($socket, $dest, $port);
        socket_getsockname($socket, $addr, $port);
        socket_close($socket);
    }
    return $addr;
}
function get_client_ip() {
    $ipaddress = '';
    if ($_SERVER['HTTP_CLIENT_IP']) $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
    else if($_SERVER['HTTP_X_FORWARDED_FOR']) $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
    else if($_SERVER['HTTP_X_FORWARDED']) $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
    else if($_SERVER['HTTP_FORWARDED_FOR']) $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
    else if($_SERVER['HTTP_FORWARDED']) $ipaddress = $_SERVER['HTTP_FORWARDED'];
    else if($_SERVER['HTTP_X_REAL_IP']) $ipaddress = $_SERVER['HTTP_X_REAL_IP'];
    else if($_SERVER['REMOTE_ADDR']) $ipaddress = $_SERVER['REMOTE_ADDR'];
    // proxy transparente não esconde o IP local, colocando ele após o IP da rede, separado por vírgula
    if (strpos($ipaddress, ',') !== false) {
        $ips = explode(',', $ipaddress);
        $ipaddress = trim($ips[0]);
    }
    if ($ipaddress == '::1' || $ipaddress == '127.0.0.1') $ipaddress = 'localhost';
    return $ipaddress;
}
$ip = @get_client_ip();
$lan_ip = @socket_get_lan_ip();
function getServerURL() {
    $url = (lowercase($_SERVER['HTTPS']) == "on")?"https://":"http://";
    if (strlen($_SERVER['SERVER_NAME'])) $url .= $_SERVER['SERVER_NAME'];
    elseif (strlen($_SERVER['HTTP_HOST'])) $url .= $_SERVER['HTTP_HOST'];
    if ($_SERVER['SERVER_PORT'] != "80" && $_SERVER['SERVER_PORT'] != "443") $url .= ":".$_SERVER['SERVER_PORT'];
    return $url;
}
function getCompleteURL() {
    return getServerURL().$_SERVER['REQUEST_URI'];
}
$url = @getCompleteURL();
$url_info = parse_url($url);
$doc_root = rtrim($_SERVER['DOCUMENT_ROOT'],DIRECTORY_SEPARATOR); // ex: 'C:/htdocs'
$url_root = rtrim(@getServerURL(),'/'); // ex. 'http://www.site.com'
$fm_file = __FILE__;
$fm_url = $url_root.$_SERVER['PHP_SELF'];
$fm_path_info = pathinfo($fm_file);
$open_basedir_ini = trim(@ini_get("open_basedir"));
$open_basedirs = array();
if (strlen($open_basedir_ini)) {
    $dirs = array($open_basedir_ini);
    if ($is_windows) {
        if (strpos($open_basedir_ini,';') !== false) {
            $dirs = explode(';',$open_basedir_ini);
        }
        $dirs = array_map('ucfirst',$dirs);
    } else {
        if (strpos($open_basedir_ini,':') !== false) {
            $dirs = explode(':',$open_basedir_ini);
        }
    }
    foreach ($dirs as $dir) {
        $dir = rtrim($dir,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR; // fm_root must have trailing slash
        if (is_dir($dir)) $open_basedirs[] = $dir;
    }
}
$sys_lang = strtolower(substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2));
if (!function_exists('mb_strtolower') || !function_exists('mb_strtoupper')) {
    die('PHP File Manager<br>Error: Please enable "mbstring" php module.<br>http://php.net/manual/en/book.mbstring.php');
}
// +--------------------------------------------------
// | Config Class
// +--------------------------------------------------
function object_to_array( $var ) {
    if( !is_object( $var ) && !is_array( $var ) ) {
        return $var;
    }
    if( is_object( $var ) ) {
        $var = get_object_vars( $var );
    }
    return array_map( 'object_to_array', $var );
}
function array_to_object( $var ) {
    if( !is_object( $var ) && !is_array( $var ) ) {
        return $var;
    }
    $obj = new stdClass();
    foreach ($var as $key => $value) {
        if (strlen($key)) $obj->{$key} = array_to_object( $value );
    }
    return $obj;
}
class config {
    var $data;
    function __construct(){
        $this->data = array(
            'lang'=>'',
            'fm_root'=>'',
            'timezone'=>'',
            'date_format'=>'Y/m/d H:i',
            'auth_pass'=>md5(''),
            'error_reporting'=>1
        );
    }
    function save(){
        global $fm_file;
        $config_string = "<?php".chr(13).chr(10)."//".json_encode($this->data).chr(13).chr(10);
        if (is_file($fm_file)){
            $lines = file($fm_file);
            $script_start_line = 1;
            if (strpos($lines[0],'<?php') === 0 && strpos($lines[1],'//{"') === 0) $script_start_line = 2;
            if ($fh = @fopen($fm_file, "w")){
                @fputs($fh,$config_string,strlen($config_string));
                for ($x=$script_start_line;$x<count($lines);$x++) @fputs($fh,$lines[$x],strlen($lines[$x]));
                @fclose($fh);
            }
        }
    }
    function load(){
        global $fm_file;
        $data = false;
        if (is_file($fm_file)){
            $fh = fopen($fm_file, 'r');
            $line1 = fgets($fh);
            $line2 = fgets($fh);
            $line3 = fgets($fh);
            fclose($fh);
            if (strpos($line1,'<?php') === 0 && strpos($line2,'//{"') === 0){
                $config_string = trim(substr($line2,2));
                if (strlen($config_string)) $data = object_to_array(json_decode($config_string));
            }
        }
        if (is_array($data) && count($data)) $this->data = $data;
        foreach ($this->data as $key => $val) $GLOBALS[$key] = $val;
    }
}
// +--------------------------------------------------
// | Config Load
// +--------------------------------------------------
$cfg = new config();
$cfg->load();
if (strlen($timezone)) @date_default_timezone_set($timezone);
//@setlocale(LC_CTYPE, 'C');
//@ini_set('default_charset', $charset);
@mb_internal_encoding($charset);
@ini_set('mbstring.substitute_character','none'); // That will strip invalid characters from UTF-8 strings
@ini_set("allow_url_fopen",1);
@error_reporting(0);
@ini_set("display_errors",0);
if ($error_reporting > 0){
    error_reporting(E_ERROR | E_PARSE | E_COMPILE_ERROR); @ini_set("display_errors",1);
}
function fb_log(){
    global $error_reporting;
    if ($error_reporting < 2) return;
    if (!class_exists('ChromePhp')) return;
    $arguments = func_get_args();
    if (func_num_args() > 1 && is_string($arguments[0])) {
        ChromePhp::log($arguments[0].': ',$arguments[1]);
    } else {
        ChromePhp::log($arguments[0]);
    }
}
if (!strlen($fm_current_root)) {
    if ($is_windows) {
        if (strpos($doc_root,":") !== false) $fm_current_root = ucfirst(substr($doc_root,0,strpos($doc_root,":")+1).DIRECTORY_SEPARATOR); // If doc_root has ":" take the drive letter
        $fm_current_root = ucfirst($doc_root.DIRECTORY_SEPARATOR);
    } else {
        $fm_current_root = "/"; // Linux default show root
    }
} else {
    if ($is_windows) $fm_current_root = ucfirst($fm_current_root);
}
if (strlen($fm_root)){
    $fm_current_root = $fm_root;
}
if (count($open_basedirs)){
    $fm_current_root_ok = false;
    foreach ($open_basedirs as $open_basedir) {
        if (strpos($fm_current_root,$open_basedir) !== false) {
            $fm_current_root_ok = true;
            break;
        }
    }
    if (!$fm_current_root_ok) {
        $fm_path = rtrim($fm_path_info['dirname'],DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
        foreach ($open_basedirs as $open_basedir) {
            if (strpos($fm_path,$open_basedir) !== false) {
                $fm_current_root = $open_basedir;
                $fm_current_root_ok = true;
                break;
            }
        }
    }
    if (!$fm_current_root_ok){
        $fm_current_root = $open_basedirs[0];
    }
}
if (!isset($fm_current_dir)){
    $fm_path = rtrim($fm_path_info['dirname'],DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
    if (strpos($fm_path,$fm_current_root) !== false) {
        $fm_current_dir = $fm_path;
    } else {
        $fm_current_dir = $fm_current_root;
    }
    if ($is_windows) $fm_current_dir = ucfirst($fm_current_dir);
    if (strlen($_COOKIE['fm_current_dir'])) {
        $fm_current_dir = $_COOKIE['fm_current_dir'];
    }
}
$fm_current_root = rtrim($fm_current_root,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
$fm_current_dir = rtrim($fm_current_dir,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
@chdir($fm_current_dir); // Note: So is_link(), is_file(), is_dir() and other functions work with relative paths too.
//fb_log('fm_root',$fm_root);
//fb_log('fm_current_root',$fm_current_root);
//fb_log('fm_current_dir',$fm_current_dir);
if (isset($set_resolve_ids)){
    $resolve_ids=intval($set_resolve_ids);
    setcookie("resolve_ids", $resolve_ids, time()+$cookie_cache_time, "/");
}
// +--------------------------------------------------
// | User/Group Functions
// +--------------------------------------------------
$passwd_array = false;
function get_user_name($uid) {
    global $is_windows, $passwd_array;
    if ($is_windows) return $uid;
    if ($passwd_array === false){
        @system_exec_cmd("cat /etc/passwd",$passwd_file);
        $passwd_array = explode(chr(10),$passwd_file);
    }
    foreach ($passwd_array as $line) {
        $mat = explode(":",$line);
        if ($mat[2] == $uid){
            return $mat[0];
        }
    }
    if (function_exists('posix_getpwuid')) {
        $info = posix_getpwuid($uid);
        return $info['name'];
    }
    return $uid;
}
$group_array = false;
function get_group_name($gid) {
    global $is_windows, $group_array;
    if ($is_windows) return $gid;
    if ($group_array === false){
        @system_exec_cmd("cat /etc/group",$group_file);
        $group_array = explode(chr(10),$group_file);
    }
    foreach ($group_array as $line) {
        $mat = explode(":",$line);
        if ($mat[2] == $gid){
            return $mat[0];
        }
    }
    if (function_exists('posix_getgrgid')) {
        $info = posix_getgrgid($gid);
        return $info['name'];
    }
    return $gid;
}
function get_user_groups($user_name) {
    global $is_windows, $group_array;
    if ($is_windows) return array();
    if ($group_array === false){
        @system_exec_cmd("cat /etc/group",$group_file);
        $group_array = explode(chr(10),$group_file);
    }
    $resul = array();
    $resul['ids'] = array();
    $resul['names'] = array();
    foreach ($group_array as $line) {
        $mat = explode(":",$line);
        $user_names = explode(",",$mat[3]);
        if (array_search($user_name,$user_names) !== false){
            $resul['ids'][] = $mat[2];
            $resul['names'][] = $mat[0];
        }
    }
    return $resul;
}
function is_rwx_phpfm($file,$what='r'){
    global $is_windows;
    // Note: You can only change the uid/euid of the current process when one of the two is currently set to 0 (root).
    // groupadd gteste
    // usermod -a -G gteste www-data
    // gpasswd -d www-data gteste
    if (!is_array($GLOBALS['script_info'])) {
        $GLOBALS['script_info'] = array();
        $GLOBALS['script_info']['sys_uname'] = function_exists('posix_uname') ? @posix_uname() : '';
        $GLOBALS['script_info']['sys_hostname'] = function_exists('gethostname') ? @gethostname() : '';
        if (!strlen($GLOBALS['script_info']['sys_hostname'])){
            $GLOBALS['script_info']['sys_hostname'] = @getenv('COMPUTERNAME');
        }
        $GLOBALS['script_info']['script_user_id'] = function_exists('posix_getuid') ? @posix_getuid() : '';
        $GLOBALS['script_info']['script_user_name'] = $GLOBALS['script_info']['script_user_id'];
        $GLOBALS['script_info']['script_user_home'] = '';
        $GLOBALS['script_info']['script_user_shell'] = '';
        $GLOBALS['script_info']['script_user_group_id'] = '';
        $GLOBALS['script_info']['script_user_group_name'] = '';
        $GLOBALS['script_info']['script_user_group_ids'] = array();
        $GLOBALS['script_info']['script_user_group_names'] = array();
        $GLOBALS['script_info']['script_group_id'] = function_exists('posix_getgid') ? @posix_getgid() : '';
        $GLOBALS['script_info']['script_group_name'] = $GLOBALS['script_info']['script_group_id'];
        $GLOBALS['script_info']['script_group_members'] = '';
        if ($GLOBALS['script_info']['script_user_id'] && function_exists('posix_getpwuid')) {
            $info = posix_getpwuid($GLOBALS['script_info']['script_user_id']);
            $GLOBALS['script_info']['script_user_home'] = $info['dir'];
            $GLOBALS['script_info']['script_user_shell'] = $info['shell'];
            $GLOBALS['script_info']['script_user_name'] = $info['name'];
            $GLOBALS['script_info']['script_user_group_id'] = $info['gid'];
            if (function_exists('posix_getgrgid')) {
                $info = posix_getgrgid($GLOBALS['script_info']['script_user_group_id']);
                $GLOBALS['script_info']['script_user_group_name'] = $info['name'];
            }
            $info = get_user_groups($GLOBALS['script_info']['script_user_name']);
            $GLOBALS['script_info']['script_user_group_ids'] = $info['ids'];
            $GLOBALS['script_info']['script_user_group_names'] = $info['names'];
            array_unshift($GLOBALS['script_info']['script_user_group_ids'], $GLOBALS['script_info']['script_user_group_id']);
            array_unshift($GLOBALS['script_info']['script_user_group_names'], $GLOBALS['script_info']['script_user_group_name']);

        }
        if (!strlen($GLOBALS['script_info']['script_user_name'])) {
            if (!system_exec_cmd('whoami',$GLOBALS['script_info']['script_user_name'])) {
                $GLOBALS['script_info']['script_user_name'] = '';
            }
        }
        if (!strlen($GLOBALS['script_info']['script_user_name']) && function_exists('get_current_user')) {
            $GLOBALS['script_info']['script_user_name'] = get_current_user();
        }
        if (!strlen($GLOBALS['script_info']['script_user_name'])){
            $GLOBALS['script_info']['script_user_name'] = @getenv('USERNAME') ? : @getenv('USER');
        }
        if ($is_windows && strpos($GLOBALS['script_info']['script_user_name'],'\\') !== false){
            $GLOBALS['script_info']['script_user_name'] = ucfirst(substr($GLOBALS['script_info']['script_user_name'],strpos($GLOBALS['script_info']['script_user_name'],'\\')+1));
        }
        if (function_exists('posix_getgrgid')) {
            $info = posix_getgrgid($GLOBALS['script_info']['script_group_id']);
            $GLOBALS['script_info']['script_group_name'] = $info['name'];
            $GLOBALS['script_info']['script_group_members'] = $info['members'];
        }
        fb_log($GLOBALS['script_info']);
    }
    $file_info = array();
    $file_info['name'] = $file;
    $file_stat = stat($file);
    $file_info['nlinks'] = $file_stat['nlink'];
    $file_info['perms'] = fileperms($file);
    $file_info['owner'] = fileowner($file);
    $file_info['group'] = filegroup($file);
    $file_info['is_owner_readable'] = ($file_info['perms'] & 0x0100);
    $file_info['is_group_readable'] = ($file_info['perms'] & 0x0020);
    $file_info['is_world_readable'] = ($file_info['perms'] & 0x0004);
    $file_info['is_readable'] = false;
    if ($file_info['is_world_readable']) {
        $file_info['is_readable'] = true;
    }
    if ($file_info['is_group_readable']) {
        foreach ($GLOBALS['script_info']['script_user_group_ids'] as $gid) {
            if ($file_info['group'] == $gid) {
                $file_info['is_readable'] = true;
                break;
            }
        }
    }
    if ($file_info['is_owner_readable'] && $file_info['owner'] == $GLOBALS['script_info']['script_user_id']) {
        $file_info['is_readable'] = true;
    }
    $file_info['is_owner_writable'] = ($file_info['perms'] & 0x0080);
    $file_info['is_group_writable'] = ($file_info['perms'] & 0x0010);
    $file_info['is_world_writable'] = ($file_info['perms'] & 0x0002);
    $file_info['is_writable'] = false;
    if ($file_info['is_world_writable']) {
        $file_info['is_writable'] = true;
    }
    if ($file_info['is_group_writable']) {
        foreach ($GLOBALS['script_info']['script_user_group_ids'] as $gid) {
            if ($file_info['group'] == $gid) {
                $file_info['is_writable'] = true;
                break;
            }
        }
    }
    if ($file_info['is_owner_writable'] && $file_info['owner'] == $GLOBALS['script_info']['script_user_id']) {
        $file_info['is_writable'] = true;
    }
    $file_info['is_owner_executable'] = ($file_info['perms'] & 0x0040);
    $file_info['is_group_executable'] = ($file_info['perms'] & 0x0400);
    $file_info['is_world_executable'] = ($file_info['perms'] & 0x0001);
    $file_info['is_executable'] = false;
    if ($file_info['is_world_executable']) {
        $file_info['is_executable'] = true;
    }
    if ($file_info['is_group_executable']) {
        foreach ($GLOBALS['script_info']['script_user_group_ids'] as $gid) {
            if ($file_info['group'] == $gid) {
                $file_info['is_executable'] = true;
                break;
            }
        }
    }
    if ($file_info['is_owner_executable'] && $file_info['owner'] == $GLOBALS['script_info']['script_user_id']) {
        $file_info['is_executable'] = true;
    }
    if ($what == 'r') return $file_info['is_readable'];
    if ($what == 'w') return $file_info['is_writable'];
    if ($what == 'x') return $file_info['is_executable'];
    return false;
}
function is_readable_phpfm($file){
    return is_rwx_phpfm($file,'r');
}
function is_writable_phpfm($file){
    return is_rwx_phpfm($file,'w');
}
function is_executable_phpfm($file){
    return is_rwx_phpfm($file,'x');
}
// +--------------------------------------------------
// | File Manager Actions
// +--------------------------------------------------
if ($action != '99') {
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
    header("Content-Type: text/html; charset=".$charset);
}
if ($auth_pass == md5('') || $loggedon==$auth_pass){
    switch ($frame){
        case 1: break; // Empty Frame
        case 2: frame2(); break;
        case 3: frame3(); break;
        default:
            switch($action){
                case 1: logout(); break;
                case 2: config_form(); break;
                case 3: download(); break;
                case 4: view_form(); break;
                case 5: server_info_form(); break;
                case 6: break;
                case 7: edit_file_form(); break;
                case 8: chmod_form(); break;
                case 9: shell_form(); break;
                case 10: upload_form(); break;
                case 11: system_exec_file(); break;
                case 12: portscan_form(); break;
                case 14: dir_list_update_total_size(); break;
                case 99: get_base64_file(); break;
                default:
                    if ($noscript) login_form();
                    else frameset();
            }
    }
} elseif (strlen($pass)) {
    login();
} else {
    login_form();
}
// +--------------------------------------------------
// | File System
// +--------------------------------------------------
function symlink_phpfm($target,$link){
    global $is_windows;
    $ok = false;
    if (!$is_windows){ // symlink() function not available on windows
        if (function_exists('symlink')) {
            $ok = symlink($target,$link);
        } else {
            $GLOBALS['dir_list_warn_message'] .= 'Error: php symlink() function is disabled.<br>';
        }
    }
    if (!$ok){
        $cmd = '';
        if ($is_windows){
            //$runas = 'runas /noprofile /user:Administrator ';
            if (is_dir($target)) $cmd = $runas.'mklink /D '.escapeshellarg($link).' '.escapeshellarg($target);
            else $cmd = $runas.'mklink '.escapeshellarg($link).' '.escapeshellarg($target);
        } else {
            $cmd = 'ln -s '.escapeshellarg($target).' '.escapeshellarg($link);
        }
        $output = '';
        $ok = system_exec_cmd($cmd,$output);
        if (!$ok) {
            $GLOBALS['dir_list_warn_message'] .= 'CMD: '.$cmd.'<br>';
            $GLOBALS['dir_list_warn_message'] .= $output.'<br>';
        }
        // link() function is available on windows (Vista, Server 2008 or greater)
        // if everything failed, try to create a hardlink to the file instead
        if (!$ok && !is_dir($target) && $is_windows) {
            if (function_exists('link')) {
                $ok = link($target,$link);
            } else {
                $GLOBALS['dir_list_warn_message'] .= 'Error: php link() function is disabled.<br>';
            }
        }
    }
    return $ok;
}
function link_phpfm($target,$link){
    global $is_windows;
    if (is_dir($target)) {
        // hardlinks to directories are not allowed, create symlink instead
        // https://askubuntu.com/questions/210741/why-are-hard-links-not-allowed-for-directories
        return symlink_phpfm($target,$link);
    }
    $ok = false;
    if (function_exists('link')) { // link() function is available on windows (Vista, Server 2008 or greater)
        $ok = link($target,$link);
    } else {
        $GLOBALS['dir_list_warn_message'] .= 'Error: php link() function is disabled.<br>';
    }
    if (!$ok){
        $cmd = '';
        if ($is_windows){
            //$runas = 'runas /noprofile /user:Administrator ';
            $cmd = $runas.'mklink /H '.escapeshellarg($link).' '.escapeshellarg($target);
        } else {
            $cmd = 'ln '.escapeshellarg($target).' '.escapeshellarg($link);
        }
        $output = '';
        $ok = system_exec_cmd($cmd,$output);
        if (!$ok) {
            $GLOBALS['dir_list_warn_message'] .= 'CMD: '.$cmd.'<br>';
            $GLOBALS['dir_list_warn_message'] .= $output.'<br>';
        }
    }
    return $ok;
}
function phpfm_get_total_size($path){
    $total_size = false;
    $dir_cookiename = 'dir_'.hash('crc32',fix_cookie_name($path),FALSE);
    if (strlen($_COOKIE[$dir_cookiename])) {
        $total_size = $_COOKIE[$dir_cookiename];
        if ($total_size != 'error'){
            return intval($total_size);
        }
        return $total_size;
    }
    $total_size = system_get_total_size($path);
    if ($total_size !== false) {
        setcookie((string)$dir_cookiename, (string)$total_size, 0 , "/");
    }
    return $total_size;
}
function dir_list_update_total_size(){
    global $fm_current_dir, $dirname;
    $path = rtrim($fm_current_dir,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$dirname;
    $total_size = system_get_total_size($path);
    if ($total_size === false) {
        $total_size = php_get_total_size($path);
    }
    if ($total_size === false) {
        $total_size = 'error';
    }
    $dir_cookiename = 'dir_'.hash('crc32',fix_cookie_name($fm_current_dir.$dirname),FALSE);
    setcookie((string)$dir_cookiename, (string)$total_size, 0 , "/");
    echo $total_size;
    die();
}
// INFO: php filesize() returns ZERO for files over 4Gb
function phpfm_filesize($file){
    $filesize = intval(filesize($file));
    if ($filesize <= 0) $filesize = system_get_total_size($file);
    return $filesize;
}
function system_get_total_size($path){
    global $is_windows;
    $total_size = false;
    if ($is_windows){
        if (class_exists('COM')) {
            $fsobj = new COM('Scripting.FileSystemObject');
            if (is_object($fsobj)) {
                try {
                    if (is_dir($path)) $ref = $fsobj->GetFolder($path);
                    else $ref = $fsobj->GetFile($path);
                    if (is_object($ref)) {
                        $total_size = floatval($ref->size);
                        $fsobj = null;
                        unset($fsobj);
                    }
                } catch (Exception $e) {
                }
            }
        }
        if ($total_size === false) {
            if (is_file($path)){
                $output = '';
                if (system_exec_cmd('for %I in ('.$path.') do @echo %~zI',$output)){
                    $total_size = floatval($output);
                }
            }
        }
    } else {
        $output = '';
        if (system_exec_cmd('du -sb '.$path,$output)){
            $total_size = floatval(substr($output,0,strpos($output,"\t")));
        }
    }
    if ($total_size === false) fb_log('system_get_total_size("'.$path.'") = FALSE');
    else fb_log('system_get_total_size("'.$path.'") = '.format_size($total_size));
    return $total_size;
}
function php_get_total_size($path) {
    global $debug_mode,$max_php_recursion_counter;
    $max_php_recursion_counter = 0;
    $total_size = php_get_total_size_execute($path);
    if ($total_size === false) fb_log('php_get_total_size("'.$path.'") = false'.' (recursion: '.$max_php_recursion_counter.')');
    else fb_log('php_get_total_size("'.$path.'") = '.format_size($total_size).' (recursion: '.$max_php_recursion_counter.')');
    return $total_size;
}
function php_get_total_size_execute($path) {
    global $debug_mode,$max_php_recursion,$max_php_recursion_counter;
    fb_log('php_get_total_size_execute',$path);
    if ($debug_mode) return 0;
    $total_size = 0;
    if (is_dir($path)) {
        $entry_list = scandir(fs_encode($path));
        foreach ($entry_list as $entry) {
            if ($entry == "." || $entry == "..") continue;
            if (is_dir($path.DIRECTORY_SEPARATOR.$entry)) {
                if ($max_php_recursion_counter >= $max_php_recursion) {
                    return false;
                }
                $max_php_recursion_counter++;
                $size = php_get_total_size_execute($path.DIRECTORY_SEPARATOR.$entry);
                if ($size === false) {
                    return false;
                }
                $total_size += $size;
            } else {
                $total_size += phpfm_filesize($path.DIRECTORY_SEPARATOR.$entry);
            }
        }
    } else {
        $total_size = phpfm_filesize($path);
    }
    return $total_size;
}
function php_shred($filepath) {
    // Based on https://github.com/DanielRuf/secure-shred (MIT license)
    // https://www.aldeid.com/wiki/Secure-delete-files
    // TODO: test write each pass, and rename the file before delete.
    try {
        // clear stat cache to avoid falsely reported file status
        // use $filepath parameter to possibly improve performance
        clearstatcache(true, $filepath);
        if (is_file($filepath) && is_readable($filepath) && is_writable($filepath)) {
            $read = new \SplFileObject($filepath, 'r');
            $write = new \SplFileObject($filepath, 'r+');
            while (!$read->eof()) {
                $line_pos = $read->ftell();
                $line_content = $read->fgets();
                $line_length = strlen($line_content);
                if ($line_length === 0) continue;
                for ($n=0;$n<3;$n++) { // does 3 overwrites per line
                    $write->fseek($line_pos);
                    $write->fwrite(random_bytes($line_length));
                    $write->fflush();
                }
            }
            $write->ftruncate(0);
            $read = $write = null;
            return unlink($filepath);
        }
    } catch(\Exception $e) {
        fb_log($e->getMessage().' ('.$e->getCode().')');
    }
    return false;
}
function total_delete($path,$followlinks=false,$checkhardlinks=true) {
    global $debug_mode;
    fb_log('total_delete',$path);
    if ($debug_mode) return;
    // TODO: $checkhardlinks will not allow to delete anything that has other links on the system, using stat() to avoid creating brokenlinks. Add a warning and complete action;.
    if (file_exists($path)) {
        @chmod($path,0755);
        if (is_dir($path)) {
            $entry_list = scandir(fs_encode($path));
            foreach ($entry_list as $entry) {
                if ($entry == "." || $entry == "..") continue;
                if ($followlinks == false && is_link(rtrim($path,DIRECTORY_SEPARATOR))) continue;
                total_delete($path.DIRECTORY_SEPARATOR.$entry,$followlinks,$checkhardlinks);
            }
            if (is_link($path)) @unlink($path);
            else @rmdir($path);
        } else {
            @unlink($path);
        }
    } elseif (is_link($path)) {
        @unlink($path); // Broken links must be removed
    }
}
function total_copy($orig,$dest,$copylinks=true,$followlinks=false) {
    global $debug_mode;
    fb_log('total_copy',$orig.' => '.$dest);
    if ($debug_mode) return;
    $ok = true;
    if (file_exists($orig) || is_link($orig)) {
        if ($copylinks == true && is_link($orig)){
            $ok = link_phpfm(readlink($orig), $dest);
            if (!$ok) $ok = link_phpfm($orig, $dest); // Allow copy of broken links, but rather copy the link to the target, as the link was.
        } elseif (is_dir($orig)) {
            $ok = mkdir(fs_encode($dest),0755);
            if ($ok) {
                $entry_list = scandir(fs_encode($orig));
                foreach ($entry_list as $entry) {
                    if ($entry == "." || $entry == "..") continue;
                    if ($followlinks == false && is_link(rtrim($orig,DIRECTORY_SEPARATOR))){
                        $ok = link_phpfm(readlink($orig.DIRECTORY_SEPARATOR.$entry), $dest.DIRECTORY_SEPARATOR.$entry);
                    } else {
                        $ok = total_copy($orig.DIRECTORY_SEPARATOR.$entry, $dest.DIRECTORY_SEPARATOR.$entry, $copylinks, $followlinks);
                    }
                    if (!$ok) break;
                }
            }
        } else {
            $ok = copy((string)$orig,(string)$dest);
        }
    }
    return $ok;
}
function total_move($orig,$dest) {
    global $debug_mode;
    fb_log('total_move',$orig.' => '.$dest);
    if ($debug_mode) return;
    // Just why doesn't it has a MOVE alias?!
    return rename((string)$orig,(string)$dest);
}
function download(){
    global $fm_current_dir,$filename,$debug_mode;
    $file = $fm_current_dir.$filename;
    fb_log('download',$file);
    if ($debug_mode) return;
    if(file_exists($file)){
        $is_denied = false;
        foreach($download_ext_filter as $key=>$ext){
            if (eregi($ext,$filename)){
                $is_denied = true;
                break;
            }
        }
        if (!$is_denied){
            $size = phpfm_filesize($file);
            header("Content-Type: application/save");
            header("Content-Length: $size");
            header("Content-Disposition: attachment; filename=\"".$filename."\"");
            header("Content-Transfer-Encoding: binary");
            if ($fh = fopen("$file", "rb")){
                ob_get_flush(); // Flush the output buffer and turn off output buffering, to allow direct download of big files
                fpassthru($fh);
                fclose($fh);
            } else alert(et('ReadDenied').": ".$file);
        } else alert(et('ReadDenied').": ".$file);
    } else alert(et('FileNotFound').": ".$file);
}
// Returns the full path of the current PHP executable
function linux_get_proc_name(){
    $output = '';
    $ok = system_exec_cmd("readlink -f /proc/".posix_getpid()."/exe",$output);
    if (!$ok) return false;
    return $output;
}
function system_exec_file(){
    global $fm_current_dir,$filename,$debug_mode,$is_windows;
    fb_log('system_exec_file',$filename);
    if ($debug_mode) return;
    header("Content-type: text/plain");
    $file = $fm_current_dir.$filename;
    if(file_exists($file)){
        if (!is_executable($file)) @chmod($file,0755);
        if (is_executable($file)) {
            $fm_current_dir = get_absolute_path($fm_current_dir);
            $cmd_line = '';
            if ($is_windows) {
                $cmd_line .= "cd /D ".$fm_current_dir." && ";
            } else {
                $cmd_line .= "cd ".$fm_current_dir." && ";
            }
            // TODO: verificar e usar interpretador correto
            // php -f /script.php
            // bash /script.sh
            // sh /script.sh
            // python /script.py
            // perl /script.pl
            $cmd_line .= $file;
            echo "# ".$cmd_line."\n";
            system_exec_cmd($cmd_line, $output);
            echo $output;
        } else echo('Error: '.$file.' is not executable...');
    } else echo(et('FileNotFound').": ".$file);
}
function save_upload($temp_file,$filename,$dir_dest) {
    global $upload_ext_filter,$debug_mode,$is_windows;
    fb_log('save_upload',$temp_file.' => '.$dir_dest.$filename);
    if ($debug_mode) return;
    $filename = remove_special_chars($filename);
    $file = $dir_dest.$filename;
    $filesize = phpfm_filesize($temp_file);
    $is_denied = false;
    $output = '';
    foreach($upload_ext_filter as $key=>$ext){
        if (eregi($ext,$filename)){
            $is_denied = true;
            break;
        }
    }
    if (!$is_denied){
        if (!check_limit($filesize)){
            if (file_exists($file)){
                if (unlink($file)){
                    if (copy($temp_file,$file)){
                        // https://stackoverflow.com/questions/23851821/setting-file-permissions-in-windows-with-php
                        if ($is_windows) system_exec_cmd('icacls "'.$file.'" /q /c /reset', $output);
                        else @chmod($file,0644);
                        $out = 6;
                    } else $out = 2;
                } else $out = 5;
            } else {
                if (copy($temp_file,$file)){
                    if ($is_windows) system_exec_cmd('icacls "'.$file.'" /q /c /reset', $output);
                    else @chmod($file,0644);
                    $out = 1;
                } else $out = 2;
            }
        } else $out = 3;
    } else $out = 4;
    return $out;
}
// Note: readlink() may return a relative path, with or without ./, and that is not good for is_file() is_dir() and broken link evaluation, because we can´t always chdir() to the link basepath.
function readlink_absolute_path($path){
    global $is_windows;
    if (!is_link($path)) return $path;
    $target = readlink($path);
    if (strpos($target,'.'.DIRECTORY_SEPARATOR) === 0){
        $target = substr($target,2); // remove ./
    }
    if (($is_windows && substr($target,2,1) != ':') || (!$is_windows && substr($target,0,1) != DIRECTORY_SEPARATOR)){ // check if does not start with C: or / = relative path
        $target = substr($path,0,strrpos($path,DIRECTORY_SEPARATOR)+1).$target; // complete the target using origin path
    }
    return $target;
}
// +--------------------------------------------------
// | Data Formating
// +--------------------------------------------------
function fix_cookie_name($str){
    $str = remove_acentos(trim($str));
    $str = str_replace('\\', '_', $str);
    $str = str_replace('/', '_', $str);
    $str = str_replace(':', '_', $str);
    $str = str_replace('*', '_', $str);
    $str = str_replace('?', '_', $str);
    $str = str_replace('"', '_', $str);
    $str = str_replace('<', '_', $str);
    $str = str_replace('>', '_', $str);
    $str = str_replace('|', '_', $str);
    $str = str_replace(' ', '_', $str);
    $str = str_strip($str,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-0123456789");
    $str = replace_double('_', $str);
    $str = trim($str,'_');
    return $str;
}
// http://www.ietf.org/rfc/rfc1738.txt
// The characters ";", "/", "?", ":", "@", "=" and "&" are the characters which may be reserved for special meaning within a scheme. No other characters may be reserved within a scheme.
// Thus, only alphanumerics, the special characters "$-_.+!*'(),", and reserved characters used for their reserved purposes may be used unencoded within a URL.
function fix_url($str) {
    // Remove acentos
    $str = remove_acentos($str);
    // Substitui caracteres reservados
    $str = str_replace(';', '-', $str);
    $str = str_replace('/', '-', $str);
    $str = str_replace('?', '-', $str);
    $str = str_replace(':', '-', $str);
    $str = str_replace('@', '-', $str);
    $str = str_replace('=', '-', $str);
    $str = str_replace('&', '-', $str);
    // Caracteres adicionais
    $str = str_replace('(', '-', $str);
    $str = str_replace(')', '-', $str);
    $str = str_replace('.', '-', $str);
    $str = str_replace('_', '-', $str);
    $str = str_replace(' ', '-', $str);
    // Apenas caracteres válidos
    $str = str_strip($str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890.-");
    $str = replace_double('-', $str);
    $str = trim($str,'-');
    return $str;
}
function fix_filename($str,$allowSpaces=false){ // no filesystem não podemos ter acentos
    $str = remove_acentos(trim($str));
    // Substitui caracteres reservados
    $str = str_replace('\\', '_', $str);
    $str = str_replace('/', '_', $str);
    $str = str_replace(':', '_', $str);
    $str = str_replace('*', '_', $str);
    $str = str_replace('?', '_', $str);
    $str = str_replace('"', '_', $str);
    $str = str_replace('<', '_', $str);
    $str = str_replace('>', '_', $str);
    $str = str_replace('|', '_', $str);
    if ($allowSpaces){
        // Apenas caracteres válidos
        $str = str_strip($str,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-0123456789.()[]& ");
        $str = replace_double(' ', $str);
        $str = trim($str);
    } else {
        $str = str_replace(' ', '_', $str);
        // Apenas caracteres válidos
        $str = str_strip($str,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-0123456789.()[]&");
    }
    $str = replace_double('_', $str);
    $str = trim($str,'_');
    return $str;
}
function fix_filename_download($str){ // no download podemos ter acentos
    $str = trim($str);
    // Substitui caracteres reservados
    $str = str_replace('\\', ' ', $str);
    $str = str_replace('/', ' ', $str);
    $str = str_replace(':', ' ', $str);
    $str = str_replace('*', ' ', $str);
    $str = str_replace('?', ' ', $str);
    $str = str_replace('"', ' ', $str);
    $str = str_replace('<', ' ', $str);
    $str = str_replace('>', ' ', $str);
    $str = str_replace('|', ' ', $str);
    // Apenas caracteres válidos
    $str = str_strip($str,"ÁÀÃÂÉÊÈËÍÓÔÕÒÚÜÇÑáàãâéêèëíóõôòúüçñABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-0123456789.()[] ");
    $str = replace_double(' ', $str);
    $str = trim($str);
    return $str;
}
function add_http($str){
    if (mb_strlen($str) > 0 && mb_strpos($str, 'http://') === false && mb_strpos($str, 'https://') === false) return 'http://'.$str;
    else return $str;
}
function remove_sinais($str){
    $sinais = "./\\-,:;'`~?!\"<>{}[]@#\$%^&*()_+=|";
    $str = str_replace(str_split($sinais),"",$str);
    return replace_double(" ",$str);
}
function remove_acentos($string) {
    if ( !preg_match('/[\x80-\xff]/', $string) ) return $string;
    $chars = array(
    // Decompositions for Latin-1 Supplement
    chr(195).chr(128) => 'A', chr(195).chr(129) => 'A',
    chr(195).chr(130) => 'A', chr(195).chr(131) => 'A',
    chr(195).chr(132) => 'A', chr(195).chr(133) => 'A',
    chr(195).chr(135) => 'C', chr(195).chr(136) => 'E',
    chr(195).chr(137) => 'E', chr(195).chr(138) => 'E',
    chr(195).chr(139) => 'E', chr(195).chr(140) => 'I',
    chr(195).chr(141) => 'I', chr(195).chr(142) => 'I',
    chr(195).chr(143) => 'I', chr(195).chr(145) => 'N',
    chr(195).chr(146) => 'O', chr(195).chr(147) => 'O',
    chr(195).chr(148) => 'O', chr(195).chr(149) => 'O',
    chr(195).chr(150) => 'O', chr(195).chr(153) => 'U',
    chr(195).chr(154) => 'U', chr(195).chr(155) => 'U',
    chr(195).chr(156) => 'U', chr(195).chr(157) => 'Y',
    chr(195).chr(159) => 's', chr(195).chr(160) => 'a',
    chr(195).chr(161) => 'a', chr(195).chr(162) => 'a',
    chr(195).chr(163) => 'a', chr(195).chr(164) => 'a',
    chr(195).chr(165) => 'a', chr(195).chr(167) => 'c',
    chr(195).chr(168) => 'e', chr(195).chr(169) => 'e',
    chr(195).chr(170) => 'e', chr(195).chr(171) => 'e',
    chr(195).chr(172) => 'i', chr(195).chr(173) => 'i',
    chr(195).chr(174) => 'i', chr(195).chr(175) => 'i',
    chr(195).chr(177) => 'n', chr(195).chr(178) => 'o',
    chr(195).chr(179) => 'o', chr(195).chr(180) => 'o',
    chr(195).chr(181) => 'o', chr(195).chr(182) => 'o',
    chr(195).chr(182) => 'o', chr(195).chr(185) => 'u',
    chr(195).chr(186) => 'u', chr(195).chr(187) => 'u',
    chr(195).chr(188) => 'u', chr(195).chr(189) => 'y',
    chr(195).chr(191) => 'y',
    // Decompositions for Latin Extended-A
    chr(196).chr(128) => 'A', chr(196).chr(129) => 'a',
    chr(196).chr(130) => 'A', chr(196).chr(131) => 'a',
    chr(196).chr(132) => 'A', chr(196).chr(133) => 'a',
    chr(196).chr(134) => 'C', chr(196).chr(135) => 'c',
    chr(196).chr(136) => 'C', chr(196).chr(137) => 'c',
    chr(196).chr(138) => 'C', chr(196).chr(139) => 'c',
    chr(196).chr(140) => 'C', chr(196).chr(141) => 'c',
    chr(196).chr(142) => 'D', chr(196).chr(143) => 'd',
    chr(196).chr(144) => 'D', chr(196).chr(145) => 'd',
    chr(196).chr(146) => 'E', chr(196).chr(147) => 'e',
    chr(196).chr(148) => 'E', chr(196).chr(149) => 'e',
    chr(196).chr(150) => 'E', chr(196).chr(151) => 'e',
    chr(196).chr(152) => 'E', chr(196).chr(153) => 'e',
    chr(196).chr(154) => 'E', chr(196).chr(155) => 'e',
    chr(196).chr(156) => 'G', chr(196).chr(157) => 'g',
    chr(196).chr(158) => 'G', chr(196).chr(159) => 'g',
    chr(196).chr(160) => 'G', chr(196).chr(161) => 'g',
    chr(196).chr(162) => 'G', chr(196).chr(163) => 'g',
    chr(196).chr(164) => 'H', chr(196).chr(165) => 'h',
    chr(196).chr(166) => 'H', chr(196).chr(167) => 'h',
    chr(196).chr(168) => 'I', chr(196).chr(169) => 'i',
    chr(196).chr(170) => 'I', chr(196).chr(171) => 'i',
    chr(196).chr(172) => 'I', chr(196).chr(173) => 'i',
    chr(196).chr(174) => 'I', chr(196).chr(175) => 'i',
    chr(196).chr(176) => 'I', chr(196).chr(177) => 'i',
    chr(196).chr(178) => 'IJ',chr(196).chr(179) => 'ij',
    chr(196).chr(180) => 'J', chr(196).chr(181) => 'j',
    chr(196).chr(182) => 'K', chr(196).chr(183) => 'k',
    chr(196).chr(184) => 'k', chr(196).chr(185) => 'L',
    chr(196).chr(186) => 'l', chr(196).chr(187) => 'L',
    chr(196).chr(188) => 'l', chr(196).chr(189) => 'L',
    chr(196).chr(190) => 'l', chr(196).chr(191) => 'L',
    chr(197).chr(128) => 'l', chr(197).chr(129) => 'L',
    chr(197).chr(130) => 'l', chr(197).chr(131) => 'N',
    chr(197).chr(132) => 'n', chr(197).chr(133) => 'N',
    chr(197).chr(134) => 'n', chr(197).chr(135) => 'N',
    chr(197).chr(136) => 'n', chr(197).chr(137) => 'N',
    chr(197).chr(138) => 'n', chr(197).chr(139) => 'N',
    chr(197).chr(140) => 'O', chr(197).chr(141) => 'o',
    chr(197).chr(142) => 'O', chr(197).chr(143) => 'o',
    chr(197).chr(144) => 'O', chr(197).chr(145) => 'o',
    chr(197).chr(146) => 'OE',chr(197).chr(147) => 'oe',
    chr(197).chr(148) => 'R',chr(197).chr(149) => 'r',
    chr(197).chr(150) => 'R',chr(197).chr(151) => 'r',
    chr(197).chr(152) => 'R',chr(197).chr(153) => 'r',
    chr(197).chr(154) => 'S',chr(197).chr(155) => 's',
    chr(197).chr(156) => 'S',chr(197).chr(157) => 's',
    chr(197).chr(158) => 'S',chr(197).chr(159) => 's',
    chr(197).chr(160) => 'S', chr(197).chr(161) => 's',
    chr(197).chr(162) => 'T', chr(197).chr(163) => 't',
    chr(197).chr(164) => 'T', chr(197).chr(165) => 't',
    chr(197).chr(166) => 'T', chr(197).chr(167) => 't',
    chr(197).chr(168) => 'U', chr(197).chr(169) => 'u',
    chr(197).chr(170) => 'U', chr(197).chr(171) => 'u',
    chr(197).chr(172) => 'U', chr(197).chr(173) => 'u',
    chr(197).chr(174) => 'U', chr(197).chr(175) => 'u',
    chr(197).chr(176) => 'U', chr(197).chr(177) => 'u',
    chr(197).chr(178) => 'U', chr(197).chr(179) => 'u',
    chr(197).chr(180) => 'W', chr(197).chr(181) => 'w',
    chr(197).chr(182) => 'Y', chr(197).chr(183) => 'y',
    chr(197).chr(184) => 'Y', chr(197).chr(185) => 'Z',
    chr(197).chr(186) => 'z', chr(197).chr(187) => 'Z',
    chr(197).chr(188) => 'z', chr(197).chr(189) => 'Z',
    chr(197).chr(190) => 'z', chr(197).chr(191) => 's'
    );
    $string = strtr($string, $chars);
    return $string;
}
function retifica_aspas($str){
    //return $str;
    $quotes = array(
        "\xC2\xAB"     => '"', // « (U+00AB) in UTF-8
        "\xC2\xBB"     => '"', // » (U+00BB) in UTF-8
        "\xE2\x80\x98" => "'", // ‘ (U+2018) in UTF-8
        "\xE2\x80\x99" => "'", // ’ (U+2019) in UTF-8
        "\xE2\x80\x9A" => "'", // ‚ (U+201A) in UTF-8
        "\xE2\x80\x9B" => "'", // ‛ (U+201B) in UTF-8
        "\xE2\x80\x9C" => '"', // “ (U+201C) in UTF-8
        "\xE2\x80\x9D" => '"', // ” (U+201D) in UTF-8
        "\xE2\x80\x9E" => '"', // „ (U+201E) in UTF-8
        "\xE2\x80\x9F" => '"', // ‟ (U+201F) in UTF-8
        "\xE2\x80\xB9" => "'", // ‹ (U+2039) in UTF-8
        "\xE2\x80\xBA" => "'", // › (U+203A) in UTF-8
    );
    return strtr($str, $quotes);
    // replace Microsoft Word version of single  and double quotations marks (“ ” ‘ ’) with  regular quotes (' and ")
    //return iconv('UTF-8', 'ASCII//TRANSLIT', $str);
}
function html_encode($str){
    global $charset;
    $str = preg_replace(array('/&/', '/</', '/>/', '/"/'), array('&amp;', '&lt;', '&gt;', '&quot;'), $str);  // Bypass PHP to allow any charset!!
    if (version_compare(PHP_VERSION, '5.2.3', '>=')) {
        $str = htmlentities($str, ENT_QUOTES, $charset, false);
    } else {
        $str = htmlentities($str, ENT_QUOTES, $charset);
    }
    return $str;
}
function rep($x,$y){
    if ($x) {
        $aux = "";
        for ($a=1;$a<=$x;$a++) $aux .= $y;
        return $aux;
    } else return "";
}
function str_zero($arg1,$arg2){
    if (strstr($arg1,"-") == false){
        $aux = intval($arg2) - strlen($arg1);
        if ($aux) return rep($aux,"0").$arg1;
        else return $arg1;
    } else {
        return "[$arg1]";
    }
}
function replace_double($sub,$str){
    $out=str_replace($sub.$sub,$sub,$str);
    while ( strlen($out) != strlen($str) ){
        $str=$out;
        $out=str_replace($sub.$sub,$sub,$str);
    }
    return $out;
}
function remove_special_chars($str){
    $str = trim($str);
    $str = strtr($str,array("¥µÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýÿ!@#%&*()[]{}+=?",
                            "YuAAAAAAACEEEEIIIIDNOOOOOOUUUUYsaaaaaaaceeeeiiiionoooooouuuuyy_______________"));
    $str = str_replace("..","",str_replace("/","",str_replace("\\","",str_replace("\$","",$str))));
    return $str;
}
function array_csort() {
    $args = func_get_args();
    $marray = array_shift($args);
    $msortline = "return(array_multisort(";
    foreach ($args as $arg) {
        $i++;
        if (is_string($arg)) {
            foreach ($marray as $row) {
                $sortarr[$i][] = $row[$arg];
            }
        } else {
            $sortarr[$i] = $arg;
        }
        $msortline .= "\$sortarr[".$i."],";
    }
    $msortline .= "\$marray));";
    eval($msortline);
    return $marray;
}
function show_perms($P) {
    $sP = "<b>";
    if($P & 0x1000) $sP .= 'p';            // FIFO pipe
    elseif($P & 0x2000) $sP .= 'c';        // Character special
    elseif($P & 0x4000) $sP .= 'd';        // Directory
    elseif($P & 0x6000) $sP .= 'b';        // Block special
    elseif($P & 0x8000) $sP .= '&minus;';  // Regular
    elseif($P & 0xA000) $sP .= 'l';        // Symbolic Link
    elseif($P & 0xC000) $sP .= 's';        // Socket
    else $sP .= 'u';                       // UNKNOWN
    $sP .= "</b>";
    // owner - group - others
    $sP .= (($P & 0x0100) ? 'r' : '&minus;') . (($P & 0x0080) ? 'w' : '&minus;') . (($P & 0x0040) ? (($P & 0x0800) ? 's' : 'x' ) : (($P & 0x0800) ? 'S' : '&minus;'));
    $sP .= (($P & 0x0020) ? 'r' : '&minus;') . (($P & 0x0010) ? 'w' : '&minus;') . (($P & 0x0008) ? (($P & 0x0400) ? 's' : 'x' ) : (($P & 0x0400) ? 'S' : '&minus;'));
    $sP .= (($P & 0x0004) ? 'r' : '&minus;') . (($P & 0x0002) ? 'w' : '&minus;') . (($P & 0x0001) ? (($P & 0x0200) ? 't' : 'x' ) : (($P & 0x0200) ? 'T' : '&minus;'));
    return $sP;
}
function format_size($arg) {
    if ($arg>0){
        $j = 0;
        $ext = array(" bytes"," Kb"," Mb"," Gb"," Tb");
        while ($arg >= pow(1024,$j)) ++$j;
        return round($arg / pow(1024,$j-1) * 100) / 100 . $ext[$j-1];
    } else return "0 bytes";
}
function check_limit($new_filesize=0) {
    global $fm_current_root;
    global $quota_mb;
    if($quota_mb){
        $total = intval(phpfm_get_total_size($fm_current_root));
        if (floor(($total+$new_filesize)/(1024*1024)) > $quota_mb) return true;
    }
    return false;
}
function uppercase($str){
    global $charset;
    return mb_strtoupper($str, $charset);
}
function lowercase($str){
    global $charset;
    return mb_strtolower($str, $charset);
}
function word_count($theString) {
    $theString = html_decode(strip_tags($theString));
    $char_count = mb_strlen($theString);
    $fullStr = $theString." ";
    $initial_whitespace_rExp = "^[[:alnum:]]$";

    $left_trimmedStr = ereg_replace($initial_whitespace_rExp,"",$fullStr);
    $non_alphanumerics_rExp = "^[[:alnum:]]$";
    $cleanedStr = ereg_replace($non_alphanumerics_rExp," ",$left_trimmedStr);
    $splitString = explode(" ",$cleanedStr);

    $word_count = count($splitString)-1;
    if(mb_strlen($fullStr)<2)$word_count=0;

    return $word_count;
}
function str_strip($str,$valid_chars){
    $out = "";
    for ($i=0;$i<mb_strlen($str);$i++){
        $mb_char = mb_substr($str,$i,1);
        if (mb_strpos($valid_chars,$mb_char) !== false){
            $out .= $mb_char;
        }
    }
    return $out;
}
function mb_str_ireplace($co, $naCo, $wCzym) {
    $wCzymM = mb_strtolower($wCzym);
    $coM    = mb_strtolower($co);
    $offset = 0;
    while(!is_bool($poz = mb_strpos($wCzymM, $coM, $offset))) {
        $offset = $poz + mb_strlen($naCo);
        $wCzym = mb_substr($wCzym, 0, $poz). $naCo .mb_substr($wCzym, $poz+mb_strlen($co));
        $wCzymM = mb_strtolower($wCzym);
    }
    return $wCzym;
}
// +--------------------------------------------------
// | Interface
// +--------------------------------------------------
function html_header($header=""){
    global $charset,$fm_color,$fm_path_info,$cookie_cache_time;
    echo "
    <!DOCTYPE HTML PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"//www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">
    <html xmlns=\"//www.w3.org/1999/xhtml\">
    <head>
    <meta http-equiv=\"content-type\" content=\"text/html; charset=".$charset."\" />
    <link rel=\"shortcut icon\" href=\"".$fm_path_info['basename']."?action=99&filename=favicon.ico\" type=\"image/x-icon\">
    <title>".et('FileMan')."</title>
    <style>
        .fm-title { margin: 0; font-weight: 500; line-height: 1.2; font-size: 1.5rem; }
        .float-left { float: left }
        .float-right { float: right }
        .noselect {
            -webkit-touch-callout: none; /* iOS Safari */
            -webkit-user-select: none; /* Safari */
            -khtml-user-select: none; /* Konqueror HTML */
            -moz-user-select: none; /* Firefox */
            -ms-user-select: none; /* Internet Explorer/Edge */
            user-select: none; /* Non-prefixed version */
        }
        .btn {
            display: inline-block;
            text-align: center;
            white-space: nowrap;
            vertical-align: middle;
            user-select: none;
            padding: 0 .4rem .05rem .2rem;
            line-height: 1.6;
            cursor: pointer;
        }
        .noIcon {
            padding: 0 .4rem .05rem .4rem;
        }
        i.bdc-link {
            font-style: normal;
            padding: 0 1px;
        }
        .fm-disk-info span {
            display: inline-block;
            margin: 2px 0;
            font-weight: 700;
        }
        .table {
            width: 100%;
            margin-bottom: 1rem;
            border-collapse: collapse;
        }
        .table .thead-light th {
            color: #495057;
            background-color: #e9ecef;
            border-color: #dee2e6;
            vertical-align: bottom;
            border-bottom: 2px solid #dee2e6;
            border-bottom-width: 2px;
        }
        .table td, .table th {
            padding: .3rem .4rem;
            border: 1px solid #dee2e6;
        }
        .table th {
            text-align: left;
        }
        .table td.lg {
            width: 400px;
        }
        .table td.sm {
            width: 10px;
            padding: .3rem .6rem;
            white-space: nowrap;
        }
        table.entry_name_table {
            width: 100%;
        }
        table.entry_name_table td {
            border: none;
            white-space: nowrap;
            padding: 0;
        }
        table.entry_name_table td.entry_name {
            padding-right: 60px;
            padding-top: 3px;
        }
        table.entry_name_table td .fa {
            margin-top: 0;
            margin-left: -6px;
            margin-right: 3px;
        }
        .form-signin {
            max-width: 350px;
            padding: 20px 20px 25px 20px;
            /*margin: 0 auto;*/
            background-color: #fff;
            border: 1px solid #ccc;
        }
        .form-signin-heading {
            margin-top: 0;
            margin-bottom: 18px;
            white-space: nowrap;
        }
        .form-control {
            display: block;
            width: 100%;
            margin-top: 1px;
            padding: 4px 10px;
            color: #495057;
            background-color: #fff;
            background-clip: padding-box;
            border: 1px solid #ced4da;
        }
        .form-signin input[type=\"password\"] {
            max-width: calc(100% - 80px);
            float: left;
        }
        .alert {
            position: relative;
            padding: 5px 10px;
            border: 1px solid transparent;
            clear: both;
        }
        .alert-danger {
            color: #721c24;
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }
        .mt-3 { margin-top: 1rem!important; }
        .mt-5 { margin-top: 3rem!important; }
        .icon_loading {
            background:url('".$fm_path_info['basename']."?action=99&filename=throbber.gif') 0 0 no-repeat;
            width: 16px;
            height: 16px;
            line-height: 16px;
            display: inline-block;
            vertical-align: text-bottom;
        }
        .fa {
            background:url('".$fm_path_info['basename']."?action=99&filename=file_sprite.png') 0 0 no-repeat;
            width: 18px;
            height: 18px;
            line-height: 18px;
            display: inline-block;
            vertical-align: text-bottom;
            margin-top: 3px;
        }
        .fa.fa-code { background-position: -126px 0; }
        .fa.fa-code-o { background-position: -143px 0; }
        .fa.fa-php { background-position: -108px -18px; }
        .fa.fa-picture { background-position: -125px -18px; }
        .fa.fa-file-text-o { background-position: -254px -18px; }
        .fa-file-archive-o { background-position: -180px 0; }
        .fa.fa-html { background-position: -434px -18px; }
        .fa.fa-file-excel-o { background-position: -361px 0; }
        .fa.fa-music { background-position: -108px 0; }
        .fa.fa-video { background-position: -90px 0; }
        .fa.fa-file-aspx { background-position: -236px 0; }
        .fa.fa-database { background-position: -272px 0; }
        .fa.fa-file-word { background-position: -361px -18px; }
        .fa.fa-file-powerpoint { background-position: -144px -18px; }
        .fa.fa-font { background-position: -415px 0; }
        .fa.file-pdf { background-position: -18px 0; }
        .fa.file-image-o { background-position: -398px 0; }
        .fa.fa-gear { background-position: -434px 0; }
        .fa.fa-download { background-position: -162px -18px; }
        .fa.fa-settings { background-position: -398px -18px; }
        .fa.fa-refresh { background-position: -236px -18px; }
        .fa.fa-lunix { background-position: -290px -18px; }
        .fa.fa-folder { background-position: -506px -18px; }
        .fa.fa-add-file { background-position: -54px 0; }
        .fa.fa-upload { background-position: -453px 0; }
        .fa.fa-file-go { background-position: -470px 0; }
        .fa.fa-link { background-position: -488px -18px; }
        .fa.fa-find { background-position: -380px 0; }
        .fa.fa-file-light { background-position: -470px -18px; }
        .fa.fa-file-remove { background-position: -290px 0; }
        .fa.fa-file-config { background-position: -308px 0; }
        .fa.fa-resolve { background-position: -272px 0; }
        .fa.fa-perms { background-position: -344px 0; }
        .fa.fa-copy { background-position: -198px 0; }
        .fa.fa-copy-o { background-position: -198px -18px; }
        .fa.fa-edit { background-position: -326px 0; }
        .fa.fa-rename { background-position: -454px -18px; }
        .fa.fa-glob { background-position: -380px -18px; }
        .fa.fa-vs { background-position: -326px -18px; }
        .fa.fa-search { background-position: 0 -18px; }
    </style>
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        function Is(){
            this.appname = navigator.appName;
            this.appversion = navigator.appVersion;
            this.platform = navigator.platform;
            this.useragent = navigator.userAgent.toLowerCase();
            this.ie = ( this.appname == 'Microsoft Internet Explorer' );
            if (( this.useragent.indexOf( 'mac' ) != -1 ) || ( this.platform.indexOf( 'mac' ) != -1 )){
                this.sisop = 'mac';
            } else if (( this.useragent.indexOf( 'windows' ) != -1 ) || ( this.platform.indexOf( 'win32' ) != -1 )){
                this.sisop = 'windows';
            } else if (( this.useragent.indexOf( 'inux' ) != -1 ) || ( this.platform.indexOf( 'linux' ) != -1 )){
                this.sisop = 'linux';
            }
        }
        var is = new Is();
        function enterSubmit(keypressEvent,submitFunc){
            var kCode = (is.ie) ? keypressEvent.keyCode : keypressEvent.which
            if( kCode == 13) eval(submitFunc);
        }
        function getCookieVal(offset) {
            var endstr = document.cookie.indexOf (';', offset);
            if (endstr == -1) endstr = document.cookie.length;
            return decodeURIComponent(document.cookie.substring(offset, endstr));
        }
        function getCookie(name) {
            var arg = name + '=';
            var alen = arg.length;
            var clen = document.cookie.length;
            var i = 0;
            while (i < clen) {
                var j = i + alen;
                if (document.cookie.substring(i, j) == arg) return getCookieVal (j);
                i = document.cookie.indexOf(' ', i) + 1;
                if (i == 0) break;
            }
            return null;
        }
        function setCookie(name, value) {
            var argv = setCookie.arguments;
            var argc = setCookie.arguments.length;
            var expires = (argc > 2) ? argv[2] : null;
            var path = (argc > 3) ? argv[3] : null;
            var domain = (argc > 4) ? argv[4] : null;
            var secure = (argc > 5) ? argv[5] : false;
            document.cookie = name + '=' + encodeURIComponent(value) +
            ((expires == null) ? '' : ('; expires=' + expires.toGMTString())) +
            ((path == null) ? '' : ('; path=' + path)) +
            ((domain == null) ? '' : ('; domain=' + domain)) +
            ((secure == true) ? '; secure' : '');
        }
        function delCookie(name) {
            var exp = new Date();
            exp.setTime (exp.getTime() - 1);
            var cval = getCookie (name);
            document.cookie = name + '=' + cval + '; expires=' + exp.toGMTString();
        }
        function setCookiePersistent(name, value){
            var exp = new Date();
            exp.setTime(exp.getTime()+".$cookie_cache_time.");
            setCookie(name,value,exp);
        }
        var frameWidth, frameHeight;
        function getFrameSize(){
            if (self.innerWidth){
                frameWidth = self.innerWidth;
                frameHeight = self.innerHeight;
            }else if (document.documentElement && document.documentElement.clientWidth){
                frameWidth = document.documentElement.clientWidth;
                frameHeight = document.documentElement.clientHeight;
            }else if (document.body){
                frameWidth = document.body.clientWidth;
                frameHeight = document.body.clientHeight;
            }else return false;
            return true;
        }
        getFrameSize();
        function str_replace (search, replace, subject, count) {
            var i = 0,
                j = 0,
                temp = '',
                repl = '',
                sl = 0,
                fl = 0,
                f = [].concat(search),
                r = [].concat(replace),
                s = subject,
                ra = Object.prototype.toString.call(r) === '[object Array]',
                sa = Object.prototype.toString.call(s) === '[object Array]';
            s = [].concat(s);
            if (count) {
                this.window[count] = 0;
            }

            for (i = 0, sl = s.length; i < sl; i++) {
                if (s[i] === '') {
                    continue;
                }
                for (j = 0, fl = f.length; j < fl; j++) {
                    temp = s[i] + '';
                    repl = ra ? (r[j] !== undefined ? r[j] : '') : r[0];
                    s[i] = (temp).split(f[j]).join(repl);
                    if (count && s[i] !== temp) {
                        this.window[count] += (temp.length - s[i].length) / f[j].length;
                    }
                }
            }
            return sa ? s : s[0];
        }
        function rep(str,i){
            str = String(str);
            i = parseInt(i);
            if (i > 0) {
                var out = '';
                for (var ii=1;ii<=i;ii++) out += str;
                return out;
            } else return '';
        }
    //-->
    </script>
    <style type=\"text/css\">
    html {
        width: 100%;
        margin-left: 0 !important;
    }
    body {
        font-family : Arial;
        font-size: 14px;
        font-weight : normal;
        color: #".$fm_color['Text'].";
        background-color: #".$fm_color['Bg'].";
    }
    table {
        font-family : Arial;
        font-size: 14px;
        font-weight : normal;
        color: #".$fm_color['Text'].";
        cursor: default;
    }
    input {
        font-family : Arial;
        font-size: 14px;
        font-weight : normal;
        color: #".$fm_color['Text'].";
    }
    textarea {
        font-family : Courier;
        font-size: 12px;
        font-weight : normal;
        color: #".$fm_color['Text'].";
    }
    a {
        font-family : Arial;
        font-size : 14px;
        font-weight : bold;
        text-decoration: none;
        color: #".$fm_color['Text'].";
    }
    a:link {
        color: #".$fm_color['Text'].";
    }
    a:visited {
        color: #".$fm_color['Text'].";
    }
    a:hover {
        color: #".$fm_color['Link'].";
    }
    a:active {
        color: #".$fm_color['Text'].";
    }
    tr.entryUnselected {
        background-color: #".$fm_color['Entry'].";
    }
    tr.entryUnselected:hover {
        background-color: #".$fm_color['Over'].";
    }
    tr.entrySelected {
        background-color: #".$fm_color['Mark'].";
    }
    </style>
    ".$header."
    </head>
    ";
}
function reloadframe($ref,$frame_number,$plus=""){
    global $fm_current_dir,$fm_path_info;
    echo "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        ".$ref.".frame".$frame_number.".location.href='".$fm_path_info['basename']."?frame=".$frame_number."&fm_current_dir=".rawurlencode($fm_current_dir.$plus)."';
    //-->
    </script>
    ";
}
function alert($arg){
    echo "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        alert('$arg');
    //-->
    </script>
    ";
}
function get_encoding($text){
    define('UTF32_BIG_ENDIAN_BOM'   , chr(0x00).chr(0x00).chr(0xFE).chr(0xFF));
    define('UTF32_LITTLE_ENDIAN_BOM', chr(0xFF).chr(0xFE).chr(0x00).chr(0x00));
    define('UTF16_BIG_ENDIAN_BOM'   , chr(0xFE).chr(0xFF));
    define('UTF16_LITTLE_ENDIAN_BOM', chr(0xFF).chr(0xFE));
    define('UTF8_BOM'               , chr(0xEF).chr(0xBB).chr(0xBF));
    $first2 = mb_substr($text, 0, 2);
    $first3 = mb_substr($text, 0, 3);
    $first4 = mb_substr($text, 0, 4);
    if ($first3 == UTF8_BOM) return 'UTF-8'; // WITH BOM
    elseif ($first4 == UTF32_BIG_ENDIAN_BOM) return 'UTF-32BE';
    elseif ($first4 == UTF32_LITTLE_ENDIAN_BOM) return 'UTF-32LE';
    elseif ($first2 == UTF16_BIG_ENDIAN_BOM) return 'UTF-16BE';
    elseif ($first2 == UTF16_LITTLE_ENDIAN_BOM) return 'UTF-16LE';
    elseif (mb_detect_encoding($text, 'UTF-8', true) == true) return 'UTF-8'; // WITHOUT BOM
    elseif (mb_detect_encoding($text, 'ISO-8859-1', true) == true) return 'ISO-8859-1';
    else return mb_detect_encoding($text);
}
function utf8_convert($str){
    if (extension_loaded('mbstring') && extension_loaded('iconv')) {
        $str_chatset = get_encoding($str);
        if ($str_chatset == "UTF-8") return $str;
        return iconv($str_chatset, "UTF-8//TRANSLIT", $str);
    } else return utf8_encode($str);
}
function convert_charset($str,$charset){
    $str_chatset = get_encoding($str);
    if ($str_chatset == $charset) return $str;
    else return iconv($str_chatset, $charset."//TRANSLIT", $str);
}
function fs_encode($str){
    global $is_windows;
    if ($is_windows) {
        if (extension_loaded('mbstring') && extension_loaded('iconv')) {
            $str = convert_charset($str,'ISO-8859-1');
        }
    }
    return $str;
}
class tree_fs {
    protected $base = null;
    public function __construct($base) {
        $this->base = $this->real($base);
        if(!$this->base) { fb_log('Base directory does not exist'); }
    }
    protected function real($path) {
        if (is_link($path)) $temp = get_absolute_path(fs_encode($path));
        else $temp = realpath(fs_encode($path));
        if(!$temp) { fb_log('Path does not exist: ' . $path); }
        if($this->base && strlen($this->base)) {
            if(strpos($temp, $this->base) !== 0) { fb_log('Path is not inside base ('.$this->base.'): ' . $temp); }
        }
        return $temp;
    }
    protected function path($id) {
        global $is_windows;
        $path = str_replace('/', DIRECTORY_SEPARATOR, $id);
        $path = $this->real($this->base.DIRECTORY_SEPARATOR.$path);
        $path = rtrim($path, DIRECTORY_SEPARATOR);
        if (!$is_windows) {
            $path = DIRECTORY_SEPARATOR.$path;
        }
        $path = replace_double(DIRECTORY_SEPARATOR,$path);
        //fb_log('path()',$id.' => '.$path);
        return $path;
    }
    protected function id($path) {
        global $is_windows;
        $id = $this->real($path);
        $id = substr($id, strlen($this->base));
        $id = str_replace(DIRECTORY_SEPARATOR, '/', $id);
        $id = '/'.rtrim($id, '/');
        $id = replace_double('/',$id);
        //fb_log('id()',$path.' => '.$id);
        return $id;
    }
    public function lst($id, $with_root=false) {
        $path = $this->path($id);
        $lst = scandir(fs_encode($path));
        if(!$lst) { fb_log('Could not list path: '.$path); }
        $res = array();
        foreach($lst as $item) {
            if ($item == '.' || $item == '..' || $item === null) { continue; }
            $item_path = rtrim($path,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$item;
            if (is_dir($item_path)) {
                if (is_link($item_path)) $item .= ' (L)';
                $res[] = array('text' => utf8_convert($item), 'children' => true,  'id' => utf8_convert($this->id($item_path)), 'icon' => 'folder');
            } elseif (is_link($item_path) && !is_file($item_path)) {
                // Add &#8202; Invisible char to change color to RED using Jquery https://stackoverflow.com/questions/17978720/invisible-characters-ascii
                // TODO: Find a better way to show RED broken folder links, using jsTree API
                if (is_link($item_path)) $item .= ' (L*)';
                $res[] = array('text' => utf8_convert($item), 'children' => true,  'id' => utf8_convert($this->id($item_path)), 'icon' => 'folder');
            }
        }
        if($with_root && $this->id($path) == '/') {
            $res = array(array('text' => utf8_convert($this->base), 'children' => $res, 'id' => '/', 'icon'=>'folder', 'state' => array('opened' => true, 'disabled' => false)));
        }
        return $res;
    }
    public function data($id) {
        if(strpos($id, ":")) {
            $id = array_map(array($this, 'id'), explode(':', $id));
            return array('type'=>'multiple', 'content'=> 'Multiple selected: ' . implode(' ', $id));
        }
        $path = $this->path($id);
        if(is_dir($path)) {
            return array('type'=>'folder', 'content'=> $id);
        }
        fb_log('Not a valid selection: '.$path);
    }
}
function frame2(){
    global $fm_root,$fm_current_root,$fm_path_info,$setflag,$is_windows,$cookie_cache_time,$fm_current_dir,$auth_pass,$open_basedirs;
    if(isset($_GET['operation'])) {
        $tree_fs = new tree_fs($fm_current_root);
        try {
            $resul = null;
            switch($_GET['operation']) {
                case 'get_node':
                    $node = (strlen($_GET['id']) && $_GET['id'] !== '#') ? $_GET['id'] : '/';
                    $with_root = true;
                    $resul = $tree_fs->lst($node, $with_root);
                    break;
                default:
                    fb_log('Unsupported operation: '.$_GET['operation']);
                    break;
            }
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($resul);
        }
        catch (Exception $e) {
            header($_SERVER['SERVER_PROTOCOL'] . ' 500 Server Error');
            header('Status:  500 Server Error');
            echo $e->getMessage();
        }
        die();
    }
    html_header("
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        function saveFrameSize(){
            if (getFrameSize()){
                var exp = new Date();
                exp.setTime(exp.getTime()+".$cookie_cache_time.");
                setCookie('leftFrameWidth',frameWidth,exp);
            }
        }
        window.onresize = saveFrameSize;
    //-->
    </script>");
    echo "<body marginwidth=\"0\" marginheight=\"0\">
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        // Disable text selection, binding the onmousedown, but not for some elements, it must work.
        function disableTextSelection(e){
            var type = String(e.target.type);
            return (type.indexOf('select') != -1 || type.indexOf('button') != -1 || type.indexOf('input') != -1 || type.indexOf('radio') != -1);
        }
        function enableTextSelection(){return true}
        if (is.ie) document.onselectstart=new Function('return false')
        else {
            document.body.onmousedown=disableTextSelection
            document.body.onclick=enableTextSelection
        }
        var flag = ".(($setflag)?"true":"false")."
        function set_flag(arg) {
            flag = arg;
        }
        function go_tree(arg) {
            if (flag) {
                parent.frame3.set_dir_dest(arg+'".addslashes(DIRECTORY_SEPARATOR)."');
                flag = false;
            } else {
                parent.frame3.location.href='".addslashes($fm_path_info['basename'])."?frame=3&fm_current_root=".rawurlencode($fm_current_root)."&fm_current_dir='+encodeURIComponent(arg)+'".rawurlencode(DIRECTORY_SEPARATOR)."';
            }
        }
        function set_fm_current_root(arg){
            document.location.href='".addslashes($fm_path_info['basename'])."?frame=2&fm_current_root='+encodeURIComponent(arg);
        }
        function refresh_tree(){
            document.location.href='".addslashes($fm_path_info['basename'])."?frame=2&fm_current_root=".rawurlencode($fm_current_root)."';
        }
        function logout(){
            document.location.href='".addslashes($fm_path_info['basename'])."?action=1';
        }
    //-->
    </script>
    ";
    echo "<table width=\"100%\" height=\"100%\" border=0 cellspacing=0 cellpadding=5>\n";
    echo "<tr valign=top height=10 bgcolor=\"#DDDDDD\" style=\"border-bottom: 2px solid #eaeaea;\"><td style=\"padding: 6px 6px 1px; 6px;\">";
    echo "<form style=\"display:inline-block;\" action=\"".$fm_path_info['basename']."\" method=\"post\" target=\"_parent\">";
        $fm_root_opts=array();
        if (strlen($fm_root) == 0) {
            if (count($open_basedirs)>1){
                foreach ($open_basedirs as $dir) {
                    $is_sel=(strpos($fm_current_root,$dir) !== false)?"selected":"";
                    $fm_root_opts[] = "<option ".$is_sel." value=\"".$dir."\">".html_encode($dir)."</option>";
                }
            } elseif ($is_windows){
                $drives=array();
                $aux="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                for($x=0;$x<strlen($aux);$x++){
                    $dir = $aux[$x].":".DIRECTORY_SEPARATOR;
                    if ($handle = @opendir($dir)){
                        @closedir($handle);
                        $is_sel=(strpos(uppercase($fm_current_root),$dir) !== false)?"selected":"";
                        $fm_root_opts[] = "<option ".$is_sel." value=\"".$dir."\">".html_encode($dir)."</option>";
                    }
                }
            }
        }
        if (count($fm_root_opts)>1) echo "<select name=drive onchange=\"set_fm_current_root(this.value)\" style=\"float:left; margin:1px 0 5px 0; margin-right:5px; padding:5px;\">".implode("\n",$fm_root_opts)."</select>";
        echo "<button type=\"button\" style=\"margin-bottom: 5px;\" class=\"btn\" onclick=\"refresh_tree()\" value=\"".et('Refresh')."\"><i class=\"fa fa-refresh\"></i> ".et('Refresh')."</button>";
        if ($auth_pass != md5('')) echo "&nbsp;<button type=\"button\" style=\"margin-bottom: 5px;\" class=\"btn \" onclick=\"logout()\" value=\"".et('Leave')."\"><i class=\"fa fa-file-go\"></i> ".et('Leave')."</button>";
    echo "</form>";
    echo "</td></tr>";
    echo "<tr valign=top><td>";
    ?>
        <script type="text/javascript" src="<?php echo $fm_path_info['basename']; ?>?action=99&filename=jquery-1.11.1.min.js"></script>
        <script type="text/javascript" src="<?php echo $fm_path_info['basename']; ?>?action=99&filename=jstree.min.js"></script>
        <link rel="stylesheet" type="text/css" href="<?php echo $fm_path_info['basename']; ?>?action=99&filename=jstree.style.min.css" media="screen" />
        <style>
            #tree { float:left; overflow:auto; padding:0; margin-bottom: 20px;}
            #tree .folder { background:url('<?php echo $fm_path_info['basename']; ?>?action=99&filename=file_sprite.png') right bottom no-repeat; }
            #tree .file { background:url('<?php echo $fm_path_info['basename']; ?>?action=99&filename=file_sprite.png') 0 0 no-repeat; }
            #tree .file-pdf { background-position: -32px 0 }
            #tree .file-as { background-position: -36px 0 }
            #tree .file-c { background-position: -72px -0px }
            #tree .file-iso { background-position: -108px -0px }
            #tree .file-htm, #tree .file-html, #tree .file-xml, #tree .file-xsl { background-position: -126px -0px }
            #tree .file-cf { background-position: -162px -0px }
            #tree .file-cpp { background-position: -216px -0px }
            #tree .file-cs { background-position: -236px -0px }
            #tree .file-sql { background-position: -272px -0px }
            #tree .file-xls, #tree .file-xlsx { background-position: -362px -0px }
            #tree .file-h { background-position: -488px -0px }
            #tree .file-crt, #tree .file-pem, #tree .file-cer { background-position: -452px -18px }
            #tree .file-php { background-position: -108px -18px }
            #tree .file-jpg, #tree .file-jpeg, #tree .file-png, #tree .file-gif, #tree .file-bmp { background-position: -126px -18px }
            #tree .file-ppt, #tree .file-pptx { background-position: -144px -18px }
            #tree .file-rb { background-position: -180px -18px }
            #tree .file-text, #tree .file-txt, #tree .file-md, #tree .file-log, #tree .file-htaccess { background-position: -254px -18px }
            #tree .file-doc, #tree .file-docx { background-position: -362px -18px }
            #tree .file-zip, #tree .file-gz, #tree .file-tar, #tree .file-rar { background-position: -416px -18px }
            #tree .file-js { background-position: -434px -18px }
            #tree .file-css { background-position: -144px -0px }
            #tree .file-fla { background-position: -398px -0px }
        </style>
        <div id="container" role="main">
            <div id="tree"></div>
        </div>
        <?php
            $tree_auto_load_nodes = substr($fm_current_dir,strlen($fm_current_root));
            $tree_auto_load_nodes = trim($tree_auto_load_nodes,DIRECTORY_SEPARATOR);
            $tree_auto_load_nodes = explode(DIRECTORY_SEPARATOR,$tree_auto_load_nodes);
        ?>
        <script>
        var tree_loaded = false;
        var tree_auto_load_nodes = <?php echo json_encode($tree_auto_load_nodes); ?>;
        var tree_auto_load_node_curr = 0;
        //console.log(tree_auto_load_nodes);
        function highlight_broken_links(){
            $("#tree a:contains('(L*)')").css({'color':'red'});
            var str = $("#tree a:contains('(L*)')").html();
            $("#tree a:contains('(L*)')").html(String(str).replace('(L*)','(L)'));
        }
        function tree_auto_load(){
            if (tree_auto_load_node_curr > tree_auto_load_nodes.length) return;
            var node_id = '/'+tree_auto_load_nodes.slice(0, tree_auto_load_node_curr+1).join('/');
            var node = $('#tree').find("[id='"+node_id+"']:eq(0)");
            tree_auto_load_node_curr++;
            //console.log('tree_auto_load() '+tree_auto_load_node_curr);
            //console.log('node_id: '+node_id);
            //console.log(node);
            if (tree_auto_load_node_curr == tree_auto_load_nodes.length) {
                if (node.length) {
                    $("#tree").jstree(true).open_node(node, function(){
                        highlight_broken_links();
                        $('#tree').jstree(true).select_node(node,true);
                        tree_loaded = true;
                    }, false);
                } else {
                    tree_loaded = true;
                }
            } else {
                if (node.length) {
                    $("#tree").jstree(true).open_node(node, tree_auto_load, false);
                } else {
                    tree_auto_load();
                }
            }
            highlight_broken_links();
        }
        $(function () {
            $('#tree')
                .jstree({
                    'core' : {
                        'data' : {
                            'url' : '?frame=2&fm_current_root=<?php echo rawurlencode($fm_current_root) ?>&operation=get_node',
                            'data' : function (node) {
                                return { 'id' : node.id };
                            }
                        },
                        'check_callback' : function(o, n, p, i, m) {
                            if(m && m.dnd && m.pos !== 'i') { return false; }
                            if(o === "move_node" || o === "copy_node") {
                                if(this.get_node(n).parent === this.get_node(p).id) { return false; }
                            }
                            return true;
                        },
                        'force_text' : true,
                        'themes' : {
                            'responsive' : false,
                            'variant' : 'small',
                            'stripes' : false
                        },
                        'expand_selected_onload' : true
                    },
                    'sort' : function(a, b) {
                        return this.get_type(a) === this.get_type(b) ? (this.get_text(a) > this.get_text(b) ? 1 : -1) : (this.get_type(a) >= this.get_type(b) ? 1 : -1);
                    },
                    'types' : {
                        'default' : { 'icon' : 'folder' },
                        'file' : { 'valid_children' : [], 'icon' : 'file' },
                        'broken_link': { 'icon' : 'folder' }
                    },
                    'unique' : {
                        'duplicate' : function (name, counter) {
                            return name + ' ' + counter;
                        }
                    },
                    'massload' : {
                        'url' : '?frame=2&fm_current_root=<?php echo rawurlencode($fm_current_root) ?>&operation=get_node',
                        'data' : function (nodes) {
                            return { 'ids' : nodes.join(',') };
                        }
                    },
                    'plugins' : ['sort','types','unique'] // 'state', 'massload'
                })
            //.on('changed.jstree', function (e, data) {
            .on('select_node.jstree', function (e, data) {
                if (!tree_loaded) return;
                if (data && data.selected && data.selected.length) {
                    //console.log('select_node.jstree()');
                    var path = String(data.selected[0]);
                    path = path.replace(/\//g,'<?php echo addslashes(DIRECTORY_SEPARATOR); ?>');
                    go_tree('<?php echo addslashes(rtrim($fm_current_root,DIRECTORY_SEPARATOR)); ?>'+path);
                }
            })
            .on('loaded.jstree', function (e, data) {
                //console.log('loaded.jstree()');
                //console.log(e);
                //console.log(data);
                tree_auto_load();
            });
            //$('#tree').jstree(true).clear_state();
        });
        </script>
    <?php
    echo "</td></tr>";
    echo "</table>\n";
    echo "</body>\n</html>";
}
if(!function_exists('mime_content_type')){
    function mime_content_type($path){
        return 'application/octet-stream'; // fallback if mod_fileinfo is not available
    }
}
function is_binary($file){
    //https://stackoverflow.com/questions/1765311/how-to-view-files-in-binary-from-bash
    //http://php.net/manual/pt_BR/function.bin2hex.php
    if (!is_file($file)) return false;
    $mime = mime_content_type($file);
    fb_log($file,$mime);
    if (strpos($mime,'text') === false && strpos($mime,'x-empty') === false) return true;
    return false;
}
function is_textfile($file){
    if (!is_file($file)) return false;
    $mime = mime_content_type($file);
    fb_log($file,$mime);
    if (strpos($mime,'text') === 0 || strpos($mime,'x-empty') !== false) return true;
    return false;
}
function dir_list_form() {
    global $script_init_time,$fm_current_root,$fm_current_dir,$quota_mb,$resolve_ids,$order_dir_list_by,$is_windows,$cmd_name,$ip,$lan_ip,$fm_path_info,$version,$date_format;
    clearstatcache();
    $out = "<style>
        #modalIframeWrapper {
            background: #FFF;
            border: 1px solid #ccc;
            margin: -2px;
            position: absolute;
            top: 22px;
            left: 5px;
            width: calc(100% - 10px);
            height: calc(100% - 50px);
            transform: translate(0,22px);
            z-index: 32000;
            display: none;
        }
        #modalIframe {
            display: block;
            background: #FFF;
            border: 1px solid #ccc;
            width: 100%;
            height: 100%;
            overflow-y: scroll;
            overflow-x: auto;
        }
        #modalIframeWrapperTitle {
            padding-left: 5px;
        }
    </style>
    <div id=\"modalIframeWrapper\">
        <table border=0 cellspacing=1 cellpadding=4 width=\"100%\" height=\"100%\">
            <tr style=\"height:20px;\">
                <td id=\"modalIframeWrapperTitle\" style=\"font-weight:bold;\">Title</td>
                <td align=right width=10><button type=\"button\" class=\"btn\" onclick=\"closeModalWindow()\" value=\"".et('Close')."\"><i class=\"fa fa-file-go\"></i> ".et('Close')."</button></td>
            </tr>
            <tr style=\"height:100%\">
                <td colspan=2 style=\"padding-top:0;\"><iframe id=\"modalIframe\" src=\"\" scrolling=\"yes\" frameborder=\"0\"></iframe></td>
            </tr>
        </table>
    </div>
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        var modalWindowReloadOnClose = false;
        var modalWindowCurrSrc = '';
        function toogleModalWindow(url,title,reloadOnClose){
            if (document.getElementById(\"modalIframeWrapper\").style.display == '' || modalWindowCurrSrc != url){
                openModalWindow(url,title,reloadOnClose);
            } else {
                modalWindowReloadOnClose = false;
                closeModalWindow();
            }
        }
        function openModalWindow(url,title,reloadOnClose){
            cancel_copy_move();
            if (typeof(title) == 'undefined') title = '';
            if (typeof(reloadOnClose) != 'undefined') modalWindowReloadOnClose = reloadOnClose;
            if (modalWindowCurrSrc != url) {
                document.getElementById(\"modalIframe\").src = url;
            }
            modalWindowCurrSrc = url;
            document.getElementById(\"modalIframeWrapper\").style.display = 'block';
            document.getElementById(\"modalIframeWrapperTitle\").innerHTML = title;
            document.getElementById(\"modalIframe\").focus();
            document.body.style.overflow = 'hidden';
            window.scrollTo(0,0);
        }
        function closeModalWindow(){
            document.getElementById(\"modalIframeWrapper\").style.display = '';
            document.body.style.overflow = 'auto';
            if (modalWindowReloadOnClose) {
                window.parent.frame3.location.href='".$fm_path_info['basename']."?frame=3&fm_current_dir=".rawurlencode($fm_current_dir)."';
            }
        }
    -->
    </script>";
    $io_error = true;
    if ($opdir = @opendir(fs_encode($fm_current_dir))) {
        $io_error = false;
        $has_files = false;
        $entry_count = 0;
        $total_size = 0;
        $entry_list = array();
        while (($entry = readdir($opdir)) !== false) {
            if ($entry == "." || $entry == "..") continue;
            $entry_list[$entry_count]['name'] = $entry;
            $entry_list[$entry_count]['namet'] = $entry;
            $entry_list[$entry_count]['size'] = 0;
            $entry_list[$entry_count]['sizet'] = 0;
            $entry_list[$entry_count]['type'] = "none";
            $entry_list[$entry_count]['date'] = date("Ymd", filemtime($fm_current_dir.$entry));
            $entry_list[$entry_count]['time'] = date("His", filemtime($fm_current_dir.$entry));
            $entry_list[$entry_count]['datet'] = date($date_format, filemtime($fm_current_dir.$entry));
            $entry_list[$entry_count]['p'] = substr(sprintf('%o', fileperms($fm_current_dir.$entry)), -4);
            $entry_list[$entry_count]['u'] = fileowner($fm_current_dir.$entry);
            $entry_list[$entry_count]['g'] = filegroup($fm_current_dir.$entry);
            if ($resolve_ids){
                $entry_list[$entry_count]['p'] = show_perms(fileperms($fm_current_dir.$entry));
                if (!$is_windows){
                    $entry_list[$entry_count]['u'] = get_user_name(fileowner($fm_current_dir.$entry));
                    $entry_list[$entry_count]['g'] = get_group_name(filegroup($fm_current_dir.$entry));
                }
            }
            if (is_link($fm_current_dir.$entry)){
                $entry_list[$entry_count]['type'] = "link";
                $entry_list[$entry_count]['target'] = readlink($fm_current_dir.$entry);
                $entry_list[$entry_count]['target_absolute_path'] = readlink_absolute_path($fm_current_dir.$entry);
                if (is_dir($entry_list[$entry_count]['target_absolute_path'])) {
                    $entry_list[$entry_count]['type'] = "dir";
                    $dirsize = phpfm_get_total_size($fm_current_dir.$entry);
                    $entry_list[$entry_count]['size'] = intval($dirsize);
                    if ($dirsize === false) {
                        $sizet = et('GetSize').'..';
                    } elseif ($dirsize === 'error'){
                        $sizet = '<span title="error: too much recursion">'.et('Error').' &#x21bb</span>';
                    } else {
                        $sizet = format_size($entry_list[$entry_count]['size']).' &#x21bb';
                    }
                    $entry_list[$entry_count]['sizet'] = "<a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:dir_list_update_total_size('".addslashes($entry)."','dir".$entry_count."size')\"><span id=\"dir".$entry_count."size\">".$sizet."</span></a>";
                } elseif (is_file($entry_list[$entry_count]['target_absolute_path'])) {
                    $entry_list[$entry_count]['type'] = "file";
                    $entry_list[$entry_count]['size'] = phpfm_filesize($fm_current_dir.$entry);
                    $entry_list[$entry_count]['sizet'] = format_size($entry_list[$entry_count]['size']);
                    $has_files = true;
                } else {
                    $entry_list[$entry_count]['type'] = "broken_link";
                    $entry_list[$entry_count]['date'] = '';
                    $entry_list[$entry_count]['time'] = '';
                    $entry_list[$entry_count]['datet'] = '';
                    $entry_list[$entry_count]['size'] = 0;
                    $entry_list[$entry_count]['sizet'] = '';
                    $entry_list[$entry_count]['p'] = '';
                }
                $entry_list[$entry_count]['linkt'] = '<span style="float:right; margin-top:3px; font-weight:bold;" title="symlink to '.$entry_list[$entry_count]['target'].'">(L)</span>';
                $ext = lowercase(strrchr($entry,"."));
                if (strstr($ext,".")){
                    $entry_list[$entry_count]['ext'] = $ext;
                    $entry_list[$entry_count]['extt'] = $ext;
                } else {
                    $entry_list[$entry_count]['ext'] = "";
                    $entry_list[$entry_count]['extt'] = "&nbsp;";
                }
            } elseif (is_file($fm_current_dir.$entry)){
                $ext = lowercase(strrchr($entry,"."));
                $entry_list[$entry_count]['type'] = "file";
                $entry_list[$entry_count]['size'] = phpfm_filesize($fm_current_dir.$entry);
                $entry_list[$entry_count]['sizet'] = format_size($entry_list[$entry_count]['size']);
                if (strstr($ext,".")){
                    $entry_list[$entry_count]['ext'] = $ext;
                    $entry_list[$entry_count]['extt'] = $ext;
                } else {
                    $entry_list[$entry_count]['ext'] = "";
                    $entry_list[$entry_count]['extt'] = "&nbsp;";
                }
                $has_files = true;
            } elseif (is_dir($fm_current_dir.$entry)) {
                $entry_list[$entry_count]['type'] = "dir";
                $dirsize = phpfm_get_total_size($fm_current_dir.$entry);
                $entry_list[$entry_count]['size'] = intval($dirsize);
                if ($dirsize === false){
                    $sizet = et('GetSize').'..';
                } elseif ($dirsize === 'error') {
                    $sizet = '<span title="error: too much recursion">'.et('Error').' &#x21bb</span>';
                } else {
                    $sizet = format_size($entry_list[$entry_count]['size']).' &#x21bb';
                }
                $entry_list[$entry_count]['sizet'] = "<a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:dir_list_update_total_size('".addslashes($entry)."','dir".$entry_count."size')\"><span id=\"dir".$entry_count."size\">".$sizet."</span></a>";
            }
            $total_size += $entry_list[$entry_count]['size'];
            $entry_count++;
        }
        @closedir($opdir);
    }
    if($entry_count){
        $or1="1A";
        $or2="2D";
        $or3="3A";
        $or4="4A";
        $or5="5A";
        $or6="6D";
        $or7="7D";
        switch($order_dir_list_by){
            case "1A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"name",SORT_STRING,SORT_ASC); $or1="1D"; break;
            case "1D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"name",SORT_STRING,SORT_DESC); $or1="1A"; break;
            case "2A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"p",SORT_STRING,SORT_ASC,"g",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_ASC); $or2="2D"; break;
            case "2D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"p",SORT_STRING,SORT_DESC,"g",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_ASC); $or2="2A"; break;
            case "3A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_ASC,"g",SORT_STRING,SORT_ASC); $or3="3D"; break;
            case "3D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_DESC,"g",SORT_STRING,SORT_ASC); $or3="3A"; break;
            case "4A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"g",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_DESC); $or4="4D"; break;
            case "4D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"g",SORT_STRING,SORT_DESC,"u",SORT_STRING,SORT_DESC); $or4="4A"; break;
            case "5A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"size",SORT_NUMERIC,SORT_ASC); $or5="5D"; break;
            case "5D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"size",SORT_NUMERIC,SORT_DESC); $or5="5A"; break;
            case "6A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"date",SORT_STRING,SORT_ASC,"time",SORT_STRING,SORT_ASC,"name",SORT_STRING,SORT_ASC); $or6="6D"; break;
            case "6D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"date",SORT_STRING,SORT_DESC,"time",SORT_STRING,SORT_DESC,"name",SORT_STRING,SORT_ASC); $or6="6A"; break;
            case "7A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"ext",SORT_STRING,SORT_ASC,"name",SORT_STRING,SORT_ASC); $or7="7D"; break;
            case "7D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"ext",SORT_STRING,SORT_DESC,"name",SORT_STRING,SORT_ASC); $or7="7A"; break;
        }
    }
    $out .= "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
    function go_dir_list(arg) {
        document.location.href='".addslashes($fm_path_info['basename'])."?frame=3&fm_current_dir=".rawurlencode($fm_current_dir)."'+encodeURIComponent(arg)+'".addslashes(DIRECTORY_SEPARATOR)."';
    }
    function resolve_ids() {
        document.location.href='".addslashes($fm_path_info['basename'])."?frame=3&set_resolve_ids=".($resolve_ids?'0':'1')."&fm_current_dir=".rawurlencode($fm_current_dir)."';
    }
    var entry_list = new Array();
    // Custom object constructor
    function entry(name, type, perms, size, selected){
        this.name = name;
        this.type = type;
        this.perms = perms;
        this.size = size;
        this.selected = false;
    }
    // Declare entry_list for selection procedures";
    foreach ($entry_list as $i=>$data){
        $out .= "\n\tentry_list['entry$i'] = new entry('".addslashes($data['name'])."', '".$data['type']."', '".$data['p']."', '".$data['size']."', false);";
    }
    $out .= "
    function dir_list_update_total_size(dirname,id){
        var el = document.getElementById(id);
        if (el) {
            el.innerHTML = '<div class=\"icon_loading\"></div>';
        }
        $.ajax({
            type: 'GET',
            url: '".$fm_path_info['basename']."?action=14&dirname='+encodeURIComponent(dirname)+'&fm_current_dir=".rawurlencode($fm_current_dir)."',
            dataType: 'text',
            crossDomain: false,
            success: function (data){
                dir_list_update_total_size_callback(dirname,id,data);
            },
            error: function (err){
                console.log(err);
            }
        });
    }
    function dir_list_update_total_size_callback(dirname,id,dirsize){
        for(var x=0;x<".(integer)count($entry_list).";x++){
            if(entry_list['entry'+x].name == dirname){
                entry_list['entry'+x].size = parseInt(dirsize);
                break;
            }
        }
        var el = document.getElementById(id);
        if (el) {
            if (dirsize == 'error') el.innerHTML = '<span title=\"error: too much recursion\">".et('Error')." &#x21bb</span>';
            else el.innerHTML = format_size(dirsize)+' &#x21bb';
        }
        update_footer_status();
    }
    // Select/Unselect Rows OnClick/OnMouseOver
    var lastRows = new Array(null,null);
    function selectEntry(Row, Action){
        if (multipleSelection){
            // Avoid repeated onmouseover events from same Row ( cell transition )
            if (Row != lastRows[0]){
                if (Action == 'over') {
                    if (entry_list[Row.id].selected){
                        if (unselect(entry_list[Row.id])) {
                            Row.className = 'entryUnselected';
                        }
                        // Change the last Row when you change the movement orientation
                        if (lastRows[0] != null && lastRows[1] != null){
                            var LastRowID = lastRows[0].id;
                            if (Row.id == lastRows[1].id){
                                if (unselect(entry_list[LastRowID])) {
                                    lastRows[0].className = 'entryUnselected';
                                }
                            }
                        }
                    } else {
                        if (select(entry_list[Row.id])){
                            Row.className = 'entrySelected';
                        }
                        // Change the last Row when you change the movement orientation
                        if (lastRows[0] != null && lastRows[1] != null){
                            var LastRowID = lastRows[0].id;
                            if (Row.id == lastRows[1].id){
                                if (select(entry_list[LastRowID])) {
                                    lastRows[0].className = 'entrySelected';
                                }
                            }
                        }
                    }
                    lastRows[1] = lastRows[0];
                    lastRows[0] = Row;
                }
            }
        } else {
            if (Action == 'click') {
                var newClassName = null;
                if (entry_list[Row.id].selected){
                    if (unselect(entry_list[Row.id])) newClassName = 'entryUnselected';
                } else {
                    if (select(entry_list[Row.id])) newClassName = 'entrySelected';
                }
                if (newClassName) {
                    lastRows[0] = lastRows[1] = Row;
                    Row.className = newClassName;
                }
            }
        }
        return true;
    }
    // Disable text selection and bind multiple selection flag
    var multipleSelection = false;
    if (is.ie) {
        document.onselectstart=new Function('return false');
        document.onmousedown=switch_flag_on;
        document.onmouseup=switch_flag_off;
        // Event mouseup is not generated over scrollbar.. curiously, mousedown is.. go figure.
        window.onscroll=new Function('multipleSelection=false');
        window.onresize=new Function('multipleSelection=false');
    } else {
        if (document.layers) window.captureEvents(Event.MOUSEDOWN);
        if (document.layers) window.captureEvents(Event.MOUSEUP);
        window.onmousedown=switch_flag_on;
        window.onmouseup=switch_flag_off;
    }
    // Using same function and a ternary operator couses bug on double click
    function switch_flag_on(e) {
        if (is.ie){
            multipleSelection = (event.button == 1);
        } else {
            multipleSelection = (e.which == 1);
        }
        return false;
        //var type = String(e.target.type);
        //return (type.indexOf('select') != -1 || type.indexOf('button') != -1 || type.indexOf('input') != -1 || type.indexOf('radio') != -1);
    }
    function switch_flag_off(e) {
        if (is.ie){
            multipleSelection = (event.button != 1);
        } else {
            multipleSelection = (e.which != 1);
        }
        lastRows[0] = lastRows[1] = null;
        update_footer_selection_total_status();
        return false;
    }
    var total_dirs = 0;
    var total_files = 0;
    var total_size = 0;
    var total_dirs_selected = 0;
    var total_files_selected = 0;
    var total_size_selected = 0;
    var last_entry_selected = '';
    function select(Entry){
        if(Entry.selected) return false;
        Entry.selected = true;
        last_entry_selected = Entry.name;
        document.form_action.chmod_arg.value = Entry.perms;
        update_footer_selection_total_status();
        return true;
    }
    function unselect(Entry){
        if (!Entry.selected) return false;
        Entry.selected = false;
        update_footer_selection_total_status();
        return true;
    }
    function is_anything_selected(){
        var selected_dir_list = new Array();
        var selected_file_list = new Array();
        for(var x=0;x<".(integer)count($entry_list).";x++){
            if(entry_list['entry'+x].selected){
                if(entry_list['entry'+x].type == 'dir') selected_dir_list.push(entry_list['entry'+x].name);
                else selected_file_list.push(entry_list['entry'+x].name);
            }
        }
        document.form_action.selected_dir_list.value = selected_dir_list.join('<|*|>');
        document.form_action.selected_file_list.value = selected_file_list.join('<|*|>');
        return (total_dirs_selected>0 || total_files_selected>0);
    }
    function format_size(arg) {
        var resul = '';
        if (arg>0){
            var j = 0;
            var ext = new Array(' bytes',' Kb',' Mb',' Gb',' Tb');
            while (arg >= Math.pow(1024,j)) ++j;
            resul = (Math.round(arg/Math.pow(1024,j-1)*100)/100) + ext[j-1];
        } else resul = '0 bytes';
        return resul;
    }
    function update_footer_status(){
        update_footer_total_status();
        update_footer_selection_total_status();
    }
    function update_footer_total_status(){
        total_size = 0;
        total_dirs = 0;
        total_files = 0;
        for(var x=0;x<".(integer)count($entry_list).";x++){
            if(entry_list['entry'+x].type == 'dir'){
                total_dirs++;
            } else {
                total_files++;
            }
            total_size += parseInt(entry_list['entry'+x].size);
        }
        var total_size_status = '';
        if (total_dirs) {
            total_size_status += total_dirs+' ".et('Dir_s')."';
        }
        if (total_files) {
            if (total_dirs) total_size_status += ' ".et('And')." ';
            total_size_status += total_files+' ".et('File_s')."';
        }
        if (total_size_status != '') {
            if (total_size) total_size_status += ' = '+format_size(total_size);
        }
        var el = document.getElementById('total_size_status');
        if (el) {
            el.innerHTML = '<span>'+total_size_status+'</span><br />';
            if (total_size_status != '') el.style.display='';
            else el.style.display='none';
        }
    }
    function update_footer_selection_total_status(){
        total_size_selected = 0;
        total_dirs_selected = 0;
        total_files_selected = 0;
        for(var x=0;x<".(integer)count($entry_list).";x++){
            if(entry_list['entry'+x].selected){
                if(entry_list['entry'+x].type == 'dir'){
                    total_dirs_selected++;
                } else {
                    total_files_selected++;
                }
                total_size_selected += parseInt(entry_list['entry'+x].size);
            }
        }
        var selection_total_size_status = '';
        if (total_dirs_selected) {
            selection_total_size_status += total_dirs_selected+' ".et('Dir_s')."';
        }
        if (total_files_selected) {
            if (total_dirs_selected) selection_total_size_status += ' ".et('And')." ';
            selection_total_size_status += total_files_selected+' ".et('File_s')."';
        }
        if (selection_total_size_status != '') {
            selection_total_size_status += ' ".et('Selected_s')."';
            if (total_size_selected) selection_total_size_status += ' = '+format_size(total_size_selected);
        }
        var el = document.getElementById('selection_total_size_status');
        if (el) {
            el.innerHTML = '<span>'+selection_total_size_status+'</span><br />';
            if (selection_total_size_status != '') el.style.display='';
            else el.style.display='none';
        }
        window.status = selection_total_size_status;
    }
    // Select all/none/inverse
    function selectANI(Butt){
        cancel_copy_move();
        for(var x=0;x<". (integer)count($entry_list).";x++){
            var Row = document.getElementById('entry'+x);
            var newClassName = null;
            switch (Butt.value){
                case '".et('SelAll')."':
                    if (select(entry_list[Row.id])) newClassName = 'entrySelected';
                break;
                case '".et('SelNone')."':
                    if (unselect(entry_list[Row.id])) newClassName = 'entryUnselected';
                break;
                case '".et('SelInverse')."':
                    if (entry_list[Row.id].selected){
                        if (unselect(entry_list[Row.id])) newClassName = 'entryUnselected';
                    } else {
                        if (select(entry_list[Row.id])) newClassName = 'entrySelected';
                    }
                break;
            }
            if (newClassName) {
                Row.className = newClassName;
            }
        }
        if (Butt.value == '".et('SelAll')."'){
            for(var i=0;i<2;i++){
                document.getElementById('ANI'+i).innerHTML='<i class=\"fa fa-copy-o\"></i> " . et('SelNone') . "';
                document.getElementById('ANI'+i).value='".et('SelNone')."';
            }
        } else if (Butt.value == '".et('SelNone')."'){
            for(var i=0;i<2;i++){
                document.getElementById('ANI'+i).innerHTML='<i class=\"fa fa-copy-o\"></i> " . et('SelAll') . "';
                document.getElementById('ANI'+i).value='".et('SelAll')."';
            }
        }
        update_footer_selection_total_status();
        return true;
    }
    function upload_form(){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=10&fm_current_dir=".rawurlencode($fm_current_dir)."','".et('Upload')."',true);
    }
    function edit_file_form(arg){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=7&fm_current_dir=".rawurlencode($fm_current_dir)."&filename='+encodeURIComponent(arg),'".et('Edit')." ".addslashes($fm_current_dir)."'+(arg));
    }
    function config_form(){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=2','".et('Configurations')."');
    }
    function server_info_form(arg){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=5','".et('ServerInfo')."');
    }
    function shell_form(){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=9&fm_current_dir=".rawurlencode($fm_current_dir)."','".et('Shell')."',true);
    }
    function portscan_form(){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=12','".et('Portscan')."');
    }
    function about_form(){
        toogleModalWindow('//www.dulldusk.com/phpfm/?version=".$version."','".et('About')." - ".et("FileMan")." - ".et('Version')." ".$version."');
    }
    function view_form(arg){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=4&fm_current_dir=".rawurlencode($fm_current_dir)."&filename='+encodeURIComponent(arg),'".et("View")." '+(arg));
    }
    function download_entry(arg){
        parent.frame1.location.href='".addslashes($fm_path_info['basename'])."?action=3&fm_current_dir=".rawurlencode($fm_current_dir)."&filename='+encodeURIComponent(arg);
    }
    function decompress_entry(arg){
        if(confirm('".uppercase(et('Decompress'))." \\''+arg+'\\' ?')) {
            document.form_action.action.value = 72;
            document.form_action.cmd_arg.value = arg;
            document.form_action.submit();
        }
    }
    function execute_entry(arg){
        if(confirm('".et('ConfExec')." \\''+arg+'\\' ?')) {
            toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=11&fm_current_dir=".rawurlencode($fm_current_dir)."&filename='+encodeURIComponent(arg),'".et('Exec')." '+(arg));
        }
    }
    function delete_entry(arg){
        if(confirm('".uppercase(et('Rem'))." \\''+arg+'\\' ?')) document.location.href='".addslashes($fm_path_info['basename'])."?frame=3&action=8&cmd_arg='+encodeURIComponent(arg)+'&fm_current_dir=".rawurlencode($fm_current_dir)."';
    }
    function rename_entry(arg){
        var nome = '';
        if (nome = prompt('".uppercase(et('Ren'))." \\''+arg+'\\' ".et('To')." ...',arg)) document.location.href='".addslashes($fm_path_info['basename'])."?frame=3&action=3&fm_current_dir=".rawurlencode($fm_current_dir)."&old_name='+encodeURIComponent(arg)+'&new_name='+encodeURIComponent(nome);
    }
    function set_dir_dest(arg){
        document.form_action.dir_dest.value = arg;
        if (document.form_action.action.value.length > 0) {
            test(document.form_action.action.value);
        } else {
            alert('".et('JSError').".');
        }
    }
    function sel_dir(arg){
        document.form_action.action.value = arg;
        document.form_action.dir_dest.value='';
        if (!is_anything_selected()) set_dir_list_warn('".et('NoSel')."...');
        else {
            set_dir_list_warn('".et('SelDir')."...');
            parent.frame2.set_flag(true);
        }
    }
    function set_dir_list_warn(arg){
        var el = document.getElementById(\"dir_list_warn\");
        if (el) {
            if (arg != '' && arg != false){
                el.innerHTML = arg;
                el.style.display = '';
            } else {
                el.style.display = 'none';
            }
        }
    }
    function cancel_copy_move(){
        document.form_action.action.value = 0;
        set_dir_list_warn(false);
        parent.frame2.set_flag(false);
    }
    function chmod_form(){
        cancel_copy_move();
        if (!is_anything_selected()) set_dir_list_warn('".et('NoSel')."...');
        else {
            toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=8&chmod_arg='+encodeURIComponent(document.form_action.chmod_arg.value),'".et('Perms')."');
            document.form_action.dir_dest.value='';
            document.form_action.chmod_arg.value='';
        }
    }
    function set_chmod_arg(arg){
        cancel_copy_move();
        if (!is_anything_selected()) set_dir_list_warn('".et('NoSel')."...');
        else {
            document.form_action.dir_dest.value='';
            document.form_action.chmod_arg.value=arg;
            test(9);
        }
    }
    function test_action(){
        if (document.form_action.action.value != 0) return true;
        else return false;
    }
    function test_prompt(arg){
        cancel_copy_move();
        var erro='';
        var conf='';
        if (arg == 1){
            closeModalWindow();
            document.form_action.cmd_arg.value = prompt('".et('TypeDir').".');
        } else if (arg == 2){
            closeModalWindow();
            document.form_action.cmd_arg.value = prompt('".et('TypeArq').".');
        } else if (arg == 71){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else {
                var zipname = '';
                if (last_entry_selected != '') zipname = last_entry_selected+'.zip';
                if (total_files_selected + total_dirs_selected == 1) document.form_action.cmd_arg.value = prompt('".et('TypeArqComp')."',zipname);
                else document.form_action.cmd_arg.value = prompt('".et('TypeArqComp')."');
            }
        }
        if (erro!=''){
            document.form_action.cmd_arg.focus();
            set_dir_list_warn(erro);
        } else if(document.form_action.cmd_arg.value.length>0) {
            document.form_action.action.value = arg;
            document.form_action.submit();
        }
    }
    function strstr(haystack,needle){
        var index = haystack.indexOf(needle);
        return (index==-1)?false:index;
    }
    function valid_dest(dest,orig){
        return (strstr(dest,orig)==false)?true:false;
    }
    function test(arg){
        cancel_copy_move();
        document.form_action.target='_self';
        var erro='';
        var conf='';
        if (arg == 4){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            conf = '".et('RemSel')." ?\\n';
        } else if (arg == 5){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else if(document.form_action.dir_dest.value.length == 0) erro = '".et('NoDestDir').".';
            else if(document.form_action.dir_dest.value == document.form_action.fm_current_dir.value) erro = '".et('DestEqOrig').".';
            else if(!valid_dest(document.form_action.dir_dest.value,document.form_action.fm_current_dir.value)) erro = '".et('InvalidDest').".';
            conf = '".et('CopyTo')." \\' '+document.form_action.dir_dest.value+' \\' ?\\n';
        } else if (arg == 6){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else if(document.form_action.dir_dest.value.length == 0) erro = '".et('NoDestDir').".';
            else if(document.form_action.dir_dest.value == document.form_action.fm_current_dir.value) erro = '".et('DestEqOrig').".';
            else if(!valid_dest(document.form_action.dir_dest.value,document.form_action.fm_current_dir.value)) erro = '".et('InvalidDest').".';
            conf = '".et('MoveTo')." \\' '+document.form_action.dir_dest.value+' \\' ?\\n';
        } else if (arg == 121 || arg == 122){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else if(document.form_action.dir_dest.value.length == 0) erro = '".et('NoDestDir').".';
            else if(!valid_dest(document.form_action.dir_dest.value,document.form_action.fm_current_dir.value)) erro = '".et('InvalidDest').".';
            var total_selected = 0;
            var entry_name = '';
            conf = '';
            for(var x=0;x<".(integer)count($entry_list).";x++){
                if(entry_list['entry'+x].selected){
                    total_selected++;
                    if (entry_name == '') entry_name = entry_list['entry'+x].name;
                    conf += document.form_action.dir_dest.value+entry_list['entry'+x].name+' 🡺 ".addslashes($fm_current_dir)."'+entry_list['entry'+x].name+'\\n';
                }
            }
            if (total_selected == 1) {
                var link_name = prompt('Enter the Symlink name.',entry_name);
                if (link_name === null) {
                    cancel_copy_move();
                    return;
                }
                link_name = String(link_name).trim();
                if (link_name.length == 0) {
                    cancel_copy_move();
                    return;
                }
                document.form_action.cmd_arg.value = link_name;
                conf = document.form_action.dir_dest.value+link_name+' 🡺 ".addslashes($fm_current_dir)."'+entry_name+'\\n';
                if (arg == 121) conf = 'Create Symlink ?\\n'+conf;
                else conf = 'Create Hardlink ?\\n'+conf;
            } else {
                document.form_action.cmd_arg.value = '';
                if (arg == 121) conf = 'Create Symlinks ?\\n'+conf;
                else conf = 'Create Hardlinks ?\\n'+conf;
            }
        } else if (arg == 9){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else if(document.form_action.chmod_arg.value.length == 0) erro = '".et('NoNewPerm').".';
            //conf = '".et('AlterPermTo')." \\''+document.form_action.chmod_arg.value+'\\' ?\\n';
        } else if (arg == 73){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else document.form_action.target='frame1';
        }
        if (erro!=''){
            set_dir_list_warn(erro);
        } else if(conf!='') {
            if(confirm(conf)) {
                document.form_action.action.value = arg;
                document.form_action.submit();
            } else {
                set_dir_list_warn(false);
            }
        } else {
            document.form_action.action.value = arg;
            document.form_action.submit();
        }
    }
    //-->
    </script>";
    $out .= "
    <table class=\"table\">
        <tr style=\"border-bottom: 2px solid #eaeaea;\">
        <td bgcolor=\"#DDDDDD\" colspan=50><nobr>
        <form action=\"".$fm_path_info['basename']."\" method=\"post\" onsubmit=\"return test_action();\">
            <div class=\"float-left\">
                <button type=\"button\" class=\"btn\" onclick=\"config_form()\"><i class=\"fa fa-settings\"></i> " . et('Config') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"server_info_form()\" value=\"" . et('ServerInfo') . "\"><i class=\"fa fa-lunix\"></i> " . et('ServerInfo') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"test_prompt(1)\" value=\"" . et('CreateDir') . "\"> <i class=\"fa fa-folder\"></i> ".et('CreateDir')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"test_prompt(2)\" value=\"" . et('CreateArq') . "\"> <i class=\"fa fa-add-file\"></i> ".et('CreateArq')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"upload_form()\" value=\"" . et('Upload') . "\"><i class=\"fa fa-upload\"></i> " . et('Upload') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"shell_form()\" value=\"" . et('Shell') . "\"><i class=\"fa fa-file-go\"></i> " . et('Shell') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"portscan_form()\" value=\"" . et('Portscan') . "\"><i class=\"fa fa-find\"></i> " . et('Portscan') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"resolve_ids()\" value=\"" . et('ResolveIDs') . "\"><i class=\"fa fa-resolve\"></i> " . et('ResolveIDs') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"about_form()\" value=\"".et('About')."\"><i class=\"fa fa-glob\"></i> ".et('About')."</button>
            </div>
        </form>
        </nobr>
        </td>
        </tr>";
    $out .= "
    <form name=\"form_action\" action=\"".$fm_path_info['basename']."\" method=\"post\" onsubmit=\"return test_action();\">
        <input type=hidden name=\"frame\" value=3>
        <input type=hidden name=\"action\" value=0>
        <input type=hidden name=\"dir_dest\" value=\"\">
        <input type=hidden name=\"chmod_arg\" value=\"\">
        <input type=hidden name=\"cmd_arg\" value=\"\">
        <input type=hidden name=\"fm_current_dir\" value=\"$fm_current_dir\">
        <input type=hidden name=\"dir_before\" value=\"$dir_before\">
        <input type=hidden name=\"selected_dir_list\" value=\"\">
        <input type=hidden name=\"selected_file_list\" value=\"\">";
    function get_breadcrumbs($path){
        $entry_list = explode(DIRECTORY_SEPARATOR, rtrim($path,DIRECTORY_SEPARATOR));
        $uplink = '';
        if (count($entry_list) == 1){
            $breadcrumbs = '<a href="'.$fm_path_info['basename'].'?frame=3&fm_current_dir='.rawurlencode($path).'">'.$path.'</a>';;
        } else {
            $breadcrumbs = array();
            for($x=0;$x<count($entry_list);$x++){
                $entry_path = strstr(rtrim($path,DIRECTORY_SEPARATOR), $entry_list[$x], true).$entry_list[$x].DIRECTORY_SEPARATOR;
                $breadcrumbs[] = '<a href="'.$fm_path_info['basename'].'?frame=3&fm_current_dir='.rawurlencode($entry_path).'">'.$entry_list[$x].'</a>';
                if ($x<count($entry_list)-1) $uplink .= $entry_list[$x].DIRECTORY_SEPARATOR;
            }
            $breadcrumbs = implode('<i class="bdc-link">'.DIRECTORY_SEPARATOR.'</i>',$breadcrumbs);
        }
        if (strlen($uplink)) $uplink = "<a href=\"".$fm_path_info['basename']."?frame=3&fm_current_dir=".rawurlencode($uplink)."\">🡹</a>&nbsp;&nbsp;";
        return $uplink.$breadcrumbs;
    }
    function get_link_breadcrumbs($path){
        $out = '';
        if (is_link(rtrim($path,DIRECTORY_SEPARATOR))){
            $target = readlink(rtrim($path,DIRECTORY_SEPARATOR));
            $target_absolute_path = readlink_absolute_path(rtrim($path,DIRECTORY_SEPARATOR));
            if (is_dir($target_absolute_path)){
                $breadcrumbs = array();
                foreach (explode(DIRECTORY_SEPARATOR, $target_absolute_path) as $r) {
                    $breadcrumbs[] = '<a href="'.$fm_path_info['basename'].'?frame=3&fm_current_dir='.strstr($target_absolute_path, $r, true).$r.DIRECTORY_SEPARATOR.'">'.$r.'</a>';
                }
                if (count($breadcrumbs)){
                    $out .= '&nbsp;<b>(L)</b>&nbsp;&nbsp;🡺&nbsp;&nbsp;'.implode('<i class="bdc-link">'.DIRECTORY_SEPARATOR.'</i>',$breadcrumbs);
                }
                if (is_link($target_absolute_path)){
                    $out .= get_link_breadcrumbs($target_absolute_path);
                }
            }
        }
        return $out;
    }
    $out .= "
    <tr bgcolor=\"#DDDDDD\" style=\"border-bottom: 2px solid #eaeaea;\"><td style=\"padding:8px;\" colspan=50><nobr>";;
    $out .= get_breadcrumbs($fm_current_dir);
    $out .= get_link_breadcrumbs($fm_current_dir);
    $out .= "</nobr></td></tr>";
    if (!$io_error) {
        if($entry_count){
            $out .= "
                <tr style=\"border-bottom: 2px solid #d4d2d2;\">
                <td bgcolor=\"#DDDDDD\" colspan=50><nobr>
                <button type=\"button\" class=\"btn\" onclick=\"selectANI(this)\" id=\"ANI0\" value=\"".et('SelAll')."\"><i class=\"fa fa-copy-o\"></i> " . et('SelAll') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"selectANI(this)\" value=\"".et('SelInverse')."\"><i class=\"fa fa-file-light\"></i> " . et('SelInverse') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"test(4)\"><i class=\"fa fa-file-remove\"></i> " . et('Rem') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"sel_dir(5)\"><i class=\"fa fa-copy\"></i> " . et('Copy') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"sel_dir(6)\"><i class=\"fa fa-file-go\"></i> " . et('Move') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"test_prompt(71)\"><i class=\"fa fa-file-archive-o\"></i> " . et('Compress') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"test(73)\"><i class=\"fa fa-download\"></i> ZIP " . et('Download') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"sel_dir(121)\" value=\"" . et('Symlink') . "\"> <i class=\"fa fa-link\"></i> ".et('Symlink')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"sel_dir(122)\" value=\"" . et('HardLink') . "\"> <i class=\"fa fa-link\"></i> ".et('HardLink')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"chmod_form()\" value=\"" . et('Perms') . "\"><i class=\"fa fa-perms\"></i> " . et('Perms') . "</button>
                </nobr></td>
                </tr>
                <tr>
                <td colspan=50 id=\"dir_list_warn\" class=\"alert alert-danger\" style=\"padding:8px;display:none;\"></td>
                </tr>";
            $dir_count = 0;
            $dir_out = array();
            $file_count = 0;
            $file_out = array();
            $max_cells = 0;
            foreach ($entry_list as $ind=>$dir_entry) {
                $file = $dir_entry['name'];
                if ($dir_entry['type'] == "dir") {
                    $dir_out[$dir_count] = array();
                    $dir_out[$dir_count][] = "
                        <tr ID=\"entry$ind\" class=\"entryUnselected\" onmouseover=\"selectEntry(this, 'over');\" onmousedown=\"selectEntry(this, 'click');\">
                        <td class=\"sm\">
                            <table class=\"entry_name_table\">
                            <tr>
                                <td width=\"1\"><span class=\"fa fa-folder\"></span></td>
                                <td class=\"entry_name\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"Javascript:go_dir_list('".addslashes($file)."')\">".utf8_convert($dir_entry['namet'])."</a></td>
                                <td align=\"right\">".utf8_convert($dir_entry['linkt'])."</td>
                            </tr>
                            </table>
                        </td>";
                    $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['p']."</td>";
                    if (!$is_windows) {
                        $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['u']."</nobr></td>";
                        $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['g']."</nobr></td>";
                    }
                    $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['sizet']."</nobr></td>";
                    $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['datet']."</nobr></td>";
                    if ($has_files) $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>Folder</td>";
                    // Directory Actions
                    if ( is_writable($fm_current_dir.$file) ) $dir_out[$dir_count][] = "
                        <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:delete_entry('".addslashes($file)."')\">".et('Rem')."</a></td>";
                    else $dir_out[$dir_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_writable($fm_current_dir.$file) ) $dir_out[$dir_count][] = "
                        <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"Javascript:rename_entry('".addslashes($file)."')\">".et('Ren')."</a></td>";
                    else $dir_out[$dir_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( count($dir_out[$dir_count]) > $max_cells ){
                        $max_cells = count($dir_out[$dir_count]);
                    }
                    $dir_count++;
                } elseif ($dir_entry['type'] == "file") {
                    $file_out[$file_count] = array();
                    $file_out[$file_count][] = "
                        <tr ID=\"entry$ind\" class=\"entryUnselected\" onmouseover=\"selectEntry(this, 'over');\" onmousedown=\"selectEntry(this, 'click');\">
                        <td class=\"sm\">
                            <table class=\"entry_name_table\">
                            <tr>
                                <td width=\"1\"><span class=\"".get_file_icon_class($fm_path_info['basename'].$file)."\"></span></td>
                                <td class=\"entry_name\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"Javascript:download_entry('".addslashes($file)."')\">".utf8_convert($dir_entry['namet'])."</a></td>
                                <td align=\"right\">".utf8_convert($dir_entry['linkt'])."</td>
                            </tr>
                            </table>
                        </td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['p']."</td>";
                    if (!$is_windows) {
                        $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['u']."</nobr></td>";
                        $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['g']."</nobr></td>";
                    }
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['sizet']."</nobr></td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['datet']."</nobr></td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['extt']."</td>";
                    // File Actions
                    if ( is_writable($fm_current_dir.$file) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:delete_entry('".addslashes($file)."')\">".et('Rem')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_writable($fm_current_dir.$file) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:rename_entry('".addslashes($file)."')\">".et('Ren')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_readable($fm_current_dir.$file) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:edit_file_form('".addslashes($file)."')\">".et('Edit')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_readable($fm_current_dir.$file) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:view_form('".addslashes($file)."');\">".et('View')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_readable($fm_current_dir.$file) && strlen($dir_entry['ext']) && (strpos(".tar#.zip#.bz2#.tbz2#.bz#.tbz#.bzip#.gzip#.gz#.tgz#", $dir_entry['ext']."#" ) !== false) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:decompress_entry('".addslashes($file)."')\">".et('Decompress')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_executable($fm_current_dir.$file) || (strlen($dir_entry['ext']) && (strpos(".exe#.com#.bat#.sh#.py#.pl", $dir_entry['ext']."#" ) !== false)) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:execute_entry('".addslashes($file)."')\">".et('Exec')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    //$file_out[$file_count][] = "<td class=\"sm\">".(is_readable_phpfm($fm_current_dir.$file)?'<font color=green>R</font>':'<font color=red>R</font>').(is_writable_phpfm($fm_current_dir.$file)?'<font color=green>W</font>':'<font color=red>W</font>').(is_executable_phpfm($fm_current_dir.$file)?'<font color=green>X</font>':'<font color=red>X</font>')."</td>";
                    if (count($file_out[$file_count])>$max_cells){
                        $max_cells = count($file_out[$file_count]);
                    }
                    $file_count++;
                } elseif ($dir_entry['type'] == "broken_link") {
                    $file_out[$file_count] = array();
                    $file_out[$file_count][] = "
                        <tr ID=\"entry$ind\" class=\"entryUnselected\" onmouseover=\"selectEntry(this, 'over');\" onmousedown=\"selectEntry(this, 'click');\">
                        <td class=\"sm\">
                            <table class=\"entry_name_table\">
                            <tr>
                                <td width=\"1\"><span class=\"".get_file_icon_class($fm_path_info['basename'].$file)."\"></span></td>
                                <td class=\"entry_name\"><font color=\"red\"><b>".utf8_convert($dir_entry['namet'])."</b></font></td>
                                <td align=\"right\"><font color=\"red\"><b>".utf8_convert($dir_entry['linkt'])."</b></font></td>
                            </tr>
                            </table>
                        </td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['p']."</td>";
                    if (!$is_windows) {
                        $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['u']."</nobr></td>";
                        $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['g']."</nobr></td>";
                    }
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['sizet']."</nobr></td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['datet']."</nobr></td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['extt']."</td>";
                    // File Actions
                    $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:delete_entry('".addslashes($file)."')\">".et('Rem')."</a></td>";
                    $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:rename_entry('".addslashes($file)."')\">".et('Ren')."</a></td>";
                    if (count($file_out[$file_count])>$max_cells){
                        $max_cells = count($file_out[$file_count]);
                    }
                    $file_count++;
                }
            }
            $out .= "
            <tr>
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or1&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Name')."</a></nobr></th>
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or2&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Perm')."</a></nobr></th>";
            if (!$is_windows) $out .= "
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or3&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Owner')."</a></th>
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or4&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Group')."</a></nobr></th>";
            $out .= "
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or5&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Size')."</a></nobr></th>
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or6&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Date')."</a></nobr></th>";
            if ($file_count) $out .= "
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or7&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Type')."</a></nobr></th>";
            $out .= "
                  <th colspan=50>&nbsp;</nobr></th>
            </tr>";
            $max_cells++;
            foreach($dir_out as $k=>$v){
                while (count($dir_out[$k])<$max_cells) {
                    $dir_out[$k][] = "<td>&nbsp;</td>";
                }
            }
            foreach($file_out as $k=>$v){
                while (count($file_out[$k])<$max_cells) {
                    $file_out[$k][] = "<td>&nbsp;</td>";
                }
            }
            $all_out = array_merge($dir_out,$file_out);
            foreach($all_out as $k=>$v){
                $out .= implode('',$all_out[$k]);
                $out .= "</tr>";
            }
            $out .= "
                <tr>
                <td bgcolor=\"#DDDDDD\" colspan=50><nobr>
                    <button type=\"button\" class=\"btn\" onclick=\"selectANI(this)\" id=\"ANI1\" value=\"".et('SelAll')."\"><i class=\"fa fa-copy-o\"></i> " . et('SelAll') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"selectANI(this)\" value=\"".et('SelInverse')."\"><i class=\"fa fa-file-light\"></i> " . et('SelInverse') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test(4)\"><i class=\"fa fa-file-remove\"></i> " . et('Rem') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"sel_dir(5)\"><i class=\"fa fa-copy\"></i> " . et('Copy') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"sel_dir(6)\"><i class=\"fa fa-file-go\"></i> " . et('Move') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test_prompt(71)\"><i class=\"fa fa-file-archive-o\"></i> " . et('Compress') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test(73)\"><i class=\"fa fa-download\"></i> ZIP " . et('Download') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test_prompt(121)\" value=\"" . et('Symlink') . "\"> <i class=\"fa fa-link\"></i> ".et('Symlink')."</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test_prompt(122)\" value=\"" . et('HardLink') . "\"> <i class=\"fa fa-link\"></i> ".et('HardLink')."</button>
                    <button type=\"button\" class=\"btn\" onclick=\"chmod_form()\" value=\"" . et('Perms') . "\"><i class=\"fa fa-perms\"></i> " . et('Perms') . "</button>
                </nobr></td>
                </tr>";
            $out .= "
            </form>";
        } else {
            $out .= "
            <tr><td colspan=50 style=\"padding:8px;\">".et('EmptyDir').".</tr>";
        }
    } else {
        $out .= "
        <tr><td colspan=50 style=\"padding:8px;\"><font color=red>".et('IOError').".<br>".rtrim($fm_current_dir,DIRECTORY_SEPARATOR)."</font></tr>";
    }
    $out .= "
        <tr style=\"border-top: 2px solid #eaeaea;\">
        <td bgcolor=\"#DDDDDD\" colspan=50 class=\"fm-disk-info\">
            <div style=\"float:left;\">
                <div id=\"total_size_status\" display=\"none\"></div>
                <div id=\"selection_total_size_status\" display=\"none\"></div>";
                if ($quota_mb) {
                    $out .= "
                    <span>".et('Partition')." = ".format_size(($quota_mb*1024*1024))." - ".format_size(($quota_mb*1024*1024)-intval(phpfm_get_total_size($fm_current_root)))." ".et('Free')."</span>";
                } else {
                    $out .= "
                    <span>".et('Partition')." = ".format_size(disk_total_space($fm_current_dir))." / ".format_size(disk_free_space($fm_current_dir))." ".et('Free')."</span>";
                }
                /*
                $out .= "
                    <br /><span>".et('RenderTime').": ".number_format((getmicrotime()-$script_init_time), 3, '.', '')." ".et('Seconds')."</span>";
                */
                $out .= "
            </div>
            <div style=\"float:right\">
                <span>".date_default_timezone_get()."</span><br />
                <span>".date($date_format)."</span>
            </div>
        </td></tr>
    </table>";
    $out .= "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        update_footer_status();
        set_dir_list_warn('".addslashes($GLOBALS['dir_list_warn_message'])."');
    //-->
    </script>";
    echo $out;
}
function upload_form(){
    global $_FILES,$fm_current_dir,$dir_dest,$quota_mb,$fm_path_info;
    html_header();
    echo "<body marginwidth=\"0\" marginheight=\"0\">";
    if (count($_FILES)==0){
        echo "
        <table height=\"100%\" border=0 cellspacing=0 cellpadding=2 style=\"padding:5px;\">
        <form name=\"upload_form\" action=\"".$fm_path_info['basename']."\" method=\"post\" ENCTYPE=\"multipart/form-data\">
        <input type=hidden name=dir_dest value=\"".$fm_current_dir."\">
        <input type=hidden name=action value=10>
        <tr><td colspan=2 align=left><nobr><b>".et('Destination').": ".$fm_current_dir."</b></nobr></td></tr>
        <tr><td width=1 align=right><b>".et('File_s').":<td><nobr><input type=\"file\" id=\"upfiles\" name=\"upfiles[]\" multiple onchange=\"upfiles_update(this);\"></nobr></td></tr>
        <tr><td colspan=2 align=left><div id=\"upfileslist\"></div></td></tr>
        <tr><td colspan=2 align=left id=\"upload_warn\"><button type=\"button\" class=\"btn\" onclick=\"upfiles_send()\" value=\"".et('Send')."\"><i class=\"fa fa-upload\"></i> ".et('Send')."</button></td></tr>
        </form>
        </table>
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            var busy = false;
            var selected_files = [];
            function upfiles_update(fileinput){
                selected_files = document.getElementById(\"upfiles\").files;
                var text = '';
                if (selected_files.length > 0) {
                    for (var i = 0; i < selected_files.length; i++) {
                        text += '<nobr>' + (i+1) + ' - ' + selected_files[i].name + '</nobr><br>';
                    }
                }
                var el = document.getElementById('upfileslist');
                if (el) {
                    el.innerHTML = text;
                }
            }
            function upfiles_send(){
                if(selected_files.length > 0){
                    if (!busy) {
                        busy = true;
                        var el = document.getElementById('upload_warn');
                        if (el) {
                            el.innerHTML = '<div class=\"icon_loading\"></div>';
                        }
                        document.upload_form.submit();
                    }
                } else {
                    alert('".et('NoFileSel').".');
                }
            }
        //-->
        </script>";
    } else {
        $out = "<tr><td colspan=2 align=left><nobr><b>".et('Destination').": ".$fm_current_dir."</b></nobr></td></tr>";
        $files = array();
        if (is_array($_FILES['upfiles'])){
            // Check and re-arrange multi-upload array()
            if (is_array($_FILES['upfiles']['name'])){
                for($i=0;$i<count($_FILES['upfiles']['name']);$i++){
                    if ($_FILES['upfiles']['error'][$i] === 0) $files[] = array(
                        'name' => $_FILES['upfiles']['name'][$i],
                        'tmp_name' => $_FILES['upfiles']['tmp_name'][$i],
                        'size' => $_FILES['upfiles']['size'][$i],
                        'type' => $_FILES['upfiles']['type'][$i],
                        'error' => $_FILES['upfiles']['error'][$i]
                    );
                }
            } else {
                foreach ($_FILES['upfiles'] as $file){
                    if ($file['error'] === 0) $files[] = $file;
                }
            }
        }
        $i=1;
        foreach ($files as $file) {
            $filename = $file['name'];
            $temp_file = $file['tmp_name'];
            if (strlen($filename)) {
                $resul = save_upload($temp_file,$filename,$dir_dest);
                switch($resul){
                    case 1:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=green>".et('FileSent')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 2:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=red>".et('IOError')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 3:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=red>".et('SpaceLimReached')." ($quota_mb Mb)</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 4:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=red>".et('InvExt')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 5:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=red>".et('FileNoOverw')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 6:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=green>".et('FileOverw')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    default:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=green>".et('FileIgnored')."</font>:</td><td>".$filename."</td></tr>\n";
                }
                $i++;
            }
        }
        $out .= "<tr><td colspan=2 align=left><nobr><b>".et('UploadEnd')."</b></nobr></td></tr>";
        echo "<table height=\"100%\" border=0 cellspacing=0 cellpadding=2 style=\"padding:5px;\">".$out."</table>";
    }
    echo "</body>\n</html>";
}
function chmod_form(){
    global $chmod_arg;
    if (!intval($chmod_arg)) $chmod_arg = '0755';
    html_header("
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        function octalchange() {
            var val = document.chmod_form.t_total.value;
            var stickybin = parseInt(val.charAt(0)).toString(2);
            var ownerbin = parseInt(val.charAt(1)).toString(2);
            while (ownerbin.length<3) { ownerbin=\"0\"+ownerbin; };
            var groupbin = parseInt(val.charAt(2)).toString(2);
            while (groupbin.length<3) { groupbin=\"0\"+groupbin; };
            var otherbin = parseInt(val.charAt(3)).toString(2);
            while (otherbin.length<3) { otherbin=\"0\"+otherbin; };
            document.chmod_form.sticky.checked = parseInt(stickybin.charAt(0));
            document.chmod_form.owner4.checked = parseInt(ownerbin.charAt(0));
            document.chmod_form.owner2.checked = parseInt(ownerbin.charAt(1));
            document.chmod_form.owner1.checked = parseInt(ownerbin.charAt(2));
            document.chmod_form.group4.checked = parseInt(groupbin.charAt(0));
            document.chmod_form.group2.checked = parseInt(groupbin.charAt(1));
            document.chmod_form.group1.checked = parseInt(groupbin.charAt(2));
            document.chmod_form.other4.checked = parseInt(otherbin.charAt(0));
            document.chmod_form.other2.checked = parseInt(otherbin.charAt(1));
            document.chmod_form.other1.checked = parseInt(otherbin.charAt(2));
            calc_chmod(1);
        };
        function calc_chmod(nototals) {
            var users = new Array(\"owner\", \"group\", \"other\");
            var totals = new Array(\"\",\"\",\"\");
            var syms = new Array(\"\",\"\",\"\");
            for (var i=0; i<users.length; i++) {
                var user=users[i];
                var field4 = user + \"4\";
                var field2 = user + \"2\";
                var field1 = user + \"1\";
                var symbolic = \"sym_\" + user;
                var number = 0;
                var sym_string = \"\";
                var sticky = \"0\";
                var sticky_sym = \" \";
                if (document.chmod_form.sticky.checked){
                    sticky = \"1\";
                    sticky_sym = \"t\";
                }
                if (document.chmod_form[field4].checked == true) { number += 4; }
                if (document.chmod_form[field2].checked == true) { number += 2; }
                if (document.chmod_form[field1].checked == true) { number += 1; }
                if (document.chmod_form[field4].checked == true) {
                    sym_string += \"r\";
                } else {
                    sym_string += \"-\";
                }
                if (document.chmod_form[field2].checked == true) {
                    sym_string += \"w\";
                } else {
                    sym_string += \"-\";
                }
                if (document.chmod_form[field1].checked == true) {
                    sym_string += \"x\";
                } else {
                    sym_string += \"-\";
                }
                totals[i] = totals[i]+number;
                syms[i] =  syms[i]+sym_string;
            }
            if (!nototals) document.chmod_form.t_total.value = sticky + totals[0] + totals[1] + totals[2];
            document.chmod_form.sym_total.value = syms[0] + syms[1] + syms[2] + sticky_sym;
        }
        function sticky_change() {
            document.chmod_form.sticky.checked = !(document.chmod_form.sticky.checked);
        }
        function apply_chmod() {
            if (confirm('".et('AlterPermTo')." \\' '+document.chmod_form.t_total.value+' \\' ?\\n')){
                window.parent.parent.frame3.set_chmod_arg(document.chmod_form.t_total.value);
                window.parent.parent.frame3.closeModalWindow();
            }
        }
        window.onload=octalchange
    //-->
    </script>");
    echo "
    <body marginwidth=\"0\" marginheight=\"0\" style=\"overflow: hidden;\">
        <div style=\"-ms-transform:scale(1.5); transform: scale(1.5) translate(0, 50px);\">
            <form name=\"chmod_form\">
                <table border=\"0\" cellspacing=\"0\" cellpadding=\"4\" align=center style=\"padding:5px;\">
                    <tr align=\"left\" valign=\"middle\">
                        <td><input type=\"text\" name=\"t_total\" value=\"".html_encode($chmod_arg)."\" size=\"4\" onKeyUp=\"octalchange()\"> </td>
                        <td><input type=\"text\" name=\"sym_total\" value=\"\" size=\"12\" readonly></td>
                    </tr>
                </table>
                <table cellpadding=\"2\" cellspacing=\"0\" border=\"0\" align=center>
                    <tr bgcolor=\"#333333\">
                        <td width=\"60\" align=\"left\"> </td>
                        <td width=\"55\" align=\"center\" style=\"color:#FFFFFF\"><b>".et('Owner')."</b></td>
                        <td width=\"55\" align=\"center\" style=\"color:#FFFFFF\"><b>".et('Group')."</b></td>
                        <td width=\"55\" align=\"center\" style=\"color:#FFFFFF\"><b>".et('Other')."<b></td>
                    </tr>
                    <tr bgcolor=\"#DDDDDD\">
                        <td width=\"60\" align=\"left\" nowrap bgcolor=\"#FFFFFF\">".et('Read')."</td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"owner4\" value=\"4\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#FFFFFF\"><input type=\"checkbox\" name=\"group4\" value=\"4\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"other4\" value=\"4\" onclick=\"calc_chmod()\"></td>
                    </tr>
                    <tr bgcolor=\"#DDDDDD\">
                        <td width=\"60\" align=\"left\" nowrap bgcolor=\"#FFFFFF\">".et('Write')."</td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"owner2\" value=\"2\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#FFFFFF\"><input type=\"checkbox\" name=\"group2\" value=\"2\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"other2\" value=\"2\" onclick=\"calc_chmod()\"></td>
                    </tr>
                    <tr bgcolor=\"#DDDDDD\">
                        <td width=\"60\" align=\"left\" nowrap bgcolor=\"#FFFFFF\">".et('Exec')."</td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"owner1\" value=\"1\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#FFFFFF\"><input type=\"checkbox\" name=\"group1\" value=\"1\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"other1\" value=\"1\" onclick=\"calc_chmod()\"></td>
                    </tr>
                </table>
                <table border=\"0\" cellspacing=\"0\" cellpadding=\"4\" align=center>
                    <tr><td colspan=2><input type=checkbox name=sticky value=\"1\" onclick=\"calc_chmod()\"> <a href=\"JavaScript:sticky_change();\">".et('StickyBit')."</a><td colspan=2 align=right><input type=button value=\"".et('Apply')."\" onClick=\"apply_chmod()\"></tr>
                </table>
            </form>
        </div>
    </body>
    </html>";
}
function get_mime_type($ext = ''){
    $mimes = array(
      'hqx'   =>  'application/mac-binhex40',
      'cpt'   =>  'application/mac-compactpro',
      'doc'   =>  'application/msword',
      'bin'   =>  'application/macbinary',
      'dms'   =>  'application/octet-stream',
      'lha'   =>  'application/octet-stream',
      'lzh'   =>  'application/octet-stream',
      'exe'   =>  'application/octet-stream',
      'class' =>  'application/octet-stream',
      'psd'   =>  'application/octet-stream',
      'so'    =>  'application/octet-stream',
      'sea'   =>  'application/octet-stream',
      'dll'   =>  'application/octet-stream',
      'oda'   =>  'application/oda',
      'pdf'   =>  'application/pdf',
      'ai'    =>  'application/postscript',
      'eps'   =>  'application/postscript',
      'ps'    =>  'application/postscript',
      'smi'   =>  'application/smil',
      'smil'  =>  'application/smil',
      'mif'   =>  'application/vnd.mif',
      'xls'   =>  'application/vnd.ms-excel',
      'ppt'   =>  'application/vnd.ms-powerpoint',
      'pptx'  =>  'application/vnd.ms-powerpoint',
      'wbxml' =>  'application/vnd.wap.wbxml',
      'wmlc'  =>  'application/vnd.wap.wmlc',
      'dcr'   =>  'application/x-director',
      'dir'   =>  'application/x-director',
      'dxr'   =>  'application/x-director',
      'dvi'   =>  'application/x-dvi',
      'gtar'  =>  'application/x-gtar',
      'php'   =>  'application/x-httpd-php',
      'php4'  =>  'application/x-httpd-php',
      'php3'  =>  'application/x-httpd-php',
      'phtml' =>  'application/x-httpd-php',
      'phps'  =>  'application/x-httpd-php-source',
      'js'    =>  'application/x-javascript',
      'swf'   =>  'application/x-shockwave-flash',
      'sit'   =>  'application/x-stuffit',
      'tar'   =>  'application/x-tar',
      'tgz'   =>  'application/x-tar',
      'xhtml' =>  'application/xhtml+xml',
      'xht'   =>  'application/xhtml+xml',
      'zip'   =>  'application/zip',
      'mid'   =>  'audio/midi',
      'midi'  =>  'audio/midi',
      'mpga'  =>  'audio/mpeg',
      'mp2'   =>  'audio/mpeg',
      'mp3'   =>  'audio/mpeg',
      'aif'   =>  'audio/x-aiff',
      'aiff'  =>  'audio/x-aiff',
      'aifc'  =>  'audio/x-aiff',
      'ram'   =>  'audio/x-pn-realaudio',
      'rm'    =>  'audio/x-pn-realaudio',
      'rpm'   =>  'audio/x-pn-realaudio-plugin',
      'ra'    =>  'audio/x-realaudio',
      'rv'    =>  'video/vnd.rn-realvideo',
      'wav'   =>  'audio/x-wav',
      'bmp'   =>  'image/bmp',
      'gif'   =>  'image/gif',
      'jpeg'  =>  'image/jpeg',
      'jpg'   =>  'image/jpeg',
      'jpe'   =>  'image/jpeg',
      'png'   =>  'image/png',
      'tiff'  =>  'image/tiff',
      'tif'   =>  'image/tiff',
      'css'   =>  'text/css',
      'html'  =>  'text/html',
      'htm'   =>  'text/html',
      'shtml' =>  'text/html',
      'txt'   =>  'text/plain',
      'text'  =>  'text/plain',
      'log'   =>  'text/plain',
      'rtx'   =>  'text/richtext',
      'rtf'   =>  'text/rtf',
      'xml'   =>  'text/xml',
      'xsl'   =>  'text/xml',
      'mpeg'  =>  'video/mpeg',
      'mpg'   =>  'video/mpeg',
      'mpe'   =>  'video/mpeg',
      'qt'    =>  'video/quicktime',
      'mov'   =>  'video/quicktime',
      'avi'   =>  'video/x-msvideo',
      'movie' =>  'video/x-sgi-movie',
      'doc'   =>  'application/msword',
      'docx'  =>  'application/msword',
      'word'  =>  'application/msword',
      'xl'    =>  'application/excel',
      'xls'   =>  'application/excel',
      'xlsx'  =>  'application/excel',
      'eml'   =>  'message/rfc822'
    );
    return (!isset($mimes[lowercase($ext)])) ? 'application/octet-stream' : $mimes[lowercase($ext)];
}
function get_file_icon_class($path){
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    switch ($ext) {
        case 'ico':
        case 'gif':
        case 'jpg':
        case 'jpeg':
        case 'jpc':
        case 'jp2':
        case 'jpx':
        case 'xbm':
        case 'wbmp':
        case 'png':
        case 'bmp':
        case 'tif':
        case 'tiff':
        case 'svg':
            $img = 'fa fa-picture';
            break;
        case 'passwd':
        case 'ftpquota':
        case 'sql':
        case 'js':
        case 'json':
        case 'sh':
        case 'config':
        case 'twig':
        case 'tpl':
        case 'md':
        case 'gitignore':
        case 'c':
        case 'cpp':
        case 'cs':
        case 'py':
        case 'map':
        case 'lock':
        case 'dtd':
            $img = 'fa fa-code';
            break;
        case 'txt':
        case 'ini':
        case 'conf':
        case 'log':
        case 'htaccess':
            $img = 'fa fa-file-text-o';
            break;
        case 'css':
        case 'less':
        case 'sass':
        case 'scss':
            $img = 'fa fa-code-o';
            break;
        case 'gz':
        case 'bz':
        case 'zip':
        case 'gzip':
        case 'bzip':
        case 'tar':
        case 'tgz':
        case 'tbz':
        case 'rar':
        case 'lha':
        case '7z':
            $img = 'fa fa-file-archive-o';
            break;
        case 'php':
        case 'php4':
        case 'php5':
        case 'phps':
        case 'phtml':
            $img = 'fa fa-php';
            break;
        case 'htm':
        case 'html':
        case 'shtml':
        case 'xhtml':
            $img = 'fa fa-html';
            break;
        case 'xml':
        case 'xsl':
        case 'xslx':
            $img = 'fa fa-file-excel';
            break;
        case 'wav':
        case 'mp3':
        case 'mp2':
        case 'm4a':
        case 'aac':
        case 'ogg':
        case 'oga':
        case 'wma':
        case 'mka':
        case 'flac':
        case 'ac3':
        case 'tds':
        case 'm3u':
        case 'm3u8':
        case 'pls':
        case 'cue':
            $img = 'fa fa-music';
            break;
        case 'avi':
        case 'mpg':
        case 'mpeg':
        case 'mp4':
        case 'm4v':
        case 'flv':
        case 'f4v':
        case 'ogm':
        case 'ogv':
        case 'mov':
        case 'mkv':
        case '3gp':
        case 'asf':
        case 'wmv':
            $img = 'fa fa-video';
            break;
        case 'xls':
        case 'xlsx':
            $img = 'fa fa-file-excel-o';
            break;
        case 'asp':
        case 'aspx':
            $img = 'fa fa-file-aspx';
            break;
        case 'sql':
        case 'mda':
        case 'myd':
        case 'dat':
        case 'sql.gz':
            $img = 'fa fa-database';
            break;
        case 'doc':
        case 'docx':
            $img = 'fa fa-file-word';
            break;
        case 'ppt':
        case 'pptx':
            $img = 'fa fa-file-powerpoint';
            break;
        case 'ttf':
        case 'ttc':
        case 'otf':
        case 'woff':
        case 'woff2':
        case 'eot':
        case 'fon':
            $img = 'fa fa-font';
            break;
        case 'pdf':
            $img = 'fa fa-file-pdf';
            break;
        case 'psd':
        case 'ai':
        case 'eps':
        case 'fla':
        case 'swf':
            $img = 'fa fa-file-image-o';
            break;
        case 'exe':
        case 'msi':
            $img = 'fa fa-file-o';
            break;
        default:
            $img = 'fa fa-file';
    }
    return $img;
}
function view_form(){
    global $doc_root,$fm_path_info,$url_info,$fm_current_dir,$is_windows,$filename,$passthru;
    if (intval($passthru)){
        $file = $fm_current_dir.$filename;
        if(file_exists($file)){
            $is_denied = false;
            foreach($download_ext_filter as $key=>$ext){
                if (eregi($ext,$filename)){
                    $is_denied = true;
                    break;
                }
            }
            if (!$is_denied){
                if ($fh = fopen("$file", "rb")){
                    fclose($fh);
                    $ext = pathinfo($file, PATHINFO_EXTENSION);
                    $ctype = get_mime_type($ext);
                    if (strpos($ctype,"application/") !== false) $ctype = "text/plain";
                    header("Pragma: public");
                    header("Expires: 0");
                    header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
                    header("Cache-Control: public");
                    header("Content-Type: ".$ctype);
                    header("Content-Disposition: inline; filename=\"".pathinfo($file, PATHINFO_BASENAME)."\";");
                    header("Content-Transfer-Encoding: binary");
                    header("Content-Length: ".phpfm_filesize($file));
                    @readfile($file);
                    exit();
                } else echo(et('ReadDenied').": ".$file);
            } else echo(et('ReadDenied').": ".$file);
        } else echo(et('FileNotFound').": ".$file);
    } else {
        html_header();
        echo "<body marginwidth=\"0\" marginheight=\"0\" style=\"height:100%; background-color:#fff;\">";
        $title = et("View").' '.addslashes($filename);
        $is_reachable_thru_webserver = (stristr($fm_current_dir,$doc_root)!==false);
        if ($is_reachable_thru_webserver){
            $url  = $url_info['scheme']."://".$url_info['host'];
            if (strlen($url_info['port'])) $url .= ":".$url_info['port'];
            $url .= str_replace(DIRECTORY_SEPARATOR,'/',str_replace($doc_root,'',$fm_current_dir));
            $url .= $filename;
            $title = et("View").' '.$url;
        } else {
            $url  = addslashes($fm_path_info['basename']);
            $url .= "?action=4&fm_current_dir=".rawurlencode($fm_current_dir)."&filename=".rawurldecode($filename)."&passthru=1";
            $title = et("View").' '.addslashes($fm_current_dir.$filename);
        }
        //fb_log('url',$url);
        echo "
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            var el = window.parent.document.getElementById(\"modalIframeWrapperTitle\");
            if (el) el.innerHTML = \"".html_encode($title)."\";
            document.location.href = '".$url."';
        //-->
        </script>";
        echo "
        </body>\n</html>";
    }
}
function ace_mode_autodetect($file){
    $mode = 'plain_text';
    $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    switch ($extension){
        case 'html':
        case 'htm':
            $mode = 'html';
        break;
        case 'css':
            $mode = 'css';
        break;
        case 'php':
        case 'php3':
        case 'php4':
        case 'php5':
        case 'php6':
        case 'php7':
        case 'phps':
            $mode = 'php';
        break;
        case 'js':
            $mode = 'javascript';
        break;
        case 'sh':
        case 'bash':
            $mode = 'batchfile';
        break;
        case 'py':
            $mode = 'python';
        break;
        case 'c':
        case 'cpp':
            $mode = 'c_cpp';
        break;
        case 'jsp':
        case 'java':
            $mode = 'jsp';
        break;
        case 'sql':
            $mode = 'sql';
        break;
        case 'ini':
            $mode = 'ini';
        break;
        case 'json':
            $mode = 'json';
        break;
        case 'twig':
            $mode = 'twig';
        break;
    }
    return $mode;
}
function edit_file_form(){
    global $fm_current_dir,$filename,$file_data,$save_file,$fm_path_info,$curr_row,$curr_col,$ace_mode,$ace_wrap,$cookie_cache_time;
    $file = $fm_current_dir.$filename;
    $ace_mode_opts = array();
    $ace_mode_opts[] = array('HTML','html');
    $ace_mode_opts[] = array('CSS','css');
    $ace_mode_opts[] = array('PHP','php');
    $ace_mode_opts[] = array('JAVASCRIPT','javascript');
    $ace_mode_opts[] = array('BATCH SCRIPT','batchfile');
    $ace_mode_opts[] = array('PYTHON','python');
    $ace_mode_opts[] = array('C/C++','c_cpp');
    $ace_mode_opts[] = array('JSP/JAVA','jsp');
    $ace_mode_opts[] = array('SQL','sql');
    $ace_mode_opts[] = array('INI','ini');
    $ace_mode_opts[] = array('JSON','json');
    $ace_mode_opts[] = array('TWIG TEMPLATE','twig');
    $ace_mode_opts[] = array('PLAIN TEXT','plain_text');
    $ace_mode_curr = ace_mode_autodetect($file);
    $file_ace_mode_cookiename = 'ace_'.hash('crc32',fix_cookie_name($file),FALSE);
    if (strlen($_COOKIE[$file_ace_mode_cookiename])) $ace_mode_curr = $_COOKIE[$file_ace_mode_cookiename];
    if (strlen($ace_mode)) $ace_mode_curr = $ace_mode;
    setcookie($file_ace_mode_cookiename, $ace_mode_curr, time()+$cookie_cache_time, "/");
    $ace_wrap_curr = 0;
    if (strlen($_COOKIE['ace_wrap'])) $ace_wrap_curr = intval($_COOKIE['ace_wrap']);
    if (strlen($ace_wrap)) $ace_wrap_curr = intval($ace_wrap);
    setcookie('ace_wrap', $ace_wrap_curr, time()+$cookie_cache_time, "/");
    $curr_row = intval($curr_row);
    $curr_col = intval($curr_col);
    $save_msg = '';
    $reload = false;
    if ($save_file){
        if (is_binary($file)){
            $file_data = base64_decode($file_data);
            //$file_data = hex2bin($file_data);
        }
        if (file_put_contents($file,$file_data,FILE_BINARY)){
            $save_msg = et("FileSaved")."!";
            $reload = true;
        } else $save_msg = et("FileSaveError")."...";
    }
    clearstatcache();
    $file_data = file_get_contents($file,FILE_BINARY);
    if (is_binary($file)){
        $file_data = base64_encode($file_data);
        //$file_data = bin2hex($file_data);
        //$file_data = chunk_split($file_data,2,"\\x");
        //$file_data = "\\x".substr($file_data,0,-2);
    }
    //<link rel=\"stylesheet\" type=\"text/css\" href=\"".$fm_path_info['basename']."?action=99&filename=prism.css\" media=\"screen\" />
    html_header("
        <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=jquery-1.11.1.min.js\"></script>
        <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=ace.js\"></script>
    ");
    echo "<body marginwidth=\"0\" marginheight=\"0\">
    <form name=\"edit_form\" action=\"".$fm_path_info['basename']."\" method=\"post\">
        <input type=hidden name=\"action\" value=\"7\">
        <input type=hidden name=\"fm_current_dir\" value=\"".$fm_current_dir."\">
        <input type=hidden name=\"filename\" value=\"".$filename."\">
        <input type=hidden name=\"file_data\" id=\"file_data\" value=\"\">
        <input type=hidden name=\"curr_row\" id=\"curr_row\" value=\"0\">
        <input type=hidden name=\"curr_col\" id=\"curr_col\" value=\"0\">
        <input type=hidden name=\"ace_mode\" id=\"ace_mode\" value=\"\">
        <input type=hidden name=\"ace_wrap\" id=\"ace_wrap\" value=\"\">
        <input type=hidden name=\"save_file\" value=\"0\">
    </form>
    <style>
        html, body {
            width: 100%;
            height: 100%;
            margin: 0 !important;
            overflow: hidden;
        }
        #div_toolbar {
            position: relative;
            display: block;
            height: 30px;
            padding: 6px;
        }
        #div_toolbar button, #div_toolbar select {
            display: inline-block;
            float: left;
            margin-right: 6px;
        }
        #div_toolbar .ace_wrap_select {
            display: inline-block;
            float: left;
            border: 1px solid #aaa;
            background-color: #ddd;
            padding: 3px 6px 4px 3px;
            margin-right: 6px;
            margin-top: 1px;
        }
        #div_toolbar .ace_wrap_select input, #div_toolbar .ace_wrap_select label {
            cursor: pointer;
        }
        #div_toolbar .save_msg {
            display: inline-block;
            float: left;
            font-weight: bold;
            border: 1px solid #aaa;
            padding: 5px 6px;
            margin-right: 6px;
            margin-top: 1px;
        }
        #div_ace_editor {
            position: relative;
            display: block;
            height: calc(100% - 43px);
            border-top: 1px solid #ccc;
        }
    </style>";
    echo "
    <div id=\"div_toolbar\">
        <button type=\"button\" class=\"btn\" onclick=\"refreshFile()\" value=\"".et('Refresh')."\"><i class=\"fa fa-refresh\"></i> ".et('Refresh')." (Ctrl+r)</button>
        <button type=\"button\" class=\"btn\" onclick=\"saveFile()\" value=\"".et('SaveFile')."\"><i class=\"fa fa-add-file\"></i> ".et('SaveFile')." (Ctrl+s)</button>
        <select name=\"ace_mode_select\" id=\"ace_mode_select\" onchange=\"changeHighlightMode()\" style=\"width:300px; margin-top:1px; padding:6px 5px 5px 5px;\">";
            foreach ($ace_mode_opts as $opt) {
                echo "
                <option value='".$opt[1]."'>Mode: ".$opt[0];
            }
        echo "
        </select>
        <div class=\"ace_wrap_select\"><input type=\"checkbox\" name=\"ace_wrap_select\" id=\"ace_wrap_select\" value=\"1\"".($ace_wrap_curr?' checked':'')." onclick=\"changeWrapMode()\"><label for=\"ace_wrap_select\" class=\"noselect\">&nbsp;Wrap</label></div>";
        if (strlen($save_msg)) echo "
        <div class=\"save_msg\">".$save_msg."</div>";
    echo "
    </div>
    <div id=\"div_ace_editor\">".html_encode($file_data)."</div>
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        ace.config.set('basePath', '".$fm_path_info['basename']."?action=99&filename=');
        ace.require(\"ace/ext/whitespace\");
        var editor = ace.edit('div_ace_editor');
        editor.setOptions({
            theme: 'ace/theme/monokai',
            mode: 'ace/mode/".$ace_mode_curr."',
            useWorker: false, // boolean: true if use web worker for loading scripts
            useSoftTabs: true, // boolean: true if we want to use spaces than tabs
            tabSize: 4,
            wrap: ".($ace_wrap_curr?'true':'false').",
            indentedSoftWrap: false,
            fixedWidthGutter: true,
            showPrintMargin: false,
            printMarginColumn: 80,
            //scrollSpeed: 2,
            fontFamily: 'Courier New',
            fontSize: '10pt'
        });
        editor.commands.addCommand({
            name: 'refreshFile',
            bindKey: {win: 'Ctrl-r', mac: 'Command-r'},
            exec: function(editor) {
                refreshFile();
            }
        });
        editor.commands.addCommand({
            name: 'saveFile',
            bindKey: {win: 'Ctrl-s', mac: 'Command-s'},
            exec: function(editor) {
                saveFile();
            }
        });
        function changeHighlightMode(){
            var mode = $('#ace_mode_select').val();
            if (mode.length > 0) mode = 'ace/mode/'+mode;
            editor.getSession().setMode(mode);
        }
        function changeWrapMode(){
            var mode = $('#ace_wrap_select').prop('checked');
            editor.getSession().setOption('wrap', mode);
        }
        function refreshFile(){
            document.edit_form.save_file.value=0;
            document.edit_form.file_data.value='';
            $('#curr_row').val(editor.getSelectionRange().start.row);
            $('#curr_col').val(editor.getSelectionRange().start.column);
            $('#ace_mode').val($('#ace_mode_select').val());
            $('#ace_wrap').val($('#ace_wrap_select').prop('checked')?1:0);
            document.edit_form.submit();
        }
        function saveFile(){
            document.edit_form.save_file.value=1;
            $('#file_data').val(editor.getSession().getValue());
            $('#curr_row').val(editor.getSelectionRange().start.row);
            $('#curr_col').val(editor.getSelectionRange().start.column);
            $('#ace_mode').val($('#ace_mode_select').val());
            $('#ace_wrap').val($('#ace_wrap_select').prop('checked')?1:0);
        ";
        if (is_writable($file)) echo "
            document.edit_form.submit();";
        else echo "
            if(confirm('".et('ConfTrySave')." ?')) document.edit_form.submit();";
        echo "
        }
        $('#ace_mode_select').val('".$ace_mode_curr."');
        window.parent.modalWindowReloadOnClose = ".($reload?'true':'false').";
        window.focus();
        editor.gotoLine(".($curr_row+1).",".($curr_col).");
        editor.focus();
    //-->
    </script>";
    echo "
    </body>\n</html>";
}
function config_form(){
    global $cfg;
    global $fm_current_dir,$fm_file,$doc_root,$fm_path_info,$fm_current_root,$sys_lang,$open_basedirs,$version;
    global $lang,$fm_root,$timezone,$date_format,$error_reporting;
    global $config_action,$newlang,$newfmroot,$newtimezone,$newdateformat,$newerror,$newpass;
    $reload = false;
    switch ($config_action){
        case 1:
            if ($cfg->data['lang'] != $newlang){
                $cfg->data['lang'] = $newlang;
                $lang = $newlang;
            }
            if ($cfg->data['fm_root'] != $newfmroot){
                $cfg->data['fm_root'] = $newfmroot;
                $fm_root = $newfmroot;
            }
            if ($cfg->data['timezone'] != $newtimezone){
                $cfg->data['timezone'] = $newtimezone;
                $timezone = $newtimezone;
            }
            if ($cfg->data['date_format'] != $newdateformat){
                $cfg->data['date_format'] = $newdateformat;
                $date_format = $newdateformat;
            }
            if ($cfg->data['error_reporting'] != $newerror){
                $cfg->data['error_reporting'] = $newerror;
                $error_reporting = $newerror;
            }
            if ($cfg->data['auth_pass'] != $newpass){
                $cfg->data['auth_pass'] = md5($newpass);
                setcookie("loggedon", $cfg->data['auth_pass'], 0 , "/");
            }
            $cfg->save();
            $reload = true;
        break;
    }
    html_header('<script type="text/javascript" src="'.$fm_path_info['basename'].'?action=99&filename=jquery-1.11.1.min.js"></script>');
    echo "<body marginwidth=\"0\" marginheight=\"0\">\n";
    if ($reload){
        echo "
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            window.setTimeout(function(){
                window.parent.parent.document.location.href='".$fm_path_info['basename']."?fm_current_dir=".rawurlencode($fm_current_dir)."';
            },500);
        //-->
        </script>";
    } else {
        $timezone_opts = json_decode('[
            ["(GMT-12:00) Pacific\/Wake","Pacific\/Wake"],
            ["(GMT-11:00) Pacific\/Apia","Pacific\/Apia"],
            ["(GMT-10:00) Pacific\/Honolulu","Pacific\/Honolulu"],
            ["(GMT-09:00) America\/Anchorage","America\/Anchorage"],
            ["(GMT-08:00) America\/Los_Angeles","America\/Los_Angeles"],
            ["(GMT-07:00) America\/Chihuahua","America\/Chihuahua"],
            ["(GMT-07:00) America\/Denver","America\/Denver"],
            ["(GMT-07:00) America\/Phoenix","America\/Phoenix"],
            ["(GMT-06:00) America\/Chicago","America\/Chicago"],
            ["(GMT-06:00) America\/Managua","America\/Managua"],
            ["(GMT-06:00) America\/Mexico_City","America\/Mexico_City"],
            ["(GMT-06:00) America\/Regina","America\/Regina"],
            ["(GMT-05:00) America\/Bogota","America\/Bogota"],
            ["(GMT-05:00) America\/Indiana\/Indianapolis","America\/Indiana\/Indianapolis"],
            ["(GMT-05:00) America\/New_York","America\/New_York"],
            ["(GMT-04:00) America\/Caracas","America\/Caracas"],
            ["(GMT-04:00) America\/Halifax","America\/Halifax"],
            ["(GMT-04:00) America\/Santiago","America\/Santiago"],
            ["(GMT-03:30) America\/St_Johns","America\/St_Johns"],
            ["(GMT-03:00) America\/Argentina\/Buenos_Aires","America\/Argentina\/Buenos_Aires"],
            ["(GMT-03:00) America\/Godthab","America\/Godthab"],
            ["(GMT-03:00) America\/Sao_Paulo","America\/Sao_Paulo"],
            ["(GMT-02:00) America\/Noronha","America\/Noronha"],
            ["(GMT-01:00) Atlantic\/Azores","Atlantic\/Azores"],
            ["(GMT-01:00) Atlantic\/Cape_Verde","Atlantic\/Cape_Verde"],
            ["(GMT 00:00) Africa\/Casablanca","\/Casablanca"],
            ["(GMT 00:00) Europe\/London","\/London"],
            ["(GMT+01:00) Africa\/Lagos","Africa\/Lagos"],
            ["(GMT+01:00) Europe\/Belgrade","Europe\/Belgrade"],
            ["(GMT+01:00) Europe\/Berlin","Europe\/Berlin"],
            ["(GMT+01:00) Europe\/Paris","Europe\/Paris"],
            ["(GMT+01:00) Europe\/Sarajevo","Europe\/Sarajevo"],
            ["(GMT+02:00) Africa\/Cairo","Africa\/Cairo"],
            ["(GMT+02:00) Africa\/Johannesburg","Africa\/Johannesburg"],
            ["(GMT+02:00) Asia\/Jerusalem","Asia\/Jerusalem"],
            ["(GMT+02:00) Europe\/Istanbul","Europe\/Istanbul"],
            ["(GMT+02:00) Europe\/Bucharest","Europe\/Bucharest"],
            ["(GMT+02:00) Europe\/Helsinki","Europe\/Helsinki"],
            ["(GMT+03:00) Africa\/Nairobi","Africa\/Nairobi"],
            ["(GMT+03:00) Asia\/Baghdad","Asia\/Baghdad"],
            ["(GMT+03:00) Asia\/Riyadh","Asia\/Riyadh"],
            ["(GMT+03:00) Europe\/Moscow","Europe\/Moscow"],
            ["(GMT+03:30) Asia\/Tehran","Asia\/Tehran"],
            ["(GMT+04:00) Asia\/Muscat","Asia\/Muscat"],
            ["(GMT+04:00) Asia\/Tbilisi","Asia\/Tbilisi"],
            ["(GMT+04:30) Asia\/Kabul","Asia\/Kabul"],
            ["(GMT+05:00) Asia\/Karachi","Asia\/Karachi"],
            ["(GMT+05:00) Asia\/Yekaterinburg","Asia\/Yekaterinburg"],
            ["(GMT+05:30) Asia\/Calcutta","Asia\/Calcutta"],
            ["(GMT+05:45) Asia\/Katmandu","Asia\/Katmandu"],
            ["(GMT+06:00) Asia\/Dhaka","Asia\/Dhaka"],
            ["(GMT+06:00) Asia\/Colombo","Asia\/Colombo"],
            ["(GMT+06:00) Asia\/Novosibirsk","Asia\/Novosibirsk"],
            ["(GMT+06:30) Asia\/Rangoon","Asia\/Rangoon"],
            ["(GMT+07:00) Asia\/Bangkok","Asia\/Bangkok"],
            ["(GMT+07:00) Asia\/Krasnoyarsk","Asia\/Krasnoyarsk"],
            ["(GMT+08:00) Asia\/Hong_Kong","Asia\/Hong_Kong"],
            ["(GMT+08:00) Asia\/Irkutsk","Asia\/Irkutsk"],
            ["(GMT+08:00) Asia\/Singapore","Asia\/Singapore"],
            ["(GMT+08:00) Asia\/Taipei","Asia\/Taipei"],
            ["(GMT+08:00) Asia\/Irkutsk","Asia\/Irkutsk"],
            ["(GMT+08:00) Australia\/Perth","Australia\/Perth"],
            ["(GMT+09:00) Asia\/Tokyo","Asia\/Tokyo"],
            ["(GMT+09:00) Asia\/Seoul","Asia\/Seoul"],
            ["(GMT+09:00) Asia\/Yakutsk","Asia\/Yakutsk"],
            ["(GMT+09:30) Australia\/Adelaide","Australia\/Adelaide"],
            ["(GMT+09:30) Australia\/Darwin","Australia\/Darwin"],
            ["(GMT+10:00) Australia\/Brisbane","Australia\/Brisbane"],
            ["(GMT+10:00) Australia\/Hobart","Australia\/Hobart"],
            ["(GMT+10:00) Australia\/Sydney","Australia\/Sydney"],
            ["(GMT+10:00) Asia\/Vladivostok","Asia\/Vladivostok"],
            ["(GMT+10:00) Pacific\/Guam","Pacific\/Guam"],
            ["(GMT+11:00) Asia\/Magadan","Asia\/Magadan"],
            ["(GMT+12:00) Pacific\/Auckland","Pacific\/Auckland"],
            ["(GMT+12:00) Pacific\/Fiji","Pacific\/Fiji"],
            ["(GMT+13:00) Pacific\/Tongatapu","Pacific\/Tongatapu"]
        ]');
        echo "
        <table border=0 cellspacing=0 cellpadding=5 align=left style=\"padding:5px;\">
        <form name=\"config_form\" action=\"".$fm_path_info['basename']."\" method=\"post\" autocomplete=\"off\">
        <input type=hidden name=action value=2>
        <input type=hidden name=config_action value=0>
        <tr><td align=right width=1>".et('FileMan').":<td>".et('Version')." ".$version." (".format_size(phpfm_filesize($fm_file)).")</td></tr>
        <tr><td align=right width=1><nobr>".et('DocRoot').":</nobr><td>".$doc_root."</td></tr>
        <tr><td align=right width=1><nobr>".et('PHPOpenBasedir').":</nobr><td>".(count($open_basedirs)?implode("<br>\n",$open_basedirs):et('PHPOpenBasedirFullAccess'))."</td></tr>
        <tr><td align=right width=1>".et('FMRoot').":<td><input type=\"text\" style=\"width:392px; padding:5px 8px;\" id=\"newfmroot\" name=\"newfmroot\" readonly autocomplete=\"off\" value=\"".html_encode($fm_root)."\" onkeypress=\"enterSubmit(event,'test_config_form(1)')\"></td></tr>
        <tr><td align=right>".et('Timezone').":<td>
            <select name=newtimezone id=newtimezone style=\"width:410px; padding:5px;\">
                <option value=''>System Default";
                foreach ($timezone_opts as $opt) {
                    echo "
                    <option value='".$opt[1]."'>".$opt[0];
                }
            echo "
            </select>
        </td></tr>
        <tr><td align=right width=1>".et('DateFormat').":<td><input type=\"text\" style=\"width:392px; padding:5px 8px;\" id=\"newdateformat\" name=\"newdateformat\" readonly autocomplete=\"off\" value=\"".html_encode($date_format)."\" onkeypress=\"enterSubmit(event,'test_config_form(1)')\"></td></tr>
        <tr><td align=right>".et('Lang').":<td>
            <select name=newlang id=newlang style=\"width:410px; padding:5px;\">
                <option value=''>System Default</option>
                <option value='ca'>Catalan - by Pere Borràs AKA @Norl</option>
                <option value='cn'>Chinese - by Wen.Xin</option>
                <option value='nl'>Dutch - by Leon Buijs</option>
                <option value='en'>English - by Fabricio Seger Kolling</option>
                <option value='fr'>French - by Jean Bilwes</option>
                <option value='de'>German - by Guido Ogrzal</option>
                <option value='it'>Italian - by Valerio Capello</option>
                <option value='ja'>Japanese - by h3zjp</option>
                <option value='ko'>Korean - by Airplanez</option>
                <option value='fa'>Persian/Dari - by Opensecure, Max Base</option>
                <option value='pt'>Portuguese - by Fabricio Seger Kolling</option>
                <option value='pl'>Polish - by Jakub Kocój</option>
                <option value='sr'>Serbian - by Miroljub Sunajko</option>
                <option value='es'>Spanish - by Sh Studios</option>
                <option value='ru'>Russian - by Евгений Рашев, Алексей Гаврюшин</option>
                <option value='tr'>Turkish - by Necdet Yazilimlari</option>
                <option value='ua'>Ukrainian - by Андрій Литвин</option>
                <option value='id'>Indonesian - by dirmanhana</option>
            </select>
        </td></tr>
        <tr><td align=right>".et('ErrorReport').":<td>
            <select name=newerror id=newerror style=\"width:410px; padding:5px;\">
                <option value=\"0\">Disabled
                <option value=\"1\">Show PHP Errors
                <option value=\"2\">Show PHP Errors + ChromePhp Debug
            </select>
        </td></tr>";
        $show_pass = '';
        if ($cfg->data['auth_pass'] != md5('')) $show_pass = $cfg->data['auth_pass'];
        echo "
        <tr><td align=right>".et('Pass').":<td>
            <input type=\"password\" style=\"width:392px; padding:5px 8px;\" name=\"newpass\" id=\"newpass\" readonly autocomplete=\"off\" value=\"".html_encode($show_pass)."\" onkeypress=\"enterSubmit(event,'test_config_form(1)')\">
        </td></tr>
        <tr><td>&nbsp;<td align=right><input type=button class=\"btn noIcon\" value=\"".et('SaveConfig')."\" onclick=\"test_config_form(1)\"></td></tr>
        </form>
        </table>
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            $('#newlang').val('".$cfg->data['lang']."');
            $('#newtimezone').val('".$cfg->data['timezone']."');
            $('#newerror').val('".$cfg->data['error_reporting']."');
            function test_config_form(arg){
                document.config_form.config_action.value = arg;
                document.config_form.submit();
            }
            // To avoid autofill, because autocomplete=off simply does not work..
            window.setTimeout(function(){
                $('#newfmroot').removeAttr('readonly');
                $('#newdateformat').removeAttr('readonly');
                $('#newpass').removeAttr('readonly');
            },250);
        //-->
        </script>";
    }
    echo "
    </body>\n</html>";
}
function phpfm_host2ip($host_or_ip){
    if (filter_var($host_or_ip, FILTER_VALIDATE_IP)) return $host_or_ip;
    else return gethostbyname($host_or_ip);
}
function phpfm_ping($host_or_ip,&$output) {
    if (!function_exists("socket_create")) {
        $output = "Function socket_create() not available";
        return false;
    }
    $timeout = 1;
    $ip = phpfm_host2ip($host_or_ip);
    $socket = socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp'));
    socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array('sec' => $timeout, 'usec' => 0));
    socket_connect($socket, $ip, 0);
    $ping_ok = false;
    $ping_tries = 2;
    for ($i=0;$i<$ping_tries;$i++) {
        $time_start = microtime(true);
        $package  = "\x08\x00\x19\x2f\x00\x00\x00\x00\x70\x69\x6e\x67";
        socket_send($socket, $package, strlen($package), 0);
        if (socket_read($socket, 255)) {
            $ping_ok = true;
        }
        $time_stop = microtime(true);
        $ms = ($time_stop - $time_start) * 1000;
        if ($ping_ok) break;
    }
    socket_close($socket);
    if ($ping_ok) $output = number_format((float)$ms, 2, '.', '').'ms';
    elseif ($ms > $timeout * 1000) $output = 'Timeout';
    else $output = 'No response';
    if ($ip != $host_or_ip) $output .= ' ('.$ip.')';
    return $ping_ok;
}
function phpfm_portscan($ip,$port,&$output){
    global $services;
    if (!function_exists("fsockopen")) {
        return "Function fsockopen() not available";
    }
    $timeout = 1;
    $proto_ip = $ip;
    if (stripos($port,'udp') !== false) $proto_ip = 'udp://'.$ip;
    $port_nr = str_strip($port,'1234567890');
    $port_open = false;
    $fp = @fsockopen($proto_ip, $port_nr, $errno, $errstr, $timeout);
    $fb_out = '';
    if($fp){
        // TODO: UDP port scan needs more testing..
        if (stripos($port,'udp') !== false) {
            stream_set_timeout($fp, 3);
            stream_set_write_buffer($fp, 0);
            stream_set_read_buffer($fp, 0);
            stream_set_blocking($fp, true);
            if (fwrite($fp,"test\n") !== falze){
                $fb_out = trim(stream_get_contents($fp));
                $info = stream_get_meta_data($fp);
                if (!$info['timed_out'] && $fb_out !== false) {
                    if (strlen($fb_out)){
                        $port_open = true;
                    }
                }
            }
        } else {
            $port_open = true;
        }
        fclose($fp);
    }
    if ($port_open) {
        $output = '│ <font color="green">Port: '.$port.(isset($services[$port])?' = '.$services[$port]:'').'</font><br>';
    } else {
        $output = '│ <font color="brown">Port: '.$port.(isset($services[$port])?' = '.$services[$port]:'').'</font><br>'; // '.$errstr.' ('.$errno.')
    }
    return $port_open;
}
/*
https://www.ricardoarrigoni.com.br/tabela-ascii-completa/
┌─────────┐
│ XXXXXXX │
├───-─────┘
├─► xxxxxxx
└─► xxxxxxx
╔═════════╗
║ XXXXXXX ║
╠═════════╝
╟► xxxxxxx
╙► xxxxxxx
*/
function portscan_form(){
    global $cfg;
    global $fm_current_dir,$fm_file,$doc_root,$fm_path_info,$fm_current_root;
    global $ip,$lan_ip;
    global $portscan_action,$portscan_ip,$portscan_ips,$portscan_port,$portscan_ports,$services,$portscan_ignore_ping;
    $services_inverted = array_flip($services);
    $default_portscan_services = explode(",","DAYTIME,FTP,SSH,TELNET,DNS,DHCP,NETBIOS-SESSION,SNMP,LDAP,SMB-AD,MSSQL,ORACLE,MYSQL/MARIADB,RDESKTOP,VNC,HTTPD-ALT");
    $default_portscan_ports = array();
    foreach ($default_portscan_services as $name) {
        if (isset($services_inverted[$name])) $default_portscan_ports[] = $services_inverted[$name];
    }
    $default_portscan_ports = implode(",",$default_portscan_ports);
    switch ($portscan_action){
        case 2: // Do Ping
            @ini_set("max_execution_time",30);
            header("Content-type: text/plain");
            $output = '';
            $ping_ok = phpfm_ping($portscan_ip,$output);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(array($ping_ok,$output));
            die();
        break;
        case 3: // Scan Port
            @ini_set("max_execution_time",30);
            $output = '';
            $portscan_ip = phpfm_host2ip($portscan_ip);
            $port_open = phpfm_portscan($portscan_ip,$portscan_port,$output);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(array($port_open,$output));
            die();
        break;
        case 4: // Scan Multiple Ports
            @ini_set("max_execution_time",120);
            $portscan_ip = phpfm_host2ip($portscan_ip);
            $portscan_ports = explode(',',$portscan_ports);
            $resul = array();
            foreach ($portscan_ports as $portscan_port) {
                $output = '';
                $port_open = phpfm_portscan($portscan_ip,$portscan_port,$output);
                $resul[] = array($port_open,$output);
            }
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($resul);
            die();
        break;
    }
    html_header('<script type="text/javascript" src="'.$fm_path_info['basename'].'?action=99&filename=jquery-1.11.1.min.js"></script>');
    $m = explode(".",$lan_ip);
    $inet = $m[0].".".$m[1].".".$m[2].".";
    if (!strlen($portscan_ip_range)) $portscan_ip_range = $inet."1-254";
    //if (!strlen($portscan_port_range)) $portscan_port_range = implode(",",array_keys($services));
    if (strlen($_COOKIE['portscan_ip_range'])) $portscan_ip_range = $_COOKIE['portscan_ip_range'];
    if (!strlen($portscan_port_range)) $portscan_port_range = $default_portscan_ports;
    if (strlen($_COOKIE['portscan_port_range'])) $portscan_port_range = $_COOKIE['portscan_port_range'];
    echo "<body marginwidth=\"0\" marginheight=\"0\">
    <style>
        html, body {
            width: 100%;
            height: 100%;
            margin: 0 !important;
            overflow: hidden;
        }
        #div_toolbar {
            position: relative;
            display: block;
            height: 130px;
            padding: 6px;
        }
        #div_toolbar button, #div_toolbar .save_msg {
            display: inline-block;
            float: left;
            margin-right: 6px;
        }
        #div_toolbar .portscan_ignore_ping {
            display: inline-block;
            float: left;
            border: 1px solid #aaa;
            background-color: #ddd;
            padding: 3px 6px 4px 3px;
            margin-right: 6px;
            margin-top: 1px;
        }
        #div_toolbar .portscan_ignore_ping input, #div_toolbar .portscan_ignore_ping label {
            cursor: pointer;
        }
        #portscanIframe {
            position: relative;
            display: block;
            background: #000;
            color: #fff;
            width: 100%;
            height: calc(100% - 143px);
            overflow-y: scroll;
            overflow-x: auto;
            border-top: 1px solid #ccc;
        }
    </style>
    <div id=\"div_toolbar\">
        <table border=0 cellspacing=0 cellpadding=5 align=center width=\"100%\" height=\"100%\">
        <form name=\"portscan_form\" action=\"".$fm_path_info['basename']."\" method=\"get\" target=\"portscanIframe\">
            <input type=hidden name=action value=12>
            <input type=hidden name=portscan_action value=0>
            <tr><td valign=top width=1>
                <table border=0 cellspacing=0 cellpadding=5>
                <tr><td align=right width=1><nobr>Hosts:</nobr><td><input type=\"text\" style=\"width:430px; padding:5px 8px;\" name=\"portscan_ip_range\" value=\"".html_encode($portscan_ip_range)."\"></td></tr>
                <tr><td align=right width=1><nobr>Scan Ports:</nobr><td><input type=\"text\" style=\"width:430px; padding:5px 8px;\" name=\"portscan_port_range\" value=\"".html_encode($portscan_port_range)."\"></td></tr>
                <tr><td>&nbsp;</td><td>
                <div class=\"portscan_ignore_ping\"><input type=\"checkbox\" name=\"portscan_ignore_ping\" id=\"portscan_ignore_ping\" value=\"1\"".($portscan_ignore_ping?' checked':'')." onclick=\"set_ping_cookie()\"><label for=\"portscan_ignore_ping\" class=\"noselect\">&nbsp;Ignore Ping</label></div>
                <button type=\"button\" class=\"btn\" onclick=\"execute_portscan()\" value=\"".et('Exec')."\"><i class=\"fa fa-refresh\"></i> ".et('Exec')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"stop_portscan()\" value=\"".et('Stop')."\"><i class=\"fa fa-delete\"></i> ".et('Stop')."</button>
                </td></tr>
                </table>
            </td><td valign=top>
                <table border=0 cellspacing=0 cellpadding=5>
                <tr><td align=right width=1><nobr>Your IP:</nobr><td><input type=\"text\" name=\"your_ip\" value=\"".$ip."\" style=\"width:150px; background-color:#ccc; padding:5px 8px;\" readonly></td></tr>";
                if (strlen($lan_ip)) echo "<tr><td align=right width=1><nobr>Server Lan IP:</nobr><td><input type=\"text\" name=\"your_ip\" value=\"".$lan_ip."\" style=\"width:150px; background-color:#ccc; padding:5px 8px;\" readonly></td></tr>";
                echo "
                </form>
                </table>
            </td></tr>
        </form>
        </table>
    </div>
    <iframe id=\"portscanIframe\" name=\"portscanIframe\" src=\"\" scrolling=\"yes\" frameborder=\"0\"></iframe>
    ";
    $ports_reference = array();
    foreach ($services as $port => $service){
        $ports_reference[] = "$port = $service";
    }
    echo "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        var iframe_text = '';
        var portscan_ips, portscan_ports;
        var portscan_curr_ip, portscan_curr_port;
        var all_ports_one_request = false;
        var portscan_ignore_ping = ".($portscan_ignore_ping?'true':'false').";
        var portscan_execute_flag = false;
        var all_service_ports = ".json_encode(array_keys($services)).";
        var portscan_ports_failed = 0;
        function get_boxed_text(str){
            str = String(str);
            var br = '<br>';
            var arr = str.split(br);
            var max_str_length = 0;
            for(var i=0;i<arr.length;i++){
                line_strip_tags = String(arr[i]).replace(/<\/?[^>]+(>|$)/g, \"\");
                if (line_strip_tags.length > max_str_length) max_str_length = line_strip_tags.length;
            }
            var out = '';
            out += '<nobr>┌'+rep('─',max_str_length+2)+'┐<nobr>'+br;
            for(var i=0;i<arr.length;i++){
                line_strip_tags = String(arr[i]).replace(/<\/?[^>]+(>|$)/g, \"\");
                out += '<nobr>│ '+arr[i]+rep('&nbsp;',(max_str_length-line_strip_tags.length))+' │<nobr>';
                if (i<arr.length) out += br;
            }
            out += '<nobr>└'+rep('─',max_str_length+2)+'┘<nobr>'+br;
            return out;
        }
        function write_to_iframe(str){
            iframe_text += str;
            var iframe_body = document.getElementById('portscanIframe').contentWindow.document;
            iframe_body.open();
            iframe_body.write('<style>body { margin:5px; background-color:#000; color:#fff; } </style><div style=\"width:100%; height:100%; font-family:Courier New; font-size:10pt; font-weight:normal; color:#aaa;\">'+iframe_text+'</div>');
            iframe_body.close();
        }
        function iframe_scroll_down(){
            var iframe_window = document.getElementById('portscanIframe').contentWindow;
            iframe_window.scrollTo( 0, 999999 );
        }
        write_to_iframe(get_boxed_text('PHP File Manager - Portscan<br><br><b>Hosts examples:</b><br>Single: phpfm.sf.net<br>Single: 192.168.0.1<br>Range: 192.168.0.1-254<br>Multiple: phpfm.sf.net,192.168.0.1,192.168.0.2'));
        write_to_iframe(get_boxed_text('<b>Ports reference:</b><br>* = ALL<br>".implode('<br>',$ports_reference)."'));
        function stop_portscan(){
            portscan_execute_flag = false;
        }
        function set_ping_cookie(){
            portscan_ignore_ping = $('#portscan_ignore_ping').prop('checked');
            var value = portscan_ignore_ping?1:0;
            setCookiePersistent('portscan_ignore_ping',value);
        }
        function execute_portscan(){
            iframe_text = '';
            portscan_ip_range = String(document.portscan_form.portscan_ip_range.value).trim();
            portscan_port_range = String(document.portscan_form.portscan_port_range.value).trim();
            setCookie('portscan_ip_range',portscan_ip_range);
            setCookie('portscan_port_range',portscan_port_range);
            var portscan_command_str = '';
            portscan_command_str += 'PHP File Manager - Portscan<br><br>';
            portscan_command_str += 'Hosts: '+portscan_ip_range+'<br>';
            portscan_command_str += 'Scan Ports: '+portscan_port_range+'<br>';
            portscan_command_str += 'Ignore Ping: '+(portscan_ignore_ping?'Yes':'No');
            portscan_ips = [];
            portscan_ports = [];
            if (portscan_port_range.length > 0) {
                if (portscan_port_range == '*') portscan_ports = all_service_ports;
                else portscan_ports = portscan_port_range.split(',');
            }
            if (portscan_ip_range.length > 0) {
                if (portscan_ip_range.indexOf('-') != -1){
                    portscan_ip_range = portscan_ip_range.split('-');
                    portscan_inet = portscan_ip_range[0].substr(0,portscan_ip_range[0].lastIndexOf('.')+1);
                    portscan_start = parseInt(portscan_ip_range[0].substr(portscan_ip_range[0].lastIndexOf('.')+1));
                    portscan_end = parseInt(portscan_ip_range[1]);
                    for(var i=portscan_start;i<=portscan_end;i++){
                        portscan_ips.push(portscan_inet+i);
                    }
                } else if (portscan_ip_range.indexOf(',') != -1){
                    portscan_ips = portscan_ip_range.split(',');
                } else {
                    portscan_ips.push(portscan_ip_range);
                }
            }
            write_to_iframe(get_boxed_text(portscan_command_str));
            portscan_curr_ip = 0;
            portscan_execute_flag = true;
            do_ping();
        }
        function do_ping(){
            if (portscan_execute_flag) {
                if (portscan_curr_ip<portscan_ips.length){
                    ip = portscan_ips[portscan_curr_ip];
                    write_to_iframe('│ Ping: '+ip+' = ');
                    iframe_scroll_down();
                    $.ajax({
                        type: 'POST',
                        url: '".$fm_path_info['basename']."',
                        dataType: 'json',
                        crossDomain: false,
                        data: {
                            action : 12,
                            portscan_action: 2,
                            portscan_ip : ip
                        },
                        success: function (data){
                            if (data[0]) {
                                write_to_iframe('<font color=\"green\">'+data[1]+'</font><br>');
                            } else {
                                write_to_iframe('<font color=\"brown\">'+data[1]+'</font><br>');
                            }
                            iframe_scroll_down();
                            if ((data[0] || portscan_ignore_ping) && portscan_ports.length > 0) {
                                portscan_curr_port = 0;
                                portscan_ports_failed = 0
                                do_scan();
                            } else {
                                portscan_curr_ip++;
                                do_ping();
                            }
                        },
                        error: function (err){
                            write_to_iframe('<font color=\"#777\">Server error</font><br>');
                        }
                    })
                } else {
                    write_to_iframe(get_boxed_text('Portscan finished'));
                    iframe_scroll_down();
                }
            } else {
                write_to_iframe(get_boxed_text('Portscan stopped'));
                iframe_scroll_down();
            }
        }
        function do_scan(){
            ip = portscan_ips[portscan_curr_ip];
            if (all_ports_one_request){
                $.get(
                    '".$fm_path_info['basename']."',
                    {
                        action : 12,
                        portscan_action: 4,
                        portscan_ip : ip,
                        portscan_ports : portscan_ports.join(',')
                    },
                    function (data){
                        data = String(data).trim();
                        if (data.length > 0) {
                            write_to_iframe(data);
                            iframe_scroll_down();
                        }
                        portscan_curr_ip++;
                        do_ping();
                    }
                )
            } else {
                if (portscan_curr_port<portscan_ports.length && portscan_execute_flag){
                    port = portscan_ports[portscan_curr_port];
                    iframe_scroll_down();
                    $.ajax({
                        type: 'POST',
                        url: '".$fm_path_info['basename']."',
                        dataType: 'json',
                        crossDomain: false,
                        data: {
                            action : 12,
                            portscan_action: 3,
                            portscan_ip : ip,
                            portscan_port : port
                        },
                        success: function (data){
                            if (data[0]) {
                                if (portscan_ports_failed > 0) write_to_iframe('<br>');
                                write_to_iframe(data[1]);
                                iframe_scroll_down();
                                portscan_ports_failed = 0;
                            } else {
                                if (portscan_ports_failed == 0) write_to_iframe('│ ');
                                write_to_iframe('<font color=\"brown\">.</font>');
                                portscan_ports_failed++;
                            }
                            portscan_curr_port++;
                            do_scan();
                        },
                        error: function (err){
                            write_to_iframe('<font color=\"brown\">.</font>');
                            portscan_ports_failed++;
                            portscan_curr_port++;
                            do_scan();
                        }
                    })
                } else {
                    if (portscan_ports_failed > 0) write_to_iframe('<br>');
                    portscan_curr_ip++;
                    do_ping();
                }
            }
        }
    //-->
    </script>
    ";
    echo "</body>\n</html>";
}
// +--------------------------------------------------
// | Shell Form Functions
// +--------------------------------------------------
function error_handler($err, $message, $file, $line) {
    global $stop;
    $stop = true;
    $content = explode("\n", file_get_contents($file));
    header('Content-Type: application/json');
    $id = extract_id(); // don't need to parse
    ob_end_clean();
    echo response(null, $id, array(
       "code" => 100,
       "message" => "Server error",
       "error" => array(
          "name" => "PHPError",
          "code" => $err,
          "message" => $message,
          "file" => $file,
          "at" => $line,
          "line" => $content[$line-1]))
    );
    exit();
}
class JsonRpcExeption extends Exception {
    function __construct($code, $message) {
        $this->code = $code;
        Exception::__construct($message);
    }
    function code() {
        return $this->code;
    }
}
function json_error() {
    switch (json_last_error()) {
    case JSON_ERROR_NONE:
        return 'No error has occurred';
    case JSON_ERROR_DEPTH:
        return 'The maximum stack depth has been exceeded';
    case JSON_ERROR_CTRL_CHAR:
        return 'Control character error, possibly incorrectly encoded';
    case JSON_ERROR_SYNTAX:
        return 'Syntax error';
    case JSON_ERROR_UTF8:
        return 'Malformed UTF-8 characters, possibly incorrectly encoded';
    }
}
function get_raw_post_data() {
    if (isset($GLOBALS['HTTP_RAW_POST_DATA'])) {
        return $GLOBALS['HTTP_RAW_POST_DATA'];
    } else {
        return file_get_contents('php://input');
    }
}
function has_field($object, $field) {
    return array_key_exists($field, get_object_vars($object));
}
function get_field($object, $field, $default) {
    $array = get_object_vars($object);
    if (isset($array[$field])) {
        return $array[$field];
    } else {
        return $default;
    }
}
function extract_id() {
    $regex = '/[\'"]id[\'"] *: *([0-9]*)/';
    $raw_data = get_raw_post_data();
    if (preg_match($regex, $raw_data, $m)) {
        return $m[1];
    } else {
        return null;
    }
}
function currentURL() {
    $pageURL = 'http';
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == "on") {
        $pageURL .= "s";
    }
    $pageURL .= "://";
    if ($_SERVER['SERVER_PORT'] != "80") {
        $pageURL .= $_SERVER['SERVER_NAME'].":".$_SERVER['SERVER_PORT'].$_SERVER['REQUEST_URI'];
    } else {
        $pageURL .= $_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
    }
    return $pageURL;
}
function service_description($object) {
    $class_name = get_class($object);
    $methods = get_class_methods($class_name);
    $service = array("sdversion" => "1.0",
                     "name" => "ShellService",
                     "address" => currentURL(),
                     "id" => "urn:md5:" . md5(currentURL()));
    $static = get_class_vars($class_name);
    foreach ($methods as $method_name) {
        $proc = array("name" => $method_name);
        $method = new ReflectionMethod($class_name, $method_name);
        $params = array();
        foreach ($method->getParameters() as $param) {
            $params[] = $param->name;
        }
        $proc['params'] = $params;
        $help_str_name = $method_name . "_documentation";
        if (array_key_exists($help_str_name, $static)) {
            $proc['help'] = $static[$help_str_name];
        }
        $service['procs'][] = $proc;
    }
    return $service;
}
function get_json_request() {
    $request = get_raw_post_data();
    if ($request == "") {
        throw new JsonRpcExeption(101, "Parse Error: no data");
    }
    $encoding = mb_detect_encoding($request, 'auto');
    //convert to unicode
    if ($encoding != 'UTF-8') {
        $request = iconv($encoding, 'UTF-8', $request);
    }
    $request = json_decode($request);
    if ($request == NULL) { // parse error
        $error = json_error();
        throw new JsonRpcExeption(101, "Parse Error: $error");
    }
    return $request;
}
function get_absolute_path($path) {
    global $is_windows;
    $path = str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $path);
    $parts = array_filter(explode(DIRECTORY_SEPARATOR, $path), 'strlen');
    $absolutes = array();
    foreach ($parts as $part) {
        if ('.' == $part) continue;
        if ('..' == $part) {
            array_pop($absolutes);
        } else {
            $absolutes[] = $part;
        }
    }
    $path = '';
    if (count($absolutes)) $path = implode(DIRECTORY_SEPARATOR, $absolutes).DIRECTORY_SEPARATOR;
    if (!$is_windows) $path = DIRECTORY_SEPARATOR.$path;
    return $path;
}
function cmd_proc_open_exec($cmd, &$stdout, &$stderr) {
    $tmp_dir = ini_get('session.save_path') ? ini_get('session.save_path') : sys_get_temp_dir();
    $outfile = tempnam($tmp_dir,"cmd");
    $errfile = tempnam($tmp_dir,"cmd");
    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("file", $outfile, "w"),
        2 => array("file", $errfile, "w")
    );
    $proc = proc_open($cmd, $descriptorspec, $pipes);
    if (!is_resource($proc)) return 255;
    fclose($pipes[0]);    //Don't really want to give any input
    $exit = proc_close($proc);
    $stdout = file_get_contents($outfile);
    $stderr = file_get_contents($errfile);
    @unlink($outfile);
    @unlink($errfile);
    return $exit;
}
function cmd_popen_exec($cmd, &$output){
    if ($handle = popen($cmd,"r")){
        while (!feof($handle)) {
            $output .= fgets($handle, 4096);
        }
        pclose($handle);
        return true;
    }
    return false;
}
if($is_windows && !function_exists('pcntl_exec') && class_exists('COM')){
    function pcntl_exec($path, $args=array()){
        if(is_string($args)) $args = array($args);
        if(count($args)) $path = '"'.$path.'"';
        $shell = new COM('WScript.Shell');
        if ($shell->run($path.(count($args) ? ' '.implode(' ',$args) : ''),0,true)) return NULL;
        else return false;
    }
}
function cmd_pcntl_exec($cmd, $args=array()){ // Does not provide output, could throw it to a file!
    if(is_string($args)) $args = array($args);
    $envs = array();
    if (pcntl_exec($cmd, $args, $envs) === NULL) return true;
    return false;
}
function system_exec_cmd($cmd, &$output){
    fb_log('system_exec_cmd: '.$cmd);
    $exec_ok = false;
    if (strlen($cmd)) {
        if (function_exists('proc_open')) {
            $stdout = $stderr = '';
            $exitCode = cmd_proc_open_exec($cmd, $stdout, $stderr);
            $exec_ok = (intval($exitCode) == 0); // 0 = success
            $output = trim($stdout);
            if (strlen($stderr)) {
                if (strlen($output)) $output .= "\n";
                $output .= trim($stderr);
            }
        } else {
            if (strpos($cmd,'2>&1') === false) {
                $cmd .= ' 2>&1';
            }
            if (function_exists('exec')) {
                $outputArr = array();
                $exitCode = 1;
                @exec($cmd, $outputArr, $exitCode);
                $exec_ok = (intval($exitCode) == 0); // 0 = success
                $output = trim(implode("\n",$outputArr));
            } elseif (function_exists('shell_exec')) {
                // The backtick operator is disabled when safe mode is enabled or shell_exec() is disabled.
                $output = @shell_exec($cmd);
                if ($output === NULL){
                    $output = '';
                    $exec_ok = false;
                } else {
                    $exec_ok = true;
                }
            } elseif (function_exists('system')) {
                @ob_clean();
                $last_output_line = @system($cmd,$exitCode);
                $output = @ob_get_contents();
                @ob_clean();
                $exec_ok = ($last_output_line !== false);
                $exec_ok = (intval($exitCode) == 0); // 0 = success
            } elseif (function_exists('passthru')) {
                @ob_clean();
                @passthru($cmd, $exitCode);
                $output = @ob_get_contents();
                @ob_clean();
                $exec_ok = (intval($exitCode) == 0); // 0 = success
            } elseif (function_exists('popen')) {
                $exec_ok = cmd_popen_exec($cmd, $output);
            } else {
                $output = "Error: PHP system exec functions are disabled.";
            }
        }
    }
    $output = trim($output);
    return $exec_ok;
}
function handle_json_rpc() {
    global $fm_current_dir,$cmd_line,$is_windows;
    @set_error_handler('error_handler');
    try {
        $input = get_json_request();
        header('Content-Type: application/json');
        $method = get_field($input, 'method', null);
        $params = get_field($input, 'params', null);
        $id = get_field($input, 'id', null);
        // json rpc error
        if (!($method && $id)) {
            if (!$id) {
                $id = extract_id();
            }
            if (!$method) {
                $error = "no method";
            } else if (!$id) {
                $error = "no id";
            } else {
                $error = "unknown reason";
            }
            throw new JsonRpcExeption(103,"Invalid Request: $error");
            //": " . $GLOBALS['HTTP_RAW_POST_DATA']));
        }
        // fix params (if params is null set it to empty array)
        if (!$params) {
            $params = array();
        }
        // if params is object change it to array
        if (is_object($params)) {
            if (count(get_object_vars($params)) == 0) {
                $params = array();
            } else {
                $params = get_object_vars($params);
            }
        }
        $fm_current_dir = get_absolute_path($fm_current_dir);
        $cmd_line = '';
        if ($is_windows) {
            $cmd_line .= "cd /D ".$fm_current_dir." && ";
        } else {
            $cmd_line .= "cd ".$fm_current_dir." && ";
        }
        $cmd_line .= $method." ".implode(" ", $params);
        if ($is_windows && strlen($method) == 2 && count($params) == 0){
            $drive = uppercase($method[0]);
            if (strpos($method,':') === 1 && strpos("ABCDEFGHIJKLMNOPQRSTUVWXYZ",$drive) !== false){
                $fm_current_dir = get_absolute_path($drive.':');
                $cmd_line = '';
            }
        } elseif (lowercase($method) == 'cd' && count($params) > 0){
            $arg = implode(' ',$params);
            if (strlen($arg)){
                if ($is_windows){
                    $drive = uppercase($arg[0]);
                    if (strpos($arg,':') === 1 && strpos("ABCDEFGHIJKLMNOPQRSTUVWXYZ",$drive) !== false){
                        $fm_current_dir = get_absolute_path($drive.':'.DIRECTORY_SEPARATOR.substr($arg,2));
                    } else {
                        $fm_current_dir = get_absolute_path($fm_current_dir.DIRECTORY_SEPARATOR.$arg);
                    }
                } else {
                    if (strpos($arg,'/') === 0){
                        $fm_current_dir = $arg;
                    } else {
                        $fm_current_dir = get_absolute_path($fm_current_dir.DIRECTORY_SEPARATOR.$arg);
                    }
                }
                $cmd_line = '';
            }
        }
        $output = '';
        $exec_ok = system_exec_cmd($cmd_line, $output);
        echo response($output, $id, null);
    } catch (JsonRpcExeption $e) {
        // exteption with error code
        $msg = $e->getMessage();
        $code = $e->code();
        if ($code = 101) { // parse error;
            $id = extract_id();
        }
        echo response(null, $id, array("name"=>"JSONRPCError", "code"=>$code, "message"=>$msg));
    } catch (Exception $e) {
        //catch all exeption from user code
        $msg = $e->getMessage();
        echo response(null, $id, array("name"=>"JSONRPCError", "code"=>200, "message"=>$msg));
    }
}
function response($result, $id, $error) {
    global $fm_current_dir,$cmd_line,$is_windows;
    // Se o path não é raiz no linux ou raiz de drive no windows, remove o ultimo separador da direita
    if ($is_windows){
        if (strlen($fm_current_dir) > 3){
            $fm_current_dir = rtrim($fm_current_dir,DIRECTORY_SEPARATOR);
        }
    } elseif (strlen($fm_current_dir) > 1) {
        $fm_current_dir = rtrim($fm_current_dir,DIRECTORY_SEPARATOR);
    }
    return json_encode(array('cmd_line' => $cmd_line,
                             'fm_current_dir' => $fm_current_dir,
                             'result' => $result,
                             'jsonrpc' => '2.0',
                             'id' => $id,
                             'error'=> $error));
}
function shell_form(){
    global $fm_current_dir,$shell_form,$cmd_arg,$fm_path_info,$is_windows;
    switch ($shell_form){
        case 1:
            handle_json_rpc();
            exit();
        break;
        default:
            html_header("
                <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=jquery-1.11.1.min.js\"></script>
                <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=jquery.terminal.min.js\"></script>
                <link rel=\"stylesheet\" type=\"text/css\" href=\"".$fm_path_info['basename']."?action=99&filename=jquery.terminal.min.css\" media=\"screen\" />
            ");
            is_rwx_phpfm(__FILE__); // Init $GLOBALS['script_info']
            $username = $GLOBALS['script_info']['script_user_name'];
            $groupname = $GLOBALS['script_info']['script_group_name'];
            $hostname = $GLOBALS['script_info']['sys_hostname'];
            $ugh = '';
            if (strlen($username)) $ugh .= $username;
            if (strlen($groupname)) $ugh .= ':'.$groupname;
            if (strlen($hostname)) $ugh .= '@'.$hostname;
            $prompt_start = '[';
            if ($username == 'root') $prompt_end .= ']# ';
            else $prompt_end .= ']$ ';
            $greetings = array();
            $greetings[] = 'PHP File Manager - Shell Terminal Emulator';
            $greetings[] = '';
            if (strlen($username)) $greetings[] = 'User: '.$username;
            if (strlen($groupname)) $greetings[] = 'Group: '.$groupname;
            if (strlen($hostname)) $greetings[] = 'Host: '.$hostname;
            $exec_functions = array('proc_open','exec','shell_exec','system','passthru','popen');
            $is_exec_disabled = true;
            foreach ($exec_functions as $f) {
                if (function_exists($f)) {
                    $is_exec_disabled = false;
                    break;
                }
            }
            if ($is_exec_disabled) {
                $greetings[] = '';
                $greetings[] = 'Warning: All PHP system exec functions are disabled.';
                $greetings[] = implode('(),',$exec_functions).'()';
            }
            $shell_current_dir = $fm_current_dir;
            if (strlen($_COOKIE['shell_current_dir'])) $shell_current_dir = $_COOKIE['shell_current_dir'];
            ?>
            <body marginwidth="0" marginheight="0">
                <style>
                    .cmd, .cmd div, .cmd span, .terminal, .terminal span, .terminal-output span {
                        font-family: Courier New !important;
                        font-size: 10pt !important;
                    }
                </style>
                <script>
                    function get_boxed_text(str){
                        str = String(str);
                        var br = String.fromCharCode(10);
                        var arr = str.split(br);
                        var max_str_length = 0;
                        for(var i=0;i<arr.length;i++){
                            arr[i] = String(arr[i]);
                            if (arr[i].length > max_str_length) max_str_length = arr[i].length;
                        }
                        var out = '';
                        out += '┌'+rep('─',max_str_length+2)+'┐'+br;
                        for(var i=0;i<arr.length;i++){
                            out += '│ '+arr[i]+rep('&nbsp;',(max_str_length-arr[i].length))+' │';
                            if (i<arr.length) out += br;
                        }
                        out += '└'+rep('─',max_str_length+2)+'┘'+br;
                        return out;
                    }
                    var shell_current_dir = '<?php echo addslashes(rtrim($shell_current_dir,DIRECTORY_SEPARATOR)); ?>';
                    jQuery(document).ready(function($) {
                        $('body').terminal(
                            function(command, term) {
                                if (command){
                                    term.pause();
                                    var params = String(command).split(' ');
                                    var method = params.shift();
                                    var timestamp = new Date().getTime();
                                    $.ajax({
                                        type: 'POST',
                                        url: '<?php echo $fm_path_info['basename']; ?>?action=9&shell_form=1&fm_current_dir='+shell_current_dir,
                                        dataType: 'json',
                                        crossDomain: false,
                                        data: JSON.stringify(
                                            {
                                                jsonrpc: '2.0',
                                                method: method,
                                                params: params,
                                                id: timestamp
                                            }
                                        ),
                                        success: function (data){
                                            if (data.error !== null){
                                                if (data.error.code == 100) term.echo(data.error.error.name+': '+data.error.error.message).resume(); // Server Error
                                                else term.echo(data.error.name+': '+data.error.message).resume();
                                            } else {
                                                shell_current_dir = data.fm_current_dir;
                                                setCookie('shell_current_dir',shell_current_dir);
                                                term.echo(data.result).resume();
                                            }
                                        },
                                        error: function (err){
                                            term.echo(err).resume();
                                        }
                                    });
                                }
                            },
                            {
                                greetings: get_boxed_text('<?php echo implode('\n',$greetings)?>'),
                                prompt: function(callback) {
                                    //console.log(shell_current_dir);
                                    callback('<?php echo $prompt_start; ?>'+shell_current_dir+'<?php echo $prompt_end; ?>');
                                },
                                name: 'shell',
                                tabcompletion: true,
                                login: false,
                                exit: false,
                                history: true,
                                convertLinks: false,
                                completion: function(terminal, command, callback) {
                                    callback(['Sorry, no tab completion...']);
                                },
                                onBlur: function() {
                                    // the height of the body is only 2 lines initialy
                                    return false;
                                }
                            }
                        );
                    });
                </script>
            <?php
            echo "</body>\n</html>";
        break;
    }
}
function server_info_form(){
    if (!@phpinfo()) echo et('NoPhpinfo')."...";
    echo "<br><br>";
        $a=ini_get_all();
        $output="<table border=1 cellspacing=0 cellpadding=4 align=center>";
        $output.="<tr><th colspan=2>ini_get_all()</td></tr>";
        while(list($key, $value)=each($a)) {
            list($k, $v)= each($a[$key]);
            $output.="<tr><td align=right>$key</td><td>$v</td></tr>";
        }
        $output.="</table>";
    echo $output;
    echo "<br><br>";
        $output="<table border=1 cellspacing=0 cellpadding=4 align=center>";
        $output.="<tr><th colspan=2>\$_SERVER</td></tr>";
        foreach ($_SERVER as $k=>$v) {
            $output.="<tr><td align=right>$k</td><td>$v</td></tr>";
        }
        $output.="</table>";
    echo $output;
    echo "<br><br>";
    echo "<table border=1 cellspacing=0 cellpadding=4 align=center>";
    $safe_mode=trim(ini_get("safe_mode"));
    if ((strlen($safe_mode)==0)||($safe_mode==0)) $safe_mode=false;
    else $safe_mode=true;
    $is_windows = (uppercase(substr(PHP_OS, 0, 3)) === 'WIN');
    echo "<tr><td colspan=2>".php_uname();
    echo "<tr><td>safe_mode<td>".($safe_mode?"on":"off");
    if ($is_windows) echo "<tr><td>sisop<td>Windows<br>";
    else echo "<tr><td>sisop<td>Linux<br>";
    echo "</table><br><br><table border=1 cellspacing=0 cellpadding=4 align=center>";
    $display_errors=ini_get("display_errors");
    $ignore_user_abort = ignore_user_abort();
    $max_execution_time = ini_get("max_execution_time");
    $upload_max_filesize = ini_get("upload_max_filesize");
    $memory_limit=ini_get("memory_limit");
    $output_buffering=ini_get("output_buffering");
    $default_socket_timeout=ini_get("default_socket_timeout");
    $allow_url_fopen = ini_get("allow_url_fopen");
    $magic_quotes_gpc = ini_get("magic_quotes_gpc");
    ignore_user_abort(true);
    ini_set("display_errors",0);
    ini_set("max_execution_time",0);
    ini_set("upload_max_filesize","10M");
    ini_set("memory_limit","20M");
    ini_set("output_buffering",0);
    ini_set("default_socket_timeout",30);
    ini_set("allow_url_fopen",1);
    ini_set("magic_quotes_gpc",0);
    echo "<tr><td colspan=4 align=center>Server Config Overwrite Test";
    echo "<tr><td> <td>Get<td>Set<td>Get";
    echo "<tr><td>display_errors<td>$display_errors<td>0<td>".ini_get("display_errors");
    echo "<tr><td>ignore_user_abort<td>".($ignore_user_abort?"on":"off")."<td>on<td>".(ignore_user_abort()?"on":"off");
    echo "<tr><td>max_execution_time<td>$max_execution_time<td>0<td>".ini_get("max_execution_time");
    echo "<tr><td>upload_max_filesize<td>$upload_max_filesize<td>10M<td>".ini_get("upload_max_filesize");
    echo "<tr><td>memory_limit<td>$memory_limit<td>20M<td>".ini_get("memory_limit");
    echo "<tr><td>output_buffering<td>$output_buffering<td>0<td>".ini_get("output_buffering");
    echo "<tr><td>default_socket_timeout<td>$default_socket_timeout<td>30<td>".ini_get("default_socket_timeout");
    echo "<tr><td>allow_url_fopen<td>$allow_url_fopen<td>1<td>".ini_get("allow_url_fopen");
    echo "<tr><td>magic_quotes_gpc<td>$magic_quotes_gpc<td>0<td>".ini_get("magic_quotes_gpc");
    echo "</table><br><br>";
    echo "</body>\n</html>";
}
// +--------------------------------------------------
// | Session
// +--------------------------------------------------
function logout(){
    global $fm_path_info;
    setcookie("loggedon",0,0,"/");
    echo "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        window.parent.document.location.href='".$fm_path_info['basename']."';
    //-->
    </script>";
}
function login(){
    global $pass,$auth_pass,$fm_path_info;
    if (md5(trim($pass)) == $auth_pass){
        setcookie("loggedon",$auth_pass,0,"/");
        header ("Location: ".$fm_path_info['basename']);
        return true;
    } else header ("Location: ".$fm_path_info['basename']."?erro=1");
    return false;
}
function login_form(){
    global $erro,$auth_pass,$loggedon,$fm_path_info,$noscript,$version;
    html_header();
    echo "
    <body>";
    if ($noscript && ($auth_pass == md5('') || $loggedon==$auth_pass)) {
        echo "
        <table border=0 cellspacing=0 cellpadding=5>
            <tr><td><font size=4>".et('FileMan')."</font></td></tr>
            <tr><td align=left><font color=red size=3>Error: No Javascript support...</font></td></tr>
        </table>
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            window.parent.document.location.href='".$fm_path_info['basename']."';
        //-->
        </script>";
    } else {
        echo "
        <form class=\"form-signin noScriptHidden mt-4\" name=\"login_form\" action=\"" . $fm_path_info['basename'] . "\" method=\"post\">
            <h2 class=\"form-signin-heading text-center\">".et('FileMan')."</h2>
            <input type=\"password\" class=\"form-control\" name=\"pass\" placeholder=\"".et('Pass')."\" required=\"\"/>
            <button type=\"submit\" class=\"btn noIcon\" style=\"float:right\" value=\"".et('Login')."\">".et('Login')."</button>
            <div style=\"clear:both\"></div>";
        if (strlen($erro)) echo "
            <div class=\"alert alert-danger\" style=\"margin-top: 10px;\">".et('InvPass')."</div>";
        echo "
        </form>
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            document.login_form.pass.focus();
        //-->
        </script>";
        echo "
        <noscript>
            <style>
                .noScriptHidden { display:none }
            </style>
            <table border=0 cellspacing=0 cellpadding=5>
                <tr><td><font size=4>".et('FileMan')."</font></td></tr>
                <tr><td align=left><font color=red size=3>Error: No Javascript support...</font></td></tr>
            </table>
        </noscript>";
    }
    echo "
    </body>
    </html>";
}
function frame3(){
    global $is_windows,$cmd_arg,$chmod_arg,$zip_dir,$fm_current_root,$cookie_cache_time;
    global $dir_dest,$fm_current_dir,$dir_before;
    global $selected_file_list,$selected_dir_list,$old_name,$new_name;
    global $action,$or_by,$order_dir_list_by;
    global $about_form_was_shown;
    // ZIP download
    if ($action == '73') {
        ignore_user_abort(true);
        ini_set("display_errors",0);
        ini_set("max_execution_time",0);
        $filename = trim(str_replace(DIRECTORY_SEPARATOR,'-',$fm_current_dir),'-');
        $filename = str_replace(':','-',$filename);
        $filename = replace_double('-',$filename);
        $filename = trim($filename,'-').'-'.date('Y.m.d-H\hi').'.zip';
        $file = new zip_file($filename);
        if ($file){
            $file->set_options(array('basedir'=>$fm_current_dir,'overwrite'=>1,'level'=>3,'inmemory'=>1));
            if (strlen($selected_file_list)){
                $selected_file_list = explode("<|*|>",$selected_file_list);
                if (count($selected_file_list)) {
                    for($x=0;$x<count($selected_file_list);$x++) {
                        $selected_file_list[$x] = trim($selected_file_list[$x]);
                        if (strlen($selected_file_list[$x])) $file->add_files($selected_file_list[$x]);
                    }
                }
            }
            if (strlen($selected_dir_list)){
                $selected_dir_list = explode("<|*|>",$selected_dir_list);
                if (count($selected_dir_list)) {
                    for($x=0;$x<count($selected_dir_list);$x++) {
                        $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                        if (strlen($selected_dir_list[$x])) $file->add_files($selected_dir_list[$x]);
                    }
                }
            }
            $file->create_archive();
            $file->download_file();
            exit();
        }
    }
    $about_form_was_shown = intval($about_form_was_shown);
    if (!$about_form_was_shown){
        setcookie("about_form_was_shown", '1' , time()+$cookie_cache_time , "/");
    }
    if (!isset($order_dir_list_by)){
        $order_dir_list_by = "1A";
        setcookie("order_dir_list_by", $order_dir_list_by , time()+$cookie_cache_time , "/");
    } elseif (strlen($or_by)){
        $order_dir_list_by = $or_by;
        setcookie("order_dir_list_by", $or_by , time()+$cookie_cache_time , "/");
    }
    setcookie("fm_current_dir", $fm_current_dir, 0 , "/");
    html_header("
        <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=jquery-1.11.1.min.js\"></script>
    ");
    echo "<body>\n";
    $GLOBALS['dir_list_warn_message'] = '';
    if ($action){
        switch ($action){
            case 1: // create dir
            $cmd_arg = fix_filename($cmd_arg);
            if (strlen($cmd_arg)){
                $cmd_arg = $fm_current_dir.$cmd_arg;
                if (!file_exists($cmd_arg)){
                    @mkdir(fs_encode($cmd_arg),0755,true);
                    @chmod(fs_encode($cmd_arg),0755);
                    reloadframe("parent",2,"&ec_dir=".$cmd_arg);
                } else alert(et('FileDirExists').".");
            }
            break;
            case 2: // create arq
            $cmd_arg = fix_filename($cmd_arg);
            if (strlen($cmd_arg)){
                $cmd_arg = $fm_current_dir.$cmd_arg;
                if (!file_exists($cmd_arg)){
                    @touch($cmd_arg);
                    @chmod($cmd_arg,0644);
                } else alert(et('FileDirExists').".");
            }
            break;
            case 3: // rename arq ou dir
            if ((strlen($old_name))&&(strlen($new_name))){
                rename($fm_current_dir.$old_name,$fm_current_dir.$new_name);
                if (is_dir($fm_current_dir.$new_name) || is_link($fm_current_dir.$new_name)) reloadframe("parent",2);
            }
            break;
            case 4: // delete sel
            if(strstr($fm_current_dir,$fm_current_root)){
                if (strlen($selected_file_list)){
                    $selected_file_list = explode("<|*|>",$selected_file_list);
                    if (count($selected_file_list)) {
                        for($x=0;$x<count($selected_file_list);$x++) {
                            $selected_file_list[$x] = trim($selected_file_list[$x]);
                            if (strlen($selected_file_list[$x])) total_delete($fm_current_dir.$selected_file_list[$x]);
                        }
                    }
                }
                if (strlen($selected_dir_list)){
                    $selected_dir_list = explode("<|*|>",$selected_dir_list);
                    if (count($selected_dir_list)) {
                        for($x=0;$x<count($selected_dir_list);$x++) {
                            $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                            if (strlen($selected_dir_list[$x])) total_delete($fm_current_dir.$selected_dir_list[$x]);
                        }
                        reloadframe("parent",2);
                    }
                }
            }
            break;
            case 5: // copy sel
            if (strlen($dir_dest)){
                if(uppercase($dir_dest) != uppercase($fm_current_dir)){
                    if (strlen($selected_file_list)){
                        $selected_file_list = explode("<|*|>",$selected_file_list);
                        if (count($selected_file_list)) {
                            for($x=0;$x<count($selected_file_list);$x++) {
                                $selected_file_list[$x] = trim($selected_file_list[$x]);
                                if (strlen($selected_file_list[$x])) total_copy($fm_current_dir.$selected_file_list[$x],$dir_dest.$selected_file_list[$x]);
                            }
                        }
                    }
                    if (strlen($selected_dir_list)){
                        $selected_dir_list = explode("<|*|>",$selected_dir_list);
                        if (count($selected_dir_list)) {
                            for($x=0;$x<count($selected_dir_list);$x++) {
                                $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                                if (strlen($selected_dir_list[$x])) total_copy($fm_current_dir.$selected_dir_list[$x],$dir_dest.$selected_dir_list[$x]);
                            }
                            reloadframe("parent",2);
                        }
                    }
                    $fm_current_dir = $dir_dest;
                }
            }
            break;
            case 6: // move sel
            if (strlen($dir_dest)){
                if(uppercase($dir_dest) != uppercase($fm_current_dir)){
                    if (strlen($selected_file_list)){
                        $selected_file_list = explode("<|*|>",$selected_file_list);
                        if (count($selected_file_list)) {
                            for($x=0;$x<count($selected_file_list);$x++) {
                                $selected_file_list[$x] = trim($selected_file_list[$x]);
                                if (strlen($selected_file_list[$x])) total_move($fm_current_dir.$selected_file_list[$x],$dir_dest.$selected_file_list[$x]);
                            }
                        }
                    }
                    if (strlen($selected_dir_list)){
                        $selected_dir_list = explode("<|*|>",$selected_dir_list);
                        if (count($selected_dir_list)) {
                            for($x=0;$x<count($selected_dir_list);$x++) {
                                $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                                if (strlen($selected_dir_list[$x])) total_move($fm_current_dir.$selected_dir_list[$x],$dir_dest.$selected_dir_list[$x]);
                            }
                            reloadframe("parent",2);
                        }
                    }
                    $fm_current_dir = $dir_dest;
                }
            }
            break;
            case 71: // compress sel
            if (strlen($cmd_arg)){
                ignore_user_abort(true);
                ini_set("display_errors",0);
                ini_set("max_execution_time",0);
                $file = false;
                if (strstr($cmd_arg,".tar")) $file = new tar_file($cmd_arg);
                elseif (strstr($cmd_arg,".zip")) $file = new zip_file($cmd_arg);
                elseif (strstr($cmd_arg,".bzip")) $file = new bzip_file($cmd_arg);
                elseif (strstr($cmd_arg,".gzip")) $file = new gzip_file($cmd_arg);
                if ($file){
                    $file->set_options(array('basedir'=>$fm_current_dir,'overwrite'=>1,'level'=>3));
                    if (strlen($selected_file_list)){
                        $selected_file_list = explode("<|*|>",$selected_file_list);
                        if (count($selected_file_list)) {
                            for($x=0;$x<count($selected_file_list);$x++) {
                                $selected_file_list[$x] = trim($selected_file_list[$x]);
                                if (strlen($selected_file_list[$x])) $file->add_files($selected_file_list[$x]);
                            }
                        }
                    }
                    if (strlen($selected_dir_list)){
                        $selected_dir_list = explode("<|*|>",$selected_dir_list);
                        if (count($selected_dir_list)) {
                            for($x=0;$x<count($selected_dir_list);$x++) {
                                $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                                if (strlen($selected_dir_list[$x])) $file->add_files($selected_dir_list[$x]);
                            }
                        }
                    }
                    $file->create_archive();
                }
                unset($file);
            }
            break;
            case 72: // decompress arq
            if (strlen($cmd_arg)){
                if (file_exists($fm_current_dir.$cmd_arg)){
                    if (strstr($cmd_arg,".zip") && class_exists('ZipArchive')) {
                        $zipArchive = new ZipArchive();
                        if ($zipArchive->open($cmd_arg) === true) {
                            $zipArchive->extractTo($fm_current_dir);
                            $zipArchive->close();
                        }
                    } else {
                        if (strstr($cmd_arg,".bzip")||strstr($cmd_arg,".bz2")||strstr($cmd_arg,".tbz2")||strstr($cmd_arg,".bz")||strstr($cmd_arg,".tbz")) $file = new bzip_file($cmd_arg);
                        elseif (strstr($cmd_arg,".gzip")||strstr($cmd_arg,".gz")||strstr($cmd_arg,".tgz")) $file = new gzip_file($cmd_arg);
                        elseif (strstr($cmd_arg,".tar")) $file = new tar_file($cmd_arg);
                        if ($file){
                            $file->set_options(array('basedir'=>$fm_current_dir,'overwrite'=>1));
                            $file->extract_files();
                        }
                        unset($file);
                    }
                    reloadframe("parent",2);
                }
            }
            break;
            case 8: // delete folder/file
            if (strlen($cmd_arg)){
                total_delete($fm_current_dir.$cmd_arg);
                reloadframe("parent",2);
            }
            break;
            case 9: // CHMOD
            if((strlen($chmod_arg) == 4)&&(strlen($fm_current_dir))){
                if ($chmod_arg[0]=="1") $chmod_arg = "0".$chmod_arg;
                else $chmod_arg = "0".substr($chmod_arg,strlen($chmod_arg)-3);
                $new_mod = octdec($chmod_arg);
                if (strlen($selected_file_list)){
                    $selected_file_list = explode("<|*|>",$selected_file_list);
                    if (count($selected_file_list)) {
                        for($x=0;$x<count($selected_file_list);$x++) {
                            $selected_file_list[$x] = trim($selected_file_list[$x]);
                            if (strlen($selected_file_list[$x])) @chmod($fm_current_dir.$selected_file_list[$x],$new_mod);
                        }
                    }
                }
                if (strlen($selected_dir_list)){
                    $selected_dir_list = explode("<|*|>",$selected_dir_list);
                    if (count($selected_dir_list)) {
                        for($x=0;$x<count($selected_dir_list);$x++) {
                            $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                            if (strlen($selected_dir_list[$x])) @chmod($fm_current_dir.$selected_dir_list[$x],$new_mod);
                        }
                    }
                }
            }
            break;
            case 121: // Symlink
            case 122: // Hardlink
            $allow_links_to_links = true; // TODO: readlink() recursive
            $cmd_arg = fix_filename($cmd_arg);
            if (strlen($dir_dest)){
                if (strlen($selected_file_list)){
                    $selected_file_list = explode("<|*|>",$selected_file_list);
                    if (count($selected_file_list)) {
                        for($x=0;$x<count($selected_file_list);$x++) {
                            $selected_file_list[$x] = trim($selected_file_list[$x]);
                            if (strlen($selected_file_list[$x])) {
                                $link_name = rtrim($dir_dest.$selected_file_list[$x],DIRECTORY_SEPARATOR);
                                if (count($selected_file_list) == 1 && strlen($cmd_arg)) {
                                    $link_name = rtrim($dir_dest.$cmd_arg,DIRECTORY_SEPARATOR);
                                }
                                if ($action == '121') symlink_phpfm($fm_current_dir.$selected_file_list[$x], $link_name);
                                else link_phpfm($fm_current_dir.$selected_file_list[$x], $link_name);
                            }
                        }
                    }
                }
                if (strlen($selected_dir_list)){
                    $selected_dir_list = explode("<|*|>",$selected_dir_list);
                    if (count($selected_dir_list)) {
                        for($x=0;$x<count($selected_dir_list);$x++) {
                            $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                            if (strlen($selected_dir_list[$x])) {
                                $link_name = rtrim($dir_dest.$selected_dir_list[$x],DIRECTORY_SEPARATOR);
                                if (count($selected_dir_list) == 1 && strlen($cmd_arg)) {
                                    $link_name = rtrim($dir_dest.$cmd_arg,DIRECTORY_SEPARATOR);
                                }
                                if ($action == '121') symlink_phpfm($fm_current_dir.$selected_dir_list[$x], $link_name);
                                else link_phpfm($fm_current_dir.$selected_dir_list[$x], $link_name);
                            }

                        }
                        reloadframe("parent",2);
                    }
                }
                $fm_current_dir = $dir_dest;
            }
            break;
        }
        if ($action != 10) {
            dir_list_form();
        }
    } else {
        dir_list_form();
    }
    if (!$about_form_was_shown) {
        echo "
        <script language=\"Javascript\" type=\"text/javascript\">
            about_form();
        </script>";
    }
    echo "
    </body>\n</html>";
}
function frameset(){
    global $fm_path_info,$leftFrameWidth;
    if (!isset($leftFrameWidth)) $leftFrameWidth = 300;
    html_header("
    <noscript>
        <meta http-equiv=\"refresh\" content=\"0;url=".$fm_path_info['basename']."?noscript=1\">
    </noscript>
    ");
    echo "
    <frameset cols=\"".$leftFrameWidth.",*\" framespacing=\"0\">
        <frameset rows=\"0,*\" framespacing=\"0\" frameborder=\"0\">
            <frame src=\"".$fm_path_info['basename']."?frame=1\" name=frame1 border=\"0\" marginwidth=\"0\" marginheight=\"0\" scrolling=\"no\">
            <frame src=\"".$fm_path_info['basename']."?frame=2\" name=frame2 border=\"0\" marginwidth=\"0\" marginheight=\"0\">
        </frameset>
        <frame src=\"".$fm_path_info['basename']."?frame=3\" name=frame3 border=\"0\" marginwidth=\"0\" marginheight=\"0\">
    </frameset>
    </html>";
}
// +--------------------------------------------------
// | Open Source Contributions
// +--------------------------------------------------
/*-------------------------------------------------
| TAR/GZIP/BZIP2/ZIP ARCHIVE CLASSES 2.1
| By Devin Doucette
| Copyright (c) 2005 Devin Doucette
| Email: darksnoopy@shaw.ca
+--------------------------------------------------
| Email bugs/suggestions to darksnoopy@shaw.ca
+--------------------------------------------------
| This script has been created and released under
| the GNU GPL and is free to use and redistribute
| only if this copyright statement is not removed
+--------------------------------------------------*/
class archive {
    function __construct($name) {
        $this->options   = array(
            'basedir' => ".",
            'name' => $name,
            'prepend' => "",
            'inmemory' => 0,
            'overwrite' => 0,
            'recurse' => 1,
            'storepaths' => 1,
            'followlinks' => 0,
            'level' => 3,
            'method' => 1,
            'sfx' => "",
            'type' => "",
            'comment' => ""
        );
        $this->files     = array();
        $this->exclude   = array();
        $this->storeonly = array();
        $this->error     = array();
    }
    function set_options($options) {
        foreach ($options as $key => $value)
            $this->options[$key] = $value;
        if (!empty($this->options['basedir'])) {
            $this->options['basedir'] = str_replace("\\", "/", $this->options['basedir']);
            $this->options['basedir'] = preg_replace("/\/+/", "/", $this->options['basedir']);
            $this->options['basedir'] = preg_replace("/\/$/", "", $this->options['basedir']);
        }
        if (!empty($this->options['name'])) {
            $this->options['name'] = str_replace("\\", "/", $this->options['name']);
            $this->options['name'] = preg_replace("/\/+/", "/", $this->options['name']);
        }
        if (!empty($this->options['prepend'])) {
            $this->options['prepend'] = str_replace("\\", "/", $this->options['prepend']);
            $this->options['prepend'] = preg_replace("/^(\.*\/+)+/", "", $this->options['prepend']);
            $this->options['prepend'] = preg_replace("/\/+/", "/", $this->options['prepend']);
            $this->options['prepend'] = preg_replace("/\/$/", "", $this->options['prepend']) . "/";
        }
    }
    function create_archive() {
        $this->make_list();
        if ($this->options['inmemory'] == 0) {
            $pwd = getcwd();
            chdir($this->options['basedir']);
            if ($this->options['overwrite'] == 0 && file_exists($this->options['name'])) {
                $this->error[] = "File {$this->options['name']} already exists.";
                chdir($pwd);
                return 0;
            } else if ($this->archive = @fopen($this->options['name'], "wb+")) {
                chdir($pwd);
            } else {
                $this->error[] = "Could not open {$this->options['name']} for writing.";
                chdir($pwd);
                return 0;
            }
        } else {
            $this->archive = "";
        }
        switch ($this->options['type']) {
            case "zip":
                if (!$this->create_zip()) {
                    $this->error[] = "Could not create zip file.";
                    return 0;
                }
                break;
            case "bzip":
                if (!$this->create_tar()) {
                    $this->error[] = "Could not create tar file.";
                    return 0;
                }
                if (!$this->create_bzip()) {
                    $this->error[] = "Could not create bzip2 file.";
                    return 0;
                }
                break;
            case "gzip":
                if (!$this->create_tar()) {
                    $this->error[] = "Could not create tar file.";
                    return 0;
                }
                if (!$this->create_gzip()) {
                    $this->error[] = "Could not create gzip file.";
                    return 0;
                }
                break;
            case "tar":
                if (!$this->create_tar()) {
                    $this->error[] = "Could not create tar file.";
                    return 0;
                }
        }
        if ($this->options['inmemory'] == 0) {
            fclose($this->archive);
        }
    }
    function add_data($data) {
        if ($this->options['inmemory'] == 0)
            fwrite($this->archive, $data);
        else
            $this->archive .= $data;
    }
    function make_list() {
        if (!empty($this->exclude))
            foreach ($this->files as $key => $value)
                foreach ($this->exclude as $current)
                    if ($value['name'] == $current['name'])
                        unset($this->files[$key]);
        if (!empty($this->storeonly))
            foreach ($this->files as $key => $value)
                foreach ($this->storeonly as $current)
                    if ($value['name'] == $current['name'])
                        $this->files[$key]['method'] = 0;
        unset($this->exclude, $this->storeonly);
    }
    function add_files($list) {
        $temp = $this->list_files($list);
        foreach ($temp as $current)
            $this->files[] = $current;
    }
    function exclude_files($list) {
        $temp = $this->list_files($list);
        foreach ($temp as $current)
            $this->exclude[] = $current;
    }
    function store_files($list) {
        $temp = $this->list_files($list);
        foreach ($temp as $current)
            $this->storeonly[] = $current;
    }
    function list_files($list) {
        if (!is_array($list)) {
            $temp = $list;
            $list = array(
                $temp
            );
            unset($temp);
        }
        $files = array();
        $pwd   = getcwd();
        chdir($this->options['basedir']);
        foreach ($list as $current) {
            $current = str_replace("\\", "/", $current);
            $current = preg_replace("/\/+/", "/", $current);
            $current = preg_replace("/\/$/", "", $current);
            if (strstr($current, "*")) {
                $regex = preg_replace("/([\\\^\$\.\[\]\|\(\)\?\+\{\}\/])/", "\\\\\\1", $current);
                $regex = str_replace("*", ".*", $regex);
                $dir   = strstr($current, "/") ? substr($current, 0, strrpos($current, "/")) : ".";
                $temp  = $this->parse_dir($dir);
                foreach ($temp as $current2)
                    if (preg_match("/^{$regex}$/i", $current2['name']))
                        $files[] = $current2;
                unset($regex, $dir, $temp, $current);
            } else if (@is_dir($current)) {
                $temp = $this->parse_dir($current);
                foreach ($temp as $file)
                    $files[] = $file;
                unset($temp, $file);
            } else if (@file_exists($current))
                $files[] = array(
                    'name' => $current,
                    'name2' => $this->options['prepend'] . preg_replace("/(\.+\/+)+/", "", ($this->options['storepaths'] == 0 && strstr($current, "/")) ? substr($current, strrpos($current, "/") + 1) : $current),
                    'type' => @is_link($current) && $this->options['followlinks'] == 0 ? 2 : 0,
                    'ext' => substr($current, strrpos($current, ".")),
                    'stat' => stat($current)
                );
        }
        chdir($pwd);
        unset($current, $pwd);
        usort($files, array(
            "archive",
            "sort_files"
        ));
        return $files;
    }
    function parse_dir($dirname) {
        $files = array();
        if ($this->options['storepaths'] == 1 && !preg_match("/^(\.+\/*)+$/", $dirname)) {
            $files = array(
                array(
                    'name' => $dirname,
                    'name2' => $this->options['prepend'] . preg_replace("/(\.+\/+)+/", "", ($this->options['storepaths'] == 0 && strstr($dirname, "/")) ? substr($dirname, strrpos($dirname, "/") + 1) : $dirname),
                    'type' => 5,
                    'stat' => stat($dirname)
                )
            );
        }
        if ($dir = @opendir($dirname)){
            while (($file = @readdir($dir)) !== false) {
                $fullname = $dirname . "/" . $file;
                if ($file == "." || $file == "..")
                    continue;
                else if (@is_dir($fullname)) {
                    if (empty($this->options['recurse']))
                        continue;
                    $temp = $this->parse_dir($fullname);
                    foreach ($temp as $file2)
                        $files[] = $file2;
                } else if (@file_exists($fullname))
                    $files[] = array(
                        'name' => $fullname,
                        'name2' => $this->options['prepend'] . preg_replace("/(\.+\/+)+/", "", ($this->options['storepaths'] == 0 && strstr($fullname, "/")) ? substr($fullname, strrpos($fullname, "/") + 1) : $fullname),
                        'type' => @is_link($fullname) && $this->options['followlinks'] == 0 ? 2 : 0,
                        'ext' => substr($file, strrpos($file, ".")),
                        'stat' => stat($fullname)
                    );
            }
            @closedir($dir);
        }
        return $files;
    }
    function sort_files($a, $b) {
        if ($a['type'] != $b['type'])
            if ($a['type'] == 5 || $b['type'] == 2)
                return -1;
            else if ($a['type'] == 2 || $b['type'] == 5)
                return 1;
            else if ($a['type'] == 5)
                return strcmp(strtolower($a['name']), strtolower($b['name']));
            else if ($a['ext'] != $b['ext'])
                return strcmp($a['ext'], $b['ext']);
            else if ($a['stat'][7] != $b['stat'][7])
                return $a['stat'][7] > $b['stat'][7] ? -1 : 1;
            else
                return strcmp(strtolower($a['name']), strtolower($b['name']));
        return 0;
    }
    function download_file() {
        if ($this->options['inmemory'] == 0) {
            $this->error[] = "Can only use download_file() if archive is in memory. Redirect to file otherwise, it is faster.";
            return;
        }
        switch ($this->options['type']) {
            case "zip":
                header("Content-Type: application/zip");
                break;
            case "bzip":
                header("Content-Type: application/x-bzip2");
                break;
            case "gzip":
                header("Content-Type: application/x-gzip");
                break;
            case "tar":
                header("Content-Type: application/x-tar");
        }
        $header = "Content-Disposition: attachment; filename=\"";
        $header .= strstr($this->options['name'], "/") ? substr($this->options['name'], strrpos($this->options['name'], "/") + 1) : $this->options['name'];
        $header .= "\"";
        header($header);
        header("Content-Length: ".strlen($this->archive));
        header("Content-Transfer-Encoding: binary");
        header("Cache-Control: no-cache, must-revalidate, max-age=60");
        header("Expires: Sat, 01 Jan 2000 12:00:00 GMT");
        print($this->archive);
        exit();
    }
}
class tar_file extends archive {
    function __construct($name) {
        parent::__construct($name);
        $this->options['type'] = "tar";
    }
    function create_tar() {
        $pwd = getcwd();
        chdir($this->options['basedir']);
        foreach ($this->files as $current) {
            if ($current['name'] == $this->options['name'])
                continue;
            if (strlen($current['name2']) > 99) {
                $path             = substr($current['name2'], 0, strpos($current['name2'], "/", strlen($current['name2']) - 100) + 1);
                $current['name2'] = substr($current['name2'], strlen($path));
                if (strlen($path) > 154 || strlen($current['name2']) > 99) {
                    $this->error[] = "Could not add {$path}{$current['name2']} to archive because the filename is too long.";
                    continue;
                }
            }
            $block    = pack("a100a8a8a8a12a12a8a1a100a6a2a32a32a8a8a155a12", $current['name2'], sprintf("%07o", $current['stat'][2]), sprintf("%07o", $current['stat'][4]), sprintf("%07o", $current['stat'][5]), sprintf("%011o", $current['type'] == 2 ? 0 : $current['stat'][7]), sprintf("%011o", $current['stat'][9]), "        ", $current['type'], $current['type'] == 2 ? @readlink($current['name']) : "", "ustar ", " ", "Unknown", "Unknown", "", "", !empty($path) ? $path : "", "");
            $checksum = 0;
            for ($i = 0; $i < 512; $i++)
                $checksum += ord(substr($block, $i, 1));
            $checksum = pack("a8", sprintf("%07o", $checksum));
            $block    = substr_replace($block, $checksum, 148, 8);
            if ($current['type'] == 2 || $current['stat'][7] == 0)
                $this->add_data($block);
            else if ($fp = @fopen($current['name'], "rb")) {
                $this->add_data($block);
                while ($temp = fread($fp, 1048576))
                    $this->add_data($temp);
                if ($current['stat'][7] % 512 > 0) {
                    $temp = "";
                    for ($i = 0; $i < 512 - $current['stat'][7] % 512; $i++)
                        $temp .= "\0";
                    $this->add_data($temp);
                }
                fclose($fp);
            } else
                $this->error[] = "Could not open file {$current['name']} for reading. It was not added.";
        }
        $this->add_data(pack("a1024", ""));
        chdir($pwd);
        return 1;
    }
    function extract_files() {
        $pwd = getcwd();
        chdir($this->options['basedir']);
        if ($fp = $this->open_archive()) {
            if ($this->options['inmemory'] == 1)
                $this->files = array();
            while ($block = fread($fp, 512)) {
                $temp = unpack("a100name/a8mode/a8uid/a8gid/a12size/a12mtime/a8checksum/a1type/a100symlink/a6magic/a2temp/a32temp/a32temp/a8temp/a8temp/a155prefix/a12temp", $block);
                $file = array(
                    'name' => $temp['prefix'] . $temp['name'],
                    'stat' => array(
                        2 => $temp['mode'],
                        4 => octdec($temp['uid']),
                        5 => octdec($temp['gid']),
                        7 => octdec($temp['size']),
                        9 => octdec($temp['mtime'])
                    ),
                    'checksum' => octdec($temp['checksum']),
                    'type' => $temp['type'],
                    'magic' => $temp['magic']
                );
                if ($file['checksum'] == 0x00000000)
                    break;
                else if (substr($file['magic'], 0, 5) != "ustar") {
                    $this->error[] = "This script does not support extracting this type of tar file.";
                    break;
                }
                $block    = substr_replace($block, "        ", 148, 8);
                $checksum = 0;
                for ($i = 0; $i < 512; $i++)
                    $checksum += ord(substr($block, $i, 1));
                if ($file['checksum'] != $checksum)
                    $this->error[] = "Could not extract from {$this->options['name']}, it is corrupt.";
                if ($this->options['inmemory'] == 1) {
                    $file['data'] = fread($fp, $file['stat'][7]);
                    fread($fp, (512 - $file['stat'][7] % 512) == 512 ? 0 : (512 - $file['stat'][7] % 512));
                    unset($file['checksum'], $file['magic']);
                    $this->files[] = $file;
                } else if ($file['type'] == 5) {
                    if (!is_dir($file['name']))
                        mkdir(fs_encode($file['name']), $file['stat'][2]);
                } else if ($this->options['overwrite'] == 0 && file_exists($file['name'])) {
                    $this->error[] = "{$file['name']} already exists.";
                    continue;
                } else if ($file['type'] == 2) {
                    symlink_phpfm($temp['symlink'], $file['name']);
                    chmod($file['name'], $file['stat'][2]);
                } else if ($new = @fopen($file['name'], "wb")) {
                    fwrite($new, fread($fp, $file['stat'][7]));
                    fread($fp, (512 - $file['stat'][7] % 512) == 512 ? 0 : (512 - $file['stat'][7] % 512));
                    fclose($new);
                    chmod($file['name'], $file['stat'][2]);
                } else {
                    $this->error[] = "Could not open {$file['name']} for writing.";
                    continue;
                }
                chown($file['name'], $file['stat'][4]);
                chgrp($file['name'], $file['stat'][5]);
                touch($file['name'], $file['stat'][9]);
                unset($file);
            }
        } else
            $this->error[] = "Could not open file {$this->options['name']}";
        chdir($pwd);
    }
    function open_archive() {
        return @fopen($this->options['name'], "rb");
    }
}
class gzip_file extends tar_file {
    function __construct($name) {
        parent::__construct($name);
        $this->options['type'] = "gzip";
    }
    function create_gzip() {
        if ($this->options['inmemory'] == 0) {
            $pwd = getcwd();
            chdir($this->options['basedir']);
            if ($fp = gzopen($this->options['name'], "wb{$this->options['level']}")) {
                fseek($this->archive, 0);
                while ($temp = fread($this->archive, 1048576))
                    gzwrite($fp, $temp);
                gzclose($fp);
                chdir($pwd);
            } else {
                $this->error[] = "Could not open {$this->options['name']} for writing.";
                chdir($pwd);
                return 0;
            }
        } else
            $this->archive = gzencode($this->archive, $this->options['level']);
        return 1;
    }
    function open_archive() {
        return @gzopen($this->options['name'], "rb");
    }
}
class bzip_file extends tar_file {
    function __construct($name) {
        parent::__construct($name);
        $this->options['type'] = "bzip";
    }
    function create_bzip() {
        if ($this->options['inmemory'] == 0) {
            $pwd = getcwd();
            chdir($this->options['basedir']);
            if ($fp = bzopen($this->options['name'], "wb")) {
                fseek($this->archive, 0);
                while ($temp = fread($this->archive, 1048576))
                    bzwrite($fp, $temp);
                bzclose($fp);
                chdir($pwd);
            } else {
                $this->error[] = "Could not open {$this->options['name']} for writing.";
                chdir($pwd);
                return 0;
            }
        } else
            $this->archive = bzcompress($this->archive, $this->options['level']);
        return 1;
    }
    function open_archive() {
        return @bzopen($this->options['name'], "rb");
    }
}
class zip_file extends archive {
    function __construct($name) {
        parent::__construct($name);
        $this->options['type'] = "zip";
    }
    function create_zip() {
        $files   = 0;
        $offset  = 0;
        $central = "";
        if (!empty($this->options['sfx']))
            if ($fp = @fopen($this->options['sfx'], "rb")) {
                $temp = fread($fp, phpfm_filesize($this->options['sfx']));
                fclose($fp);
                $this->add_data($temp);
                $offset += strlen($temp);
                unset($temp);
            } else
                $this->error[] = "Could not open sfx module from {$this->options['sfx']}.";
        $pwd = getcwd();
        chdir($this->options['basedir']);
        foreach ($this->files as $current) {
            if ($current['name'] == $this->options['name'])
                continue;
            $timedate = explode(" ", date("Y n j G i s", $current['stat'][9]));
            $timedate = ($timedate[0] - 1980 << 25) | ($timedate[1] << 21) | ($timedate[2] << 16) | ($timedate[3] << 11) | ($timedate[4] << 5) | ($timedate[5]);
            $block    = pack("VvvvV", 0x04034b50, 0x000A, 0x0000, (isset($current['method']) || $this->options['method'] == 0) ? 0x0000 : 0x0008, $timedate);
            if ($current['stat'][7] == 0 && $current['type'] == 5) {
                $block .= pack("VVVvv", 0x00000000, 0x00000000, 0x00000000, strlen($current['name2']) + 1, 0x0000);
                $block .= $current['name2'] . "/";
                $this->add_data($block);
                $central .= pack("VvvvvVVVVvvvvvVV", 0x02014b50, 0x0014, $this->options['method'] == 0 ? 0x0000 : 0x000A, 0x0000, (isset($current['method']) || $this->options['method'] == 0) ? 0x0000 : 0x0008, $timedate, 0x00000000, 0x00000000, 0x00000000, strlen($current['name2']) + 1, 0x0000, 0x0000, 0x0000, 0x0000, $current['type'] == 5 ? 0x00000010 : 0x00000000, $offset);
                $central .= $current['name2'] . "/";
                $files++;
                $offset += (31 + strlen($current['name2']));
            } else if ($current['stat'][7] == 0) {
                $block .= pack("VVVvv", 0x00000000, 0x00000000, 0x00000000, strlen($current['name2']), 0x0000);
                $block .= $current['name2'];
                $this->add_data($block);
                $central .= pack("VvvvvVVVVvvvvvVV", 0x02014b50, 0x0014, $this->options['method'] == 0 ? 0x0000 : 0x000A, 0x0000, (isset($current['method']) || $this->options['method'] == 0) ? 0x0000 : 0x0008, $timedate, 0x00000000, 0x00000000, 0x00000000, strlen($current['name2']), 0x0000, 0x0000, 0x0000, 0x0000, $current['type'] == 5 ? 0x00000010 : 0x00000000, $offset);
                $central .= $current['name2'];
                $files++;
                $offset += (30 + strlen($current['name2']));
            } else if ($fp = @fopen($current['name'], "rb")) {
                $temp = fread($fp, $current['stat'][7]);
                fclose($fp);
                $crc32 = crc32($temp);
                if (!isset($current['method']) && $this->options['method'] == 1) {
                    $temp = gzcompress($temp, $this->options['level']);
                    $size = strlen($temp) - 6;
                    $temp = substr($temp, 2, $size);
                } else
                    $size = strlen($temp);
                $block .= pack("VVVvv", $crc32, $size, $current['stat'][7], strlen($current['name2']), 0x0000);
                $block .= $current['name2'];
                $this->add_data($block);
                $this->add_data($temp);
                unset($temp);
                $central .= pack("VvvvvVVVVvvvvvVV", 0x02014b50, 0x0014, $this->options['method'] == 0 ? 0x0000 : 0x000A, 0x0000, (isset($current['method']) || $this->options['method'] == 0) ? 0x0000 : 0x0008, $timedate, $crc32, $size, $current['stat'][7], strlen($current['name2']), 0x0000, 0x0000, 0x0000, 0x0000, 0x00000000, $offset);
                $central .= $current['name2'];
                $files++;
                $offset += (30 + strlen($current['name2']) + $size);
            } else
                $this->error[] = "Could not open file {$current['name']} for reading. It was not added.";
        }
        $this->add_data($central);
        $this->add_data(pack("VvvvvVVv", 0x06054b50, 0x0000, 0x0000, $files, $files, strlen($central), $offset, !empty($this->options['comment']) ? strlen($this->options['comment']) : 0x0000));
        if (!empty($this->options['comment']))
            $this->add_data($this->options['comment']);
        chdir($pwd);
        return 1;
    }
}
/*-------------------------------------------------
| ChromePhp
| Server Side Chrome PHP debugger class
+--------------------------------------------------
| @author Craig Campbell <iamcraigcampbell@gmail.com>
+--------------------------------------------------
| Licensed under the Apache License, Version 2.0 (the "License")
| http://www.apache.org/licenses/LICENSE-2.0
+--------------------------------------------------*/
class ChromePhp {
    const VERSION = '4.1.0';
    const HEADER_NAME = 'X-ChromeLogger-Data';
    const BACKTRACE_LEVEL = 'backtrace_level';
    const LOG = 'log';
    const WARN = 'warn';
    const ERROR = 'error';
    const GROUP = 'group';
    const INFO = 'info';
    const GROUP_END = 'groupEnd';
    const GROUP_COLLAPSED = 'groupCollapsed';
    const TABLE = 'table';
    protected $_php_version;
    protected $_timestamp;
    protected $_json = array(
        'version' => self::VERSION,
        'columns' => array('log', 'backtrace', 'type'),
        'rows' => array()
    );
    protected $_backtraces = array();
    protected $_error_triggered = false;
    protected $_settings = array(
        self::BACKTRACE_LEVEL => 2
    );
    protected static $_instance;
    protected $_processed = array();
    private function __construct() {
        $this->_php_version = phpversion();
        $this->_timestamp = $this->_php_version >= 5.1 ? $_SERVER['REQUEST_TIME'] : time();
        $this->_json['request_uri'] = $_SERVER['REQUEST_URI'];
    }
    public static function getInstance() {
        if (self::$_instance === null) {
            self::$_instance = new self();
        }
        return self::$_instance;
    }
    public static function log() {
        $args = func_get_args();
        return self::_log('', $args);
    }
    public static function warn() {
        $args = func_get_args();
        return self::_log(self::WARN, $args);
    }
    public static function error() {
        $args = func_get_args();
        return self::_log(self::ERROR, $args);
    }
    public static function group() {
        $args = func_get_args();
        return self::_log(self::GROUP, $args);
    }
    public static function info() {
        $args = func_get_args();
        return self::_log(self::INFO, $args);
    }
    public static function groupCollapsed() {
        $args = func_get_args();
        return self::_log(self::GROUP_COLLAPSED, $args);
    }
    public static function groupEnd() {
        $args = func_get_args();
        return self::_log(self::GROUP_END, $args);
    }
    public static function table() {
        $args = func_get_args();
        return self::_log(self::TABLE, $args);
    }
    protected static function _log($type, array $args) {
        // nothing passed in, don't do anything
        if (count($args) == 0 && $type != self::GROUP_END) {
            return;
        }
        $logger = self::getInstance();
        $logger->_processed = array();
        $logs = array();
        foreach ($args as $arg) {
            $logs[] = $logger->_convert($arg);
        }
        $backtrace = debug_backtrace(false);
        $level = $logger->getSetting(self::BACKTRACE_LEVEL);
        $backtrace_message = 'unknown';
        if (isset($backtrace[$level]['file']) && isset($backtrace[$level]['line'])) {
            //$backtrace_message = trim($backtrace[$level]['file']).' '.trim($backtrace[$level]['line']);
            $backtrace_message = trim(basename($backtrace[$level]['file'])).':'.trim($backtrace[$level]['line']);
        }
        $logger->_addRow($logs, $backtrace_message, $type);
    }
    protected function _convert($object) {
        // if this isn't an object then just return it
        if (!is_object($object)) {
            return $object;
        }
        //Mark this object as processed so we don't convert it twice and it
        //Also avoid recursion when objects refer to each other
        $this->_processed[] = $object;
        $object_as_array = array();
        // first add the class name
        $object_as_array['___class_name'] = get_class($object);
        // loop through object vars
        $object_vars = get_object_vars($object);
        foreach ($object_vars as $key => $value) {
            // same instance as parent object
            if ($value === $object || in_array($value, $this->_processed, true)) {
                $value = 'recursion - parent object [' . get_class($value) . ']';
            }
            $object_as_array[$key] = $this->_convert($value);
        }
        $reflection = new ReflectionClass($object);
        // loop through the properties and add those
        foreach ($reflection->getProperties() as $property) {
            // if one of these properties was already added above then ignore it
            if (array_key_exists($property->getName(), $object_vars)) {
                continue;
            }
            $type = $this->_getPropertyKey($property);
            if ($this->_php_version >= 5.3) {
                $property->setAccessible(true);
            }
            try {
                $value = $property->getValue($object);
            } catch (ReflectionException $e) {
                $value = 'only PHP 5.3 can access private/protected properties';
            }
            // same instance as parent object
            if ($value === $object || in_array($value, $this->_processed, true)) {
                $value = 'recursion - parent object [' . get_class($value) . ']';
            }
            $object_as_array[$type] = $this->_convert($value);
        }
        return $object_as_array;
    }
    protected function _getPropertyKey(ReflectionProperty $property) {
        $static = $property->isStatic() ? ' static' : '';
        if ($property->isPublic()) {
            return 'public' . $static . ' ' . $property->getName();
        }
        if ($property->isProtected()) {
            return 'protected' . $static . ' ' . $property->getName();
        }
        if ($property->isPrivate()) {
            return 'private' . $static . ' ' . $property->getName();
        }
    }
    protected function _addRow(array $logs, $backtrace, $type) {
        // if this is logged on the same line for example in a loop, set it to null to save space
        if (in_array($backtrace, $this->_backtraces)) {
            $backtrace = null;
        }
        // for group, groupEnd, and groupCollapsed
        // take out the backtrace since it is not useful
        if ($type == self::GROUP || $type == self::GROUP_END || $type == self::GROUP_COLLAPSED) {
            $backtrace = null;
        }
        if ($backtrace !== null) {
            $this->_backtraces[] = $backtrace;
        }
        $row = array($logs, $backtrace, $type);
        $this->_json['rows'][] = $row;
        $this->_writeHeader($this->_json);
    }
    protected function _writeHeader($data) {
        $header = self::HEADER_NAME . ': ' . $this->_encode($data);
        // https://maxchadwick.xyz/blog/http-request-header-size-limits
        // Most web servers do limit size of headers they accept. Apache default limit is 8KB, in IIS it's 16KB.
        $limit = 7; //Kb
        if ($limit) {
            if (strlen($header) > $limit * 1024){
                $data['rows'] = array();
                $data['rows'][] = array(array('LOG Error: HTML Header too big = '.format_size(strlen($header))), '', self::ERROR);
                $header = self::HEADER_NAME . ': ' . $this->_encode($data);
            }
        }
        header($header);
    }
    protected function _encode($data) {
        return base64_encode(utf8_encode(json_encode($data)));
    }
    public function addSetting($key, $value) {
        $this->_settings[$key] = $value;
    }
    public function addSettings(array $settings) {
        foreach ($settings as $key => $value) {
            $this->addSetting($key, $value);
        }
    }
    public function getSetting($key) {
        if (!isset($this->_settings[$key])) {
            return null;
        }
        return $this->_settings[$key];
    }
}
// +--------------------------------------------------
// | Internationalization
// +--------------------------------------------------
function et($tag){
    global $lang,$sys_lang;

    // English - by Fabricio Seger Kolling
    $et['en']['Version'] = 'Version';
    $et['en']['DocRoot'] = 'Document Root';
    $et['en']['FMRoot'] = 'File Manager Root';
    $et['en']['DateFormat'] = 'Date Format';
    $et['en']['GetSize'] = 'Get size';
    $et['en']['Error'] = 'Error';
    $et['en']['Name'] = 'Name';
    $et['en']['And'] = 'and';
    $et['en']['Enter'] = 'Enter';
    $et['en']['Send'] = 'Send';
    $et['en']['Refresh'] = 'Refresh';
    $et['en']['SaveConfig'] = 'Save Configurations';
    //$et['en']['SavePass'] = 'Save Password';
    //$et['en']['TypePass'] = 'Enter the password';
    $et['en']['SaveFile'] = 'Save File';
    $et['en']['Save'] = 'Save';
    $et['en']['Leave'] = 'Leave';
    $et['en']['Edit'] = 'Edit';
    $et['en']['View'] = 'View';
    $et['en']['Config'] = 'Config';
    $et['en']['Ren'] = 'Rename';
    $et['en']['Rem'] = 'Delete';
    $et['en']['Compress'] = 'Compress';
    $et['en']['Decompress'] = 'Decompress';
    $et['en']['ResolveIDs'] = 'Resolve IDs';
    $et['en']['Move'] = 'Move';
    $et['en']['Copy'] = 'Copy';
    $et['en']['ServerInfo'] = 'Server Info';
    $et['en']['CreateDir'] = 'Create Directory';
    $et['en']['CreateArq'] = 'Create File';
    $et['en']['Symlink'] = 'Symlink';
    $et['en']['HardLink'] = 'Hardlink';
    $et['en']['ExecCmd'] = 'Execute Command';
    $et['en']['Upload'] = 'Upload';
    $et['en']['UploadEnd'] = 'Upload Finished';
    $et['en']['Perm'] = 'Perm';
    $et['en']['Perms'] = 'Permissions';
    $et['en']['Owner'] = 'Owner';
    $et['en']['Group'] = 'Group';
    $et['en']['Other'] = 'Other';
    $et['en']['Size'] = 'Size';
    $et['en']['Date'] = 'Date';
    $et['en']['Type'] = 'Type';
    $et['en']['Free'] = 'free';
    $et['en']['Shell'] = 'Shell';
    $et['en']['Read'] = 'Read';
    $et['en']['Write'] = 'Write';
    $et['en']['Exec'] = 'Execute';
    $et['en']['Apply'] = 'Apply';
    $et['en']['StickyBit'] = 'Sticky Bit';
    $et['en']['Pass'] = 'Password';
    $et['en']['Lang'] = 'Language';
    $et['en']['File'] = 'File';
    $et['en']['File_s'] = 'file(s)';
    $et['en']['Dir_s'] = 'directory(s)';
    $et['en']['To'] = 'to';
    $et['en']['Destination'] = 'Destination';
    $et['en']['Configurations'] = 'Configurations';
    $et['en']['JSError'] = 'JavaScript Error';
    $et['en']['NoSel'] = 'There are no selected items';
    $et['en']['SelDir'] = 'Select the destination directory on the left tree';
    $et['en']['TypeDir'] = 'Enter the directory name';
    $et['en']['TypeArq'] = 'Enter the file name';
    $et['en']['TypeCmd'] = 'Enter the command';
    $et['en']['TypeArqComp'] = 'Enter the file name.\\nThe extension will define the compression type.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['en']['RemSel'] = 'DELETE selected items';
    $et['en']['NoDestDir'] = 'There is no selected destination directory';
    $et['en']['DestEqOrig'] = 'Origin and destination directories are equal';
    $et['en']['InvalidDest'] = 'Destination directory is invalid';
    $et['en']['NoNewPerm'] = 'New permission not set';
    $et['en']['CopyTo'] = 'COPY to';
    $et['en']['MoveTo'] = 'MOVE to';
    $et['en']['AlterPermTo'] = 'CHANGE PERMISSIONS to';
    $et['en']['ConfExec'] = 'Confirm EXECUTE';
    $et['en']['ConfRem'] = 'Confirm DELETE';
    $et['en']['EmptyDir'] = 'Empty directory';
    $et['en']['IOError'] = 'I/O Error';
    $et['en']['FileMan'] = 'PHP File Manager';
    $et['en']['InvPass'] = 'Invalid Password';
    $et['en']['ReadDenied'] = 'Read Access Denied';
    $et['en']['FileNotFound'] = 'File not found';
    $et['en']['AutoClose'] = 'Close on Complete';
    $et['en']['OutDocRoot'] = 'File beyond DOCUMENT_ROOT';
    $et['en']['NoCmd'] = 'Error: Command not informed';
    $et['en']['ConfTrySave'] = 'File without write permisson.\\nTry to save anyway';
    $et['en']['ConfSaved'] = 'Configurations saved';
    $et['en']['PassSaved'] = 'Password saved';
    $et['en']['FileDirExists'] = 'File or directory already exists';
    $et['en']['NoPhpinfo'] = 'Function phpinfo disabled';
    $et['en']['NoReturn'] = 'no return';
    $et['en']['FileSent'] = 'File sent';
    $et['en']['SpaceLimReached'] = 'Space limit reached';
    $et['en']['InvExt'] = 'Invalid extension';
    $et['en']['FileNoOverw'] = 'File could not be overwritten';
    $et['en']['FileOverw'] = 'File overwritten';
    $et['en']['FileIgnored'] = 'File ignored';
    $et['en']['ChkVer'] = 'Check for new version';
    $et['en']['ChkVerAvailable'] = 'New version, click here to begin download!!';
    $et['en']['ChkVerNotAvailable'] = 'No new version available. :(';
    $et['en']['ChkVerError'] = 'Connection Error.';
    $et['en']['Website'] = 'Website';
    $et['en']['SendingForm'] = 'Sending files, please wait';
    $et['en']['NoFileSel'] = 'No file selected';
    $et['en']['SelAll'] = 'All';
    $et['en']['SelNone'] = 'None';
    $et['en']['SelInverse'] = 'Inverse';
    $et['en']['Selected_s'] = 'selected';
    $et['en']['Total'] = 'total';
    $et['en']['Partition'] = 'Partition';
    $et['en']['RenderTime'] = 'Time to render this page';
    $et['en']['Seconds'] = 'sec';
    $et['en']['ErrorReport'] = 'Error Reporting';
    $et['en']['Close'] = 'Close';
    $et['en']['SetPass'] = 'Set Password';
    $et['en']['ChangePass'] = 'Change Password';
    $et['en']['Portscan'] = 'Portscan';
    $et['en']['PHPOpenBasedir'] = 'PHP Open Basedir';
    $et['en']['PHPOpenBasedirFullAccess'] = '(unset) Full Access';
    $et['en']['About'] = 'About';
    $et['en']['FileSaved'] = 'File saved';
    $et['en']['FileSaveError'] = 'Error saving file';

    // Portuguese - by Fabricio Seger Kolling
    $et['pt']['Version'] = 'Versão';
    $et['pt']['DocRoot'] = 'Document Root';
    $et['pt']['FMRoot'] = 'File Manager Root';
    $et['pt']['DateFormat'] = 'Formato de Data';
    $et['pt']['GetSize'] = 'Ver tamanho';
    $et['pt']['Error'] = 'Erro';
    $et['pt']['Name'] = 'Nome';
    $et['pt']['And'] = 'e';
    $et['pt']['Enter'] = 'Entrar';
    $et['pt']['Send'] = 'Enviar';
    $et['pt']['Refresh'] = 'Atualizar';
    $et['pt']['SaveConfig'] = 'Salvar Configurações';
    //$et['pt']['SavePass'] = 'Salvar Senha';
    //$et['en']['TypePass'] = 'Digite a senha';
    $et['pt']['SaveFile'] = 'Salvar Arquivo';
    $et['pt']['Save'] = 'Salvar';
    $et['pt']['Leave'] = 'Sair';
    $et['pt']['Edit'] = 'Editar';
    $et['pt']['View'] = 'Visualizar';
    $et['pt']['Config'] = 'Config';
    $et['pt']['Ren'] = 'Renomear';
    $et['pt']['Rem'] = 'Apagar';
    $et['pt']['Compress'] = 'Compactar';
    $et['pt']['Decompress'] = 'Descompactar';
    $et['pt']['ResolveIDs'] = 'Resolver IDs';
    $et['pt']['Move'] = 'Mover';
    $et['pt']['Copy'] = 'Copiar';
    $et['pt']['ServerInfo'] = 'Server Info';
    $et['pt']['CreateDir'] = 'Criar Diretório';
    $et['pt']['CreateArq'] = 'Criar Arquivo';
    $et['pt']['ExecCmd'] = 'Executar Comando';
    $et['pt']['Upload'] = 'Upload';
    $et['pt']['UploadEnd'] = 'Upload Terminado';
    $et['pt']['Perm'] = 'Perm';
    $et['pt']['Perms'] = 'Permissões';
    $et['pt']['Owner'] = 'Dono';
    $et['pt']['Group'] = 'Grupo';
    $et['pt']['Other'] = 'Outros';
    $et['pt']['Size'] = 'Tamanho';
    $et['pt']['Date'] = 'Data';
    $et['pt']['Type'] = 'Tipo';
    $et['pt']['Free'] = 'livre';
    $et['pt']['Shell'] = 'Shell';
    $et['pt']['Read'] = 'Ler';
    $et['pt']['Write'] = 'Escrever';
    $et['pt']['Exec'] = 'Executar';
    $et['pt']['Apply'] = 'Aplicar';
    $et['pt']['StickyBit'] = 'Sticky Bit';
    $et['pt']['Pass'] = 'Senha';
    $et['pt']['Lang'] = 'Idioma';
    $et['pt']['File'] = 'Arquivo';
    $et['pt']['File_s'] = 'arquivo(s)';
    $et['pt']['Dir_s'] = 'diretorio(s)';
    $et['pt']['To'] = 'para';
    $et['pt']['Destination'] = 'Destino';
    $et['pt']['Configurations'] = 'Configurações';
    $et['pt']['JSError'] = 'Erro de JavaScript';
    $et['pt']['NoSel'] = 'Não há itens selecionados';
    $et['pt']['SelDir'] = 'Selecione o diretório de destino na árvore a esquerda';
    $et['pt']['TypeDir'] = 'Digite o nome do diretório';
    $et['pt']['TypeArq'] = 'Digite o nome do arquivo';
    $et['pt']['TypeCmd'] = 'Digite o commando';
    $et['pt']['TypeArqComp'] = 'Digite o nome do arquivo.\\nA extensão determina o tipo de compactação.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['pt']['RemSel'] = 'APAGAR itens selecionados';
    $et['pt']['NoDestDir'] = 'Não há um diretório de destino selecionado';
    $et['pt']['DestEqOrig'] = 'Diretório de origem e destino iguais';
    $et['pt']['InvalidDest'] = 'Diretório de destino inválido';
    $et['pt']['NoNewPerm'] = 'Nova permissão não foi setada';
    $et['pt']['CopyTo'] = 'COPIAR para';
    $et['pt']['MoveTo'] = 'MOVER para';
    $et['pt']['AlterPermTo'] = 'ALTERAR PERMISSÕES para';
    $et['pt']['ConfExec'] = 'Confirma EXECUTAR';
    $et['pt']['ConfRem'] = 'Confirma APAGAR';
    $et['pt']['EmptyDir'] = 'Diretório vazio';
    $et['pt']['IOError'] = 'Erro de E/S';
    $et['pt']['FileMan'] = 'PHP File Manager';
    $et['pt']['TypePass'] = 'Digite a senha';
    $et['pt']['InvPass'] = 'Senha Inválida';
    $et['pt']['ReadDenied'] = 'Acesso de leitura negado';
    $et['pt']['FileNotFound'] = 'Arquivo não encontrado';
    $et['pt']['AutoClose'] = 'Fechar Automaticamente';
    $et['pt']['OutDocRoot'] = 'Arquivo fora do DOCUMENT_ROOT';
    $et['pt']['NoCmd'] = 'Erro: Comando não informado';
    $et['pt']['ConfTrySave'] = 'Arquivo sem permissão de escrita.\\nTentar salvar assim mesmo';
    $et['pt']['ConfSaved'] = 'Configurações salvas';
    $et['pt']['PassSaved'] = 'Senha salva';
    $et['pt']['FileDirExists'] = 'Arquivo ou diretório já existe';
    $et['pt']['NoPhpinfo'] = 'Função phpinfo desabilitada';
    $et['pt']['NoReturn'] = 'sem retorno';
    $et['pt']['FileSent'] = 'Arquivo enviado';
    $et['pt']['SpaceLimReached'] = 'Limite de espaço alcançado';
    $et['pt']['InvExt'] = 'Extensão inválida';
    $et['pt']['FileNoOverw'] = 'Arquivo não pode ser sobreescrito';
    $et['pt']['FileOverw'] = 'Arquivo sobreescrito';
    $et['pt']['FileIgnored'] = 'Arquivo omitido';
    $et['pt']['ChkVer'] = 'Verificar por nova versão';
    $et['pt']['ChkVerAvailable'] = 'Nova versão, clique aqui para iniciar download!!';
    $et['pt']['ChkVerNotAvailable'] = 'Não há nova versão disponível. :(';
    $et['pt']['ChkVerError'] = 'Erro de conexão.';
    $et['pt']['Website'] = 'Website';
    $et['pt']['SendingForm'] = 'Enviando arquivos, aguarde';
    $et['pt']['NoFileSel'] = 'Nenhum arquivo selecionado';
    $et['pt']['SelAll'] = 'Tudo';
    $et['pt']['SelNone'] = 'Nada';
    $et['pt']['SelInverse'] = 'Inverso';
    $et['pt']['Selected_s'] = 'selecionado(s)';
    $et['pt']['Total'] = 'total';
    $et['pt']['Partition'] = 'Partição';
    $et['pt']['RenderTime'] = 'Tempo para gerar esta página';
    $et['pt']['Seconds'] = 'seg';
    $et['pt']['ErrorReport'] = 'Error Reporting';
    $et['pt']['Close'] = 'Fechar';
    $et['pt']['SetPass'] = 'Alterar Senha';
    $et['pt']['ChangePass'] = 'Alterar Senha';
    $et['pt']['Portscan'] = 'Portscan';
    $et['pt']['PHPOpenBasedir'] = 'PHP Open Basedir';
    $et['pt']['PHPOpenBasedirFullAccess'] = '(indefinido) Acesso Completo';
    $et['pt']['About'] = 'Sobre';
    $et['pt']['FileSaved'] = 'Arquivo salvo';
    $et['pt']['FileSaveError'] = 'Erro salvando arquivo';

    // Polish - by Jakub Kocój
    $et['pl']['Version'] = 'Wersja';
    $et['pl']['DocRoot'] = 'Document Root';
    $et['pl']['FMRoot'] = 'File Manager Root';
    $et['pl']['Name'] = 'Nazwa';
    $et['pl']['And'] = 'i';
    $et['pl']['Enter'] = 'Enter';
    $et['pl']['Send'] = 'Wyślij';
    $et['pl']['Refresh'] = 'Odśwież';
    $et['pl']['SaveConfig'] = 'Zapisz konfigurację';
    $et['pl']['SaveFile'] = 'Zapisz plik';
    $et['pl']['Save'] = 'Zapisz';
    $et['pl']['Leave'] = 'Wyjdź';
    $et['pl']['Edit'] = 'Edycja';
    $et['pl']['View'] = 'Pokaż';
    $et['pl']['Config'] = 'Konfiguracja';
    $et['pl']['Ren'] = 'Zmień nazwę';
    $et['pl']['Rem'] = 'Usuń';
    $et['pl']['Compress'] = 'Kompresuj';
    $et['pl']['Decompress'] = 'Dekompresuj';
    $et['pl']['ResolveIDs'] = 'Rozpoznaj ID';
    $et['pl']['Move'] = 'Przenieś';
    $et['pl']['Copy'] = 'Kopiuj';
    $et['pl']['ServerInfo'] = 'Informacje o serwerze';
    $et['pl']['CreateDir'] = 'Utwórz katalog';
    $et['pl']['CreateArq'] = 'Utówrz plik';
    $et['pl']['ExecCmd'] = 'Wykonaj polecenie';
    $et['pl']['Upload'] = 'Wgraj plik';
    $et['pl']['UploadEnd'] = 'Wgranie zakończone';
    $et['pl']['Perm'] = 'Prawa pliku';
    $et['pl']['Perms'] = 'Prawa dostępu';
    $et['pl']['Owner'] = 'Właściciel';
    $et['pl']['Group'] = 'Grupa';
    $et['pl']['Other'] = 'Inne';
    $et['pl']['Size'] = 'Rozmiar';
    $et['pl']['Date'] = 'Data';
    $et['pl']['Type'] = 'Typ';
    $et['pl']['Free'] = 'darmowe';
    $et['pl']['Shell'] = 'Shell';
    $et['pl']['Read'] = 'Odczyt';
    $et['pl']['Write'] = 'Zapis';
    $et['pl']['Exec'] = 'Wykonywanie';
    $et['pl']['Apply'] = 'Zastosuj';
    $et['pl']['StickyBit'] = 'Sticky Bit';
    $et['pl']['Pass'] = 'Hasło';
    $et['pl']['Lang'] = 'Język';
    $et['pl']['File'] = 'Plik';
    $et['pl']['File_s'] = 'Plik(i)';
    $et['pl']['Dir_s'] = 'katalog(i)';
    $et['pl']['To'] = 'do';
    $et['pl']['Destination'] = 'Cel';
    $et['pl']['Configurations'] = 'Konfiguracje';
    $et['pl']['JSError'] = 'Błąd JavaScript';
    $et['pl']['NoSel'] = 'Nie wybrano żadnych rekordów';
    $et['pl']['SelDir'] = 'Wybierz docelowy folder w drzewku po lewej';
    $et['pl']['TypeDir'] = 'Wpisz nazwę folderu';
    $et['pl']['TypeArq'] = 'Wpisz nazwę pliku';
    $et['pl']['TypeCmd'] = 'Wprowadź komendę';
    $et['pl']['TypeArqComp'] = 'Wprowadź nazwę pliku.\\nRozszerzenie definiuje kompresję pliku.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['pl']['RemSel'] = 'USUŃ zanzaczone rekordy';
    $et['pl']['NoDestDir'] = 'Nie wybrano folderu docelowego';
    $et['pl']['DestEqOrig'] = 'Folder docelowy jest równy bieżącemu folderowi';
    $et['pl']['InvalidDest'] = 'Folder docelowy jest niepoprawny';
    $et['pl']['NoNewPerm'] = 'Nie ustawiono uprawnień';
    $et['pl']['CopyTo'] = 'KOPIUJ do';
    $et['pl']['MoveTo'] = 'PRZENIEŚ do';
    $et['pl']['AlterPermTo'] = 'ZMIEŃ PRAWA DOSTĘPU do';
    $et['pl']['ConfExec'] = 'Potwierdź WYKONANIE POLECENIA';
    $et['pl']['ConfRem'] = 'Potwierdź USUNIĘCIE';
    $et['pl']['EmptyDir'] = 'Pusty folder';
    $et['pl']['IOError'] = 'Błąd wejścia/wyjścia';
    $et['pl']['FileMan'] = 'PHP Menadźer plików';
    $et['pl']['InvPass'] = 'Niepoprawne hasło';
    $et['pl']['ReadDenied'] = 'Czytanie dostęp zabroniony';
    $et['pl']['FileNotFound'] = 'Nie odnaleziono pliku';
    $et['pl']['AutoClose'] = 'Zamknij po zakończeniu';
    $et['pl']['OutDocRoot'] = 'Plik powyżej DOCUMENT_ROOT';
    $et['pl']['NoCmd'] = 'Błąd: Brak polecenia';
    $et['pl']['ConfTrySave'] = 'Plik bez możliwości zapisy.\\nSpróbój zapisać pomimo tego';
    $et['pl']['ConfSaved'] = 'Konfiguracja zapisana';
    $et['pl']['PassSaved'] = 'Hasło zapisane';
    $et['pl']['FileDirExists'] = 'Plik lub folder już istnieje';
    $et['pl']['NoPhpinfo'] = 'Funkcja phpinfo wyłączona';
    $et['pl']['NoReturn'] = 'bez powrotu';
    $et['pl']['FileSent'] = 'Plik wysłano';
    $et['pl']['SpaceLimReached'] = 'Osiągnięto limit miejsa';
    $et['pl']['InvExt'] = 'Niepoprawne rozszerzenie';
    $et['pl']['FileNoOverw'] = 'Plik nie może zostać nadpisany';
    $et['pl']['FileOverw'] = 'Nadpisano plik';
    $et['pl']['FileIgnored'] = 'Plik pominięte';
    $et['pl']['ChkVer'] = 'Sprawdź aktualizacje';
    $et['pl']['ChkVerAvailable'] = 'Jest nowa wersja, klikniu tutaj aby pobrać!!';
    $et['pl']['ChkVerNotAvailable'] = 'Brak nowszej wersji. :(';
    $et['pl']['ChkVerError'] = 'Błąd połączenia.';
    $et['pl']['Website'] = 'Strona';
    $et['pl']['SendingForm'] = 'Pliki są przesyłane, proszę czekać';
    $et['pl']['NoFileSel'] = 'Nie wybrano pliku';
    $et['pl']['SelAll'] = 'Wszystkie';
    $et['pl']['SelNone'] = 'Żadme';
    $et['pl']['SelInverse'] = 'Odwróć zaznaczenie';
    $et['pl']['Selected_s'] = 'zaznaczone';
    $et['pl']['Total'] = 'Wszystkie';
    $et['pl']['Partition'] = 'Partycja';
    $et['pl']['RenderTime'] = 'Czas do wyrenderowania tej strony';
    $et['pl']['Seconds'] = 'sec';
    $et['pl']['ErrorReport'] = 'Raportowanie błędów';
    $et['pl']['Close'] = 'Zamknij';
    $et['pl']['SetPass'] = 'Ustaw hasło';
    $et['pl']['ChangePass'] = 'Zmień hasło';
    $et['pl']['Portscan'] = 'Skan portów';

    // Spanish - by Sh Studios
    $et['es']['Version'] = 'Versión';
    $et['es']['DocRoot'] = 'Raiz del programa';
    $et['es']['FMRoot'] = 'Raiz del administrador de archivos';
    $et['es']['Name'] = 'Nombre';
    $et['es']['And'] = 'y';
    $et['es']['Enter'] = 'Enter';
    $et['es']['Send'] = 'Enviar';
    $et['es']['Refresh'] = 'Refrescar';
    $et['es']['SaveConfig'] = 'Guardar configuraciones';
    $et['es']['SavePass'] = 'Cuardar Contraseña';
    $et['es']['SaveFile'] = 'Guardar Archivo';
    $et['es']['Save'] = 'Guardar';
    $et['es']['Leave'] = 'Salir';
    $et['es']['Edit'] = 'Editar';
    $et['es']['View'] = 'Mirar';
    $et['es']['Config'] = 'Config.';
    $et['es']['Ren'] = 'Renombrar';
    $et['es']['Rem'] = 'Borrar';
    $et['es']['Compress'] = 'Comprimir';
    $et['es']['Decompress'] = 'Decomprimir';
    $et['es']['ResolveIDs'] = 'Resolver IDs';
    $et['es']['Move'] = 'Mover';
    $et['es']['Copy'] = 'Copiar';
    $et['es']['ServerInfo'] = 'Info del Server';
    $et['es']['CreateDir'] = 'Crear Directorio';
    $et['es']['CreateArq'] = 'Crear Archivo';
    $et['es']['ExecCmd'] = 'Ejecutar Comando';
    $et['es']['Upload'] = 'Subir';
    $et['es']['UploadEnd'] = 'Subida exitosa';
    $et['es']['Perm'] = 'Perm';
    $et['es']['Perms'] = 'Permisiones';
    $et['es']['Owner'] = 'Propietario';
    $et['es']['Group'] = 'Grupo';
    $et['es']['Other'] = 'Otro';
    $et['es']['Size'] = 'Tamaño';
    $et['es']['Date'] = 'Fecha';
    $et['es']['Type'] = 'Tipo';
    $et['es']['Free'] = 'libre';
    $et['es']['Shell'] = 'Ejecutar';
    $et['es']['Read'] = 'Leer';
    $et['es']['Write'] = 'Escribir';
    $et['es']['Exec'] = 'Ejecutar';
    $et['es']['Apply'] = 'Aplicar';
    $et['es']['StickyBit'] = 'Sticky Bit';
    $et['es']['Pass'] = 'Contraseña';
    $et['es']['Lang'] = 'Lenguage';
    $et['es']['File'] = 'Archivos';
    $et['es']['File_s'] = 'archivo(s)';
    $et['es']['Dir_s'] = 'directorio(s)';
    $et['es']['To'] = 'a';
    $et['es']['Destination'] = 'Destino';
    $et['es']['Configurations'] = 'Configuracion';
    $et['es']['JSError'] = 'Error de JavaScript';
    $et['es']['NoSel'] = 'No hay items seleccionados';
    $et['es']['SelDir'] = 'Seleccione el directorio de destino en el arbol derecho';
    $et['es']['TypeDir'] = 'Escriba el nombre del directorio';
    $et['es']['TypeArq'] = 'Escriba el nombre del archivo';
    $et['es']['TypeCmd'] = 'Escriba el comando';
    $et['es']['TypeArqComp'] = 'Escriba el nombre del directorio.\\nLa extension definira el tipo de compresion.\\nEj:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['es']['RemSel'] = 'BORRAR items seleccionados';
    $et['es']['NoDestDir'] = 'No se ha seleccionado el directorio de destino';
    $et['es']['DestEqOrig'] = 'El origen y el destino son iguales';
    $et['es']['InvalidDest'] = 'El destino del directorio es invalido';
    $et['es']['NoNewPerm'] = 'Las permisiones no se pudieron establecer';
    $et['es']['CopyTo'] = 'COPIAR a';
    $et['es']['MoveTo'] = 'MOVER a';
    $et['es']['AlterPermTo'] = 'CAMBIAR PERMISIONES a';
    $et['es']['ConfExec'] = 'Confirmar EJECUCION';
    $et['es']['ConfRem'] = 'Confirmar BORRADO';
    $et['es']['EmptyDir'] = 'Directorio Vacio';
    $et['es']['IOError'] = 'Error I/O';
    $et['es']['FileMan'] = 'PHP File Manager';
    $et['es']['TypePass'] = 'Escriba la contraseña';
    $et['es']['InvPass'] = 'Contraseña invalida';
    $et['es']['ReadDenied'] = 'Acceso de lectura denegado';
    $et['es']['FileNotFound'] = 'Archivo no encontrado';
    $et['es']['AutoClose'] = 'Cerrar al completar';
    $et['es']['OutDocRoot'] = 'Archivo antes de DOCUMENT_ROOT';
    $et['es']['NoCmd'] = 'Error: No se ha escrito ningun comando';
    $et['es']['ConfTrySave'] = 'Archivo sin permisos de escritura.\\nIntente guardar en otro lugar';
    $et['es']['ConfSaved'] = 'Configuracion Guardada';
    $et['es']['PassSaved'] = 'Contraseña guardada';
    $et['es']['FileDirExists'] = 'Archivo o directorio ya existente';
    $et['es']['NoPhpinfo'] = 'Funcion phpinfo() inhabilitada';
    $et['es']['NoReturn'] = 'sin retorno';
    $et['es']['FileSent'] = 'Archivo enviado';
    $et['es']['SpaceLimReached'] = 'Limite de espacio en disco alcanzado';
    $et['es']['InvExt'] = 'Extension inalida';
    $et['es']['FileNoOverw'] = 'El archivo no pudo ser sobreescrito';
    $et['es']['FileOverw'] = 'Archivo sobreescrito';
    $et['es']['FileIgnored'] = 'Archivo ignorado';
    $et['es']['ChkVer'] = 'Chequear las actualizaciones';
    $et['es']['ChkVerAvailable'] = 'Nueva version, haga click aqui para descargar!!';
    $et['es']['ChkVerNotAvailable'] = 'Su version es la mas reciente.';
    $et['es']['ChkVerError'] = 'Error de coneccion.';
    $et['es']['Website'] = 'Sitio Web';
    $et['es']['SendingForm'] = 'Enviando archivos, espere!';
    $et['es']['NoFileSel'] = 'Ningun archivo seleccionado';
    $et['es']['SelAll'] = 'Todos';
    $et['es']['SelNone'] = 'Ninguno';
    $et['es']['SelInverse'] = 'Inverso';
    $et['es']['Selected_s'] = 'seleccionado';
    $et['es']['Total'] = 'total';
    $et['es']['Partition'] = 'Particion';
    $et['es']['RenderTime'] = 'Generado en';
    $et['es']['Seconds'] = 'seg';
    $et['es']['ErrorReport'] = 'Reporte de error';

    // Korean - by Airplanez, totally revised by Quidn(S. Seo)
    $et['ko']['Version'] = '버전';
    $et['ko']['DocRoot'] = '호스트 루트 디렉토리';
    $et['ko']['FMRoot'] = '관리하려는 디렉토리';
    $et['ko']['DateFormat'] = '날짜 형식';
    $et['ko']['GetSize'] = '크기 계산';
    $et['ko']['Error'] = '오류';
    $et['ko']['Name'] = '이름';
    $et['ko']['And'] = '및';
    $et['ko']['Enter'] = '입력';
    $et['ko']['Send'] = '전송';
    $et['ko']['Refresh'] = '새로고침';
    $et['ko']['SaveConfig'] = '설정 저장';
    //$et['ko']['SavePass'] = '패스워드 저장';
    //$et['ko']['TypePass'] = '패스워드 입력';
    $et['ko']['SaveFile'] = '파일 저장';
    $et['ko']['Save'] = '저장';
    $et['ko']['Leave'] = '로그아웃';
    $et['ko']['Edit'] = '수정';
    $et['ko']['View'] = '보기';
    $et['ko']['Config'] = '설정';
    $et['ko']['Ren'] = '이름 변경';
    $et['ko']['Rem'] = '삭제';
    $et['ko']['Compress'] = '압축';
    $et['ko']['Decompress'] = '압축해제';
    $et['ko']['ResolveIDs'] = '소유자 ID 숫자↔문자';
    $et['ko']['Move'] = '이동';
    $et['ko']['Copy'] = '복사';
    $et['ko']['ServerInfo'] = '서버 정보';
    $et['ko']['CreateDir'] = '새 디렉토리';
    $et['ko']['CreateArq'] = '새 파일';
    $et['ko']['Symlink'] = '심링크';
    $et['ko']['HardLink'] = '하드링크';
    $et['ko']['ExecCmd'] = '명령 실행';
    $et['ko']['Upload'] = '업로드';
    $et['ko']['UploadEnd'] = '업로드 완료';
    $et['ko']['Perm'] = '권한';
    $et['ko']['Perms'] = '권한';
    $et['ko']['Owner'] = '소유자';
    $et['ko']['Group'] = '그룹';
    $et['ko']['Other'] = '기타';
    $et['ko']['Size'] = '크기';
    $et['ko']['Date'] = '날짜';
    $et['ko']['Type'] = '종류';
    $et['ko']['Free'] = '사용 가능';
    $et['ko']['Shell'] = '쉘';
    $et['ko']['Read'] = '읽기';
    $et['ko']['Write'] = '쓰기';
    $et['ko']['Exec'] = '실행';
    $et['ko']['Apply'] = '적용';
    $et['ko']['StickyBit'] = '스티키 비트';
    $et['ko']['Pass'] = '패스워드';
    $et['ko']['Lang'] = '언어';
    $et['ko']['File'] = '파일';
    $et['ko']['File_s'] = '파일';
    $et['ko']['Dir_s'] = '개의 디렉토리';
    $et['ko']['To'] = '에서';
    $et['ko']['Destination'] = '대상 디렉토리';
    $et['ko']['Configurations'] = '설정';
    $et['ko']['JSError'] = '스크립트 오류';
    $et['ko']['NoSel'] = '선택한 항목이 없습니다';
    $et['ko']['SelDir'] = '왼쪽 목록에서 대상 디렉토리를 선택해주세요';
    $et['ko']['TypeDir'] = '디렉토리 이름을 입력해주세요';
    $et['ko']['TypeArq'] = '파일 이름을 입력해주세요';
    $et['ko']['TypeCmd'] = '명령어를 입력해주세요';
    $et['ko']['TypeArqComp'] = '압축파일 이름을 입력해 주시면, 확장자에 맞는 형식으로 압축합니다.\\n\\n확장자 예시:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['ko']['RemSel'] = '선택한 항목을 삭제하시겠습니까';
    $et['ko']['NoDestDir'] = '선택한 대상 디렉토리가 없습니다';
    $et['ko']['DestEqOrig'] = '원본 디렉토리와 대상 디렉토리가 동일합니다';
    $et['ko']['InvalidDest'] = '대상 디렉토리가 올바르지 않습니다';
    $et['ko']['NoNewPerm'] = '권한이 설정되지 않았습니다';
    $et['ko']['CopyTo'] = '여기에 복사하시겠습니까';
    $et['ko']['MoveTo'] = '여기로 이동하시겠습니다';
    $et['ko']['AlterPermTo'] = '권한을 다음으로 변경하시겠습니까';
    $et['ko']['ConfExec'] = '다음을 실행하시겠습니까';
    $et['ko']['ConfRem'] = '다음을 삭제하시겠습니까';
    $et['ko']['EmptyDir'] = '디렉토리가 비었습니다';
    $et['ko']['IOError'] = '입출력 오류가 발생했습니다';
    $et['ko']['FileMan'] = 'PHP 파일 관리자';
    $et['ko']['InvPass'] = '패스워드가 올바르지 않습니다';
    $et['ko']['ReadDenied'] = '파일을 읽을 수 없습니다';
    $et['ko']['FileNotFound'] = '파일을 찾을 수 없습니다';
    $et['ko']['AutoClose'] = '완료 후 닫기';
    $et['ko']['OutDocRoot'] = '접근 가능한 디렉토리 범위를 벗어났습니다';
    $et['ko']['NoCmd'] = '오류: 명령어가 올바르지 않습니다';
    $et['ko']['ConfTrySave'] = '파일에 쓰기 권한이 없습니다.\\n그래도 저장을 시도하시겠습니까';
    $et['ko']['ConfSaved'] = '설정을 저장했습니다';
    $et['ko']['PassSaved'] = '패스워드를 저장했습니다';
    $et['ko']['FileDirExists'] = '이미 존재하는 파일 또는 디렉토리 이름입니다';
    $et['ko']['NoPhpinfo'] = 'phpinfo 함수를 사용할 수 없습니다';
    $et['ko']['NoReturn'] = '결과가 없습니다';
    $et['ko']['FileSent'] = '파일을 전송했습니다';
    $et['ko']['SpaceLimReached'] = '용량 제한을 초과했습니다';
    $et['ko']['InvExt'] = '확장자가 올바르지 않습니다';
    $et['ko']['FileNoOverw'] = '파일을 덮어쓸 수 없습니다';
    $et['ko']['FileOverw'] = '파일을 덮어썼습니다';
    $et['ko']['FileIgnored'] = '파일을 건너뛰었습니다';
    $et['ko']['ChkVer'] = '새로운 버전 확인';
    $et['ko']['ChkVerAvailable'] = '여기를 클릭하셔서 새로운 버전을 다운로드 하세요!';
    $et['ko']['ChkVerNotAvailable'] = '새로운 버전이 없습니다. :(';
    $et['ko']['ChkVerError'] = '연결에 실패했습니다';
    $et['ko']['Website'] = '웹사이트';
    $et['ko']['SendingForm'] = '파일을 전송하고 있습니다. 잠시만 기다려주세요';
    $et['ko']['NoFileSel'] = '선택한 파일이 없습니다';
    $et['ko']['SelAll'] = '전체선택';
    $et['ko']['SelNone'] = '선택해제';
    $et['ko']['SelInverse'] = '선택반전';
    $et['ko']['Selected_s'] = '선택됨';
    $et['ko']['Total'] = '전체';
    $et['ko']['Partition'] = '파티션';
    $et['ko']['RenderTime'] = '페이지 처리 시간';
    $et['ko']['Seconds'] = '초';
    $et['ko']['ErrorReport'] = '오류 출력';
    $et['ko']['Close'] = '닫기';
    $et['ko']['SetPass'] = '패스워드 설정';
    $et['ko']['ChangePass'] = '패스워드 변경';
    $et['ko']['Portscan'] = '포트스캔';
    $et['ko']['PHPOpenBasedir'] = '접근 가능한 디렉토리';
    $et['ko']['PHPOpenBasedirFullAccess'] = '(미설정) 전체 접근 가능';
    $et['ko']['About'] = '소개';
    $et['ko']['FileSaved'] = '파일을 저장했습니다';
    $et['ko']['FileSaveError'] = '파일 저장 중 오류가 발생했습니다';
    $et['ko']['Timezone'] = '시간대';
    $et['ko']['Stop'] = '정지';
    $et['ko']['Login'] = '로그인';

    // German - by Guido Ogrzal
    $et['de']['Version'] = 'Version';
    $et['de']['DocRoot'] = 'Dokument Wurzelverzeichnis';
    $et['de']['FMRoot'] = 'Dateimanager Wurzelverzeichnis';
    $et['de']['Name'] = 'Name';
    $et['de']['And'] = 'und';
    $et['de']['Enter'] = 'Eintreten';
    $et['de']['Send'] = 'Senden';
    $et['de']['Refresh'] = 'Aktualisieren';
    $et['de']['SaveConfig'] = 'Konfiguration speichern';
    $et['de']['SavePass'] = 'Passwort speichern';
    $et['de']['SaveFile'] = 'Datei speichern';
    $et['de']['Save'] = 'Speichern';
    $et['de']['Leave'] = 'Verlassen';
    $et['de']['Edit'] = 'Bearbeiten';
    $et['de']['View'] = 'Ansehen';
    $et['de']['Config'] = 'Konfigurieren';
    $et['de']['Ren'] = 'Umbenennen';
    $et['de']['Rem'] = 'Löschen';
    $et['de']['Compress'] = 'Komprimieren';
    $et['de']['Decompress'] = 'Dekomprimieren';
    $et['de']['ResolveIDs'] = 'Resolve IDs';
    $et['de']['Move'] = 'Verschieben';
    $et['de']['Copy'] = 'Kopieren';
    $et['de']['ServerInfo'] = 'Server-Info';
    $et['de']['CreateDir'] = 'Neues Verzeichnis';
    $et['de']['CreateArq'] = 'Neue Datei';
    $et['de']['ExecCmd'] = 'Kommando';
    $et['de']['Upload'] = 'Datei hochladen';
    $et['de']['UploadEnd'] = 'Datei hochladen beendet';
    $et['de']['Perm'] = 'Erlaubnis';
    $et['de']['Perms'] = 'Erlaubnis';
    $et['de']['Owner'] = 'Besitzer';
    $et['de']['Group'] = 'Gruppe';
    $et['de']['Other'] = 'Andere';
    $et['de']['Size'] = 'Größe';
    $et['de']['Date'] = 'Datum';
    $et['de']['Type'] = 'Typ';
    $et['de']['Free'] = 'frei';
    $et['de']['Shell'] = 'Shell';
    $et['de']['Read'] = 'Lesen';
    $et['de']['Write'] = 'Schreiben';
    $et['de']['Exec'] = 'Ausführen';
    $et['de']['Apply'] = 'Bestätigen';
    $et['de']['StickyBit'] = 'Sticky Bit';
    $et['de']['Pass'] = 'Passwort';
    $et['de']['Lang'] = 'Sprache';
    $et['de']['File'] = 'Datei';
    $et['de']['File_s'] = 'Datei(en)';
    $et['de']['Dir_s'] = 'Verzeichniss(e)';
    $et['de']['To'] = '-&gt;';
    $et['de']['Destination'] = 'Ziel';
    $et['de']['Configurations'] = 'Konfiguration';
    $et['de']['JSError'] = 'JavaScript Fehler';
    $et['de']['NoSel'] = 'Es gibt keine selektierten Objekte';
    $et['de']['SelDir'] = 'Selektiere das Zielverzeichnis im linken Verzeichnisbaum';
    $et['de']['TypeDir'] = 'Trage den Verzeichnisnamen ein';
    $et['de']['TypeArq'] = 'Trage den Dateinamen ein';
    $et['de']['TypeCmd'] = 'Gib das Kommando ein';
    $et['de']['TypeArqComp'] = 'Trage den Dateinamen ein.\\nDie Dateierweiterung wird den Kompressiontyp bestimmen.\\nBsp.:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['de']['RemSel'] = 'LÖSCHE die selektierten Objekte';
    $et['de']['NoDestDir'] = 'Das selektierte Zielverzeichnis existiert nicht';
    $et['de']['DestEqOrig'] = 'Quell- und Zielverzeichnis stimmen überein';
    $et['de']['InvalidDest'] = 'Zielverzeichnis ist ungültig';
    $et['de']['NoNewPerm'] = 'Neue Zugriffserlaubnis konnte nicht gesetzt werden';
    $et['de']['CopyTo'] = 'KOPIERE nach';
    $et['de']['MoveTo'] = 'VERSCHIEBE nach';
    $et['de']['AlterPermTo'] = 'ÄNDERE ZUGRIFFSERLAUBSNIS in';
    $et['de']['ConfExec'] = 'Bestätige AUSFÜHRUNG';
    $et['de']['ConfRem'] = 'Bestätige LÖSCHEN';
    $et['de']['EmptyDir'] = 'Leeres Verzeichnis';
    $et['de']['IOError'] = 'Eingabe/Ausgabe-Fehler';
    $et['de']['FileMan'] = 'PHP File Manager';
    $et['de']['TypePass'] = 'Trage das Passwort ein';
    $et['de']['InvPass'] = 'Ungültiges Passwort';
    $et['de']['ReadDenied'] = 'Lesezugriff verweigert';
    $et['de']['FileNotFound'] = 'Datei nicht gefunden';
    $et['de']['AutoClose'] = 'Schließen, wenn fertig';
    $et['de']['OutDocRoot'] = 'Datei außerhalb von DOCUMENT_ROOT';
    $et['de']['NoCmd'] = 'Fehler: Es wurde kein Kommando eingetragen';
    $et['de']['ConfTrySave'] = 'Keine Schreibberechtigung für die Datei.\\nVersuche trotzdem zu speichern';
    $et['de']['ConfSaved'] = 'Konfiguration gespeichert';
    $et['de']['PassSaved'] = 'Passwort gespeichert';
    $et['de']['FileDirExists'] = 'Datei oder Verzeichnis existiert schon';
    $et['de']['NoPhpinfo'] = 'Funktion phpinfo ist inaktiv';
    $et['de']['NoReturn'] = 'keine Rückgabe';
    $et['de']['FileSent'] = 'Datei wurde gesendet';
    $et['de']['SpaceLimReached'] = 'Verfügbares Speicherlimit wurde erreicht';
    $et['de']['InvExt'] = 'Ungültige Dateiendung';
    $et['de']['FileNoOverw'] = 'Datei kann nicht überschrieben werden';
    $et['de']['FileOverw'] = 'Datei überschrieben';
    $et['de']['FileIgnored'] = 'Datei ignoriert';
    $et['de']['ChkVer'] = 'Prüfe auf neue Version';
    $et['de']['ChkVerAvailable'] = 'Neue Version verfügbar; klicke hier, um den Download zu starten!!';
    $et['de']['ChkVerNotAvailable'] = 'Keine neue Version gefunden. :(';
    $et['de']['ChkVerError'] = 'Verbindungsfehler.';
    $et['de']['Website'] = 'Webseite';
    $et['de']['SendingForm'] = 'Sende Dateien... Bitte warten.';
    $et['de']['NoFileSel'] = 'Keine Datei selektiert';
    $et['de']['SelAll'] = 'Alle';
    $et['de']['SelNone'] = 'Keine';
    $et['de']['SelInverse'] = 'Invertieren';
    $et['de']['Selected_s'] = 'selektiert';
    $et['de']['Total'] = 'Gesamt';
    $et['de']['Partition'] = 'Partition';
    $et['de']['RenderTime'] = 'Zeit, um die Seite anzuzeigen';
    $et['de']['Seconds'] = 's';
    $et['de']['ErrorReport'] = 'Fehlerreport';

    // French - by Jean Bilwes
    $et['fr']['Version'] = 'Version';
    $et['fr']['DocRoot'] = 'Racine des documents';
    $et['fr']['FMRoot'] = 'Racine du gestionnaire de fichers';
    $et['fr']['Name'] = 'Nom';
    $et['fr']['And'] = 'et';
    $et['fr']['Enter'] = 'Enter';
    $et['fr']['Send'] = 'Envoyer';
    $et['fr']['Refresh'] = 'Rafraichir';
    $et['fr']['SaveConfig'] = 'Enregistrer la configuration';
    $et['fr']['SavePass'] = 'Enregistrer le mot de passe';
    $et['fr']['SaveFile'] = 'Enregistrer le fichier';
    $et['fr']['Save'] = 'Enregistrer';
    $et['fr']['Leave'] = 'Quitter';
    $et['fr']['Edit'] = 'Modifier';
    $et['fr']['View'] = 'Voir';
    $et['fr']['Config'] = 'Configuration';
    $et['fr']['Ren'] = 'Renommer';
    $et['fr']['Rem'] = 'Supprimer';
    $et['fr']['Compress'] = 'Compresser';
    $et['fr']['Decompress'] = 'Décompresser';
    $et['fr']['ResolveIDs'] = 'Résoudre les IDs';
    $et['fr']['Move'] = 'Déplacer';
    $et['fr']['Copy'] = 'Copier';
    $et['fr']['ServerInfo'] = 'Info serveur';
    $et['fr']['CreateDir'] = 'Créer un répertoire';
    $et['fr']['CreateArq'] = 'Créer un fichier';
    $et['fr']['ExecCmd'] = 'Executer une commande';
    $et['fr']['Upload'] = 'Upload';
    $et['fr']['UploadEnd'] = 'Upload terminé';
    $et['fr']['Perm'] = 'Perm';
    $et['fr']['Perms'] = 'Permissions';
    $et['fr']['Owner'] = 'Propriétaire';
    $et['fr']['Group'] = 'Groupe';
    $et['fr']['Other'] = 'Autre';
    $et['fr']['Size'] = 'Taille';
    $et['fr']['Date'] = 'Date';
    $et['fr']['Type'] = 'Type';
    $et['fr']['Free'] = 'libre';
    $et['fr']['Shell'] = 'Shell';
    $et['fr']['Read'] = 'Lecture';
    $et['fr']['Write'] = 'Ecriture';
    $et['fr']['Exec'] = 'Executer';
    $et['fr']['Apply'] = 'Appliquer';
    $et['fr']['StickyBit'] = 'Sticky Bit';
    $et['fr']['Pass'] = 'Mot de passe';
    $et['fr']['Lang'] = 'Langage';
    $et['fr']['File'] = 'Fichier';
    $et['fr']['File_s'] = 'fichier(s)';
    $et['fr']['Dir_s'] = 'répertoire(s)';
    $et['fr']['To'] = 'à';
    $et['fr']['Destination'] = 'Destination';
    $et['fr']['Configurations'] = 'Configurations';
    $et['fr']['JSError'] = 'Erreur JavaScript';
    $et['fr']['NoSel'] = 'Rien n\'est sélectionné';
    $et['fr']['SelDir'] = 'Selectionnez le répertoire de destination dans le panneau gauche';
    $et['fr']['TypeDir'] = 'Entrer le nom du répertoire';
    $et['fr']['TypeArq'] = 'Entrer le nom du fichier';
    $et['fr']['TypeCmd'] = 'Entrer la commande';
    $et['fr']['TypeArqComp'] = 'Entrer le nom du fichier.\\nL\'extension définira le type de compression.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['fr']['RemSel'] = 'EFFACER les objets sélectionnés';
    $et['fr']['NoDestDir'] = 'Aucun répertoire de destination n\'est sélectionné';
    $et['fr']['DestEqOrig'] = 'Les répertoires source et destination sont identiques';
    $et['fr']['InvalidDest'] = 'Le répertoire de destination est invalide';
    $et['fr']['NoNewPerm'] = 'Nouvelle permission non établie';
    $et['fr']['CopyTo'] = 'COPIER vers';
    $et['fr']['MoveTo'] = 'DEPLACER vers';
    $et['fr']['AlterPermTo'] = 'CHANGER LES PERMISSIONS';
    $et['fr']['ConfExec'] = 'Confirmer l\'EXECUTION';
    $et['fr']['ConfRem'] = 'Confirmer la DESTRUCTION';
    $et['fr']['EmptyDir'] = 'Répertoire vide';
    $et['fr']['IOError'] = 'I/O Error';
    $et['fr']['FileMan'] = 'PHP File Manager';
    $et['fr']['TypePass'] = 'Entrer le mot de passe';
    $et['fr']['InvPass'] = 'Mot de passe invalide';
    $et['fr']['ReadDenied'] = 'Droit de lecture refusé';
    $et['fr']['FileNotFound'] = 'Fichier introuvable';
    $et['fr']['AutoClose'] = 'Fermer sur fin';
    $et['fr']['OutDocRoot'] = 'Fichier au delà de DOCUMENT_ROOT';
    $et['fr']['NoCmd'] = 'Erreur: Commande non renseignée';
    $et['fr']['ConfTrySave'] = 'Fichier sans permission d\'écriture.\\nJ\'essaie de l\'enregister';
    $et['fr']['ConfSaved'] = 'Configurations enreristrée';
    $et['fr']['PassSaved'] = 'Mot de passe enreristré';
    $et['fr']['FileDirExists'] = 'Le fichier ou le répertoire existe déjà';
    $et['fr']['NoPhpinfo'] = 'Function phpinfo désactivée';
    $et['fr']['NoReturn'] = 'pas de retour';
    $et['fr']['FileSent'] = 'Fichier envoyé';
    $et['fr']['SpaceLimReached'] = 'Espace maxi atteint';
    $et['fr']['InvExt'] = 'Extension invalide';
    $et['fr']['FileNoOverw'] = 'Le fichier ne peut pas etre écrasé';
    $et['fr']['FileOverw'] = 'Fichier écrasé';
    $et['fr']['FileIgnored'] = 'Fichier ignoré';
    $et['fr']['ChkVer'] = 'Verifier nouvelle version';
    $et['fr']['ChkVerAvailable'] = 'Nouvelle version, cliquer ici pour la téléchager!!';
    $et['fr']['ChkVerNotAvailable'] = 'Aucune mise a jour de disponible. :(';
    $et['fr']['ChkVerError'] = 'Erreur de connection.';
    $et['fr']['Website'] = 'siteweb';
    $et['fr']['SendingForm'] = 'Envoi des fichiers en cours, Patienter';
    $et['fr']['NoFileSel'] = 'Aucun fichier sélectionné';
    $et['fr']['SelAll'] = 'Tous';
    $et['fr']['SelNone'] = 'Aucun';
    $et['fr']['SelInverse'] = 'Inverser';
    $et['fr']['Selected_s'] = 'selectioné';
    $et['fr']['Total'] = 'total';
    $et['fr']['Partition'] = 'Partition';
    $et['fr']['RenderTime'] = 'Temps pour afficher cette page';
    $et['fr']['Seconds'] = 'sec';
    $et['fr']['ErrorReport'] = 'Rapport d\'erreur';

    // Dutch - by Leon Buijs
    $et['nl']['Version'] = 'Versie';
    $et['nl']['DocRoot'] = 'Document Root';
    $et['nl']['FMRoot'] = 'File Manager Root';
    $et['nl']['Name'] = 'Naam';
    $et['nl']['And'] = 'en';
    $et['nl']['Enter'] = 'Enter';
    $et['nl']['Send'] = 'Verzend';
    $et['nl']['Refresh'] = 'Vernieuw';
    $et['nl']['SaveConfig'] = 'Configuratie opslaan';
    $et['nl']['SavePass'] = 'Wachtwoord opslaan';
    $et['nl']['SaveFile'] = 'Bestand opslaan';
    $et['nl']['Save'] = 'Opslaan';
    $et['nl']['Leave'] = 'Verlaten';
    $et['nl']['Edit'] = 'Wijzigen';
    $et['nl']['View'] = 'Toon';
    $et['nl']['Config'] = 'Configuratie';
    $et['nl']['Ren'] = 'Naam wijzigen';
    $et['nl']['Rem'] = 'Verwijderen';
    $et['nl']['Compress'] = 'Comprimeren';
    $et['nl']['Decompress'] = 'Decomprimeren';
    $et['nl']['ResolveIDs'] = 'Resolve IDs';
    $et['nl']['Move'] = 'Verplaats';
    $et['nl']['Copy'] = 'Kopieer';
    $et['nl']['ServerInfo'] = 'Serverinformatie';
    $et['nl']['CreateDir'] = 'Nieuwe map';
    $et['nl']['CreateArq'] = 'Nieuw bestand';
    $et['nl']['ExecCmd'] = 'Commando uitvoeren';
    $et['nl']['Upload'] = 'Upload';
    $et['nl']['UploadEnd'] = 'Upload voltooid';
    $et['nl']['Perm'] = 'Rechten';
    $et['nl']['Perms'] = 'Rechten';
    $et['nl']['Owner'] = 'Eigenaar';
    $et['nl']['Group'] = 'Groep';
    $et['nl']['Other'] = 'Anderen';
    $et['nl']['Size'] = 'Grootte';
    $et['nl']['Date'] = 'Datum';
    $et['nl']['Type'] = 'Type';
    $et['nl']['Free'] = 'free';
    $et['nl']['Shell'] = 'Shell';
    $et['nl']['Read'] = 'Lezen';
    $et['nl']['Write'] = 'Schrijven';
    $et['nl']['Exec'] = 'Uitvoeren';
    $et['nl']['Apply'] = 'Toepassen';
    $et['nl']['StickyBit'] = 'Sticky Bit';
    $et['nl']['Pass'] = 'Wachtwoord';
    $et['nl']['Lang'] = 'Taal';
    $et['nl']['File'] = 'Bestand';
    $et['nl']['File_s'] = 'bestand(en)';
    $et['nl']['Dir_s'] = 'map(pen)';
    $et['nl']['To'] = 'naar';
    $et['nl']['Destination'] = 'Bestemming';
    $et['nl']['Configurations'] = 'Instellingen';
    $et['nl']['JSError'] = 'Javascriptfout';
    $et['nl']['NoSel'] = 'Er zijn geen bestanden geselecteerd';
    $et['nl']['SelDir'] = 'Kies de bestemming in de boom aan de linker kant';
    $et['nl']['TypeDir'] = 'Voer de mapnaam in';
    $et['nl']['TypeArq'] = 'Voer de bestandsnaam in';
    $et['nl']['TypeCmd'] = 'Voer het commando in';
    $et['nl']['TypeArqComp'] = 'Voer de bestandsnaam in.\\nDe extensie zal het compressietype bepalen.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['nl']['RemSel'] = 'VERWIJDER geselecteerde itens';
    $et['nl']['NoDestDir'] = 'Er is geen doelmap geselecteerd';
    $et['nl']['DestEqOrig'] = 'Bron- en doelmap zijn hetzelfde';
    $et['nl']['InvalidDest'] = 'Doelmap is ongeldig';
    $et['nl']['NoNewPerm'] = 'Nieuwe rechten niet geset';
    $et['nl']['CopyTo'] = 'KOPIEER naar';
    $et['nl']['MoveTo'] = 'VERPLAATS naar';
    $et['nl']['AlterPermTo'] = 'VERANDER RECHTEN in';
    $et['nl']['ConfExec'] = 'Bevestig UITVOEREN';
    $et['nl']['ConfRem'] = 'Bevestig VERWIJDEREN';
    $et['nl']['EmptyDir'] = 'Lege map';
    $et['nl']['IOError'] = 'I/O Error';
    $et['nl']['FileMan'] = 'PHP File Manager';
    $et['nl']['TypePass'] = 'Voer het wachtwoord in';
    $et['nl']['InvPass'] = 'Ongeldig wachtwoord';
    $et['nl']['ReadDenied'] = 'Leestoegang ontzegd';
    $et['nl']['FileNotFound'] = 'Bestand niet gevonden';
    $et['nl']['AutoClose'] = 'Sluit na voltooien';
    $et['nl']['OutDocRoot'] = 'Bestand buiten DOCUMENT_ROOT';
    $et['nl']['NoCmd'] = 'Error: Command not informed';
    $et['nl']['ConfTrySave'] = 'Bestand zonder schrijfrechten.\\nProbeer een andere manier';
    $et['nl']['ConfSaved'] = 'Instellingen opgeslagen';
    $et['nl']['PassSaved'] = 'Wachtwoord opgeslagen';
    $et['nl']['FileDirExists'] = 'Bestand of map bestaat al';
    $et['nl']['NoPhpinfo'] = 'Functie \'phpinfo\' is uitgeschakeld';
    $et['nl']['NoReturn'] = 'no return';
    $et['nl']['FileSent'] = 'Bestand verzonden';
    $et['nl']['SpaceLimReached'] = 'Opslagruimtelimiet bereikt';
    $et['nl']['InvExt'] = 'Ongeldige extensie';
    $et['nl']['FileNoOverw'] = 'Bestand kan niet worden overgeschreven';
    $et['nl']['FileOverw'] = 'Bestand overgeschreven';
    $et['nl']['FileIgnored'] = 'Bestand genegeerd';
    $et['nl']['ChkVer'] = 'Controleer nieuwe versie';
    $et['nl']['ChkVerAvailable'] = 'Nieuwe versie, klik hier om de download te starten';
    $et['nl']['ChkVerNotAvailable'] = 'Geen nieuwe versie beschikbaar';
    $et['nl']['ChkVerError'] = 'Verbindingsfout.';
    $et['nl']['Website'] = 'Website';
    $et['nl']['SendingForm'] = 'Bestanden worden verzonden. Even geduld...';
    $et['nl']['NoFileSel'] = 'Geen bestanden geselecteerd';
    $et['nl']['SelAll'] = 'Alles';
    $et['nl']['SelNone'] = 'Geen';
    $et['nl']['SelInverse'] = 'Keer om';
    $et['nl']['Selected_s'] = 'geselecteerd';
    $et['nl']['Total'] = 'totaal';
    $et['nl']['Partition'] = 'Partitie';
    $et['nl']['RenderTime'] = 'Tijd voor maken van deze pagina';
    $et['nl']['Seconds'] = 'sec';
    $et['nl']['ErrorReport'] = 'Foutenrapport';

    // Italian - by Valerio Capello
    $et['it']['Version'] = 'Versione';
    $et['it']['DocRoot'] = 'Document Root';
    $et['it']['FMRoot'] = 'File Manager Root';
    $et['it']['Name'] = 'Nome';
    $et['it']['And'] = 'e';
    $et['it']['Enter'] = 'Immetti';
    $et['it']['Send'] = 'Invia';
    $et['it']['Refresh'] = 'Aggiorna';
    $et['it']['SaveConfig'] = 'Salva la Configurazione';
    $et['it']['SavePass'] = 'Salva la Password';
    $et['it']['SaveFile'] = 'Salva il File';
    $et['it']['Save'] = 'Salva';
    $et['it']['Leave'] = 'Abbandona';
    $et['it']['Edit'] = 'Modifica';
    $et['it']['View'] = 'Guarda';
    $et['it']['Config'] = 'Configurazione';
    $et['it']['Ren'] = 'Rinomina';
    $et['it']['Rem'] = 'Elimina';
    $et['it']['Compress'] = 'Comprimi';
    $et['it']['Decompress'] = 'Decomprimi';
    $et['it']['ResolveIDs'] = 'Risolvi IDs';
    $et['it']['Move'] = 'Sposta';
    $et['it']['Copy'] = 'Copia';
    $et['it']['ServerInfo'] = 'Informazioni sul Server';
    $et['it']['CreateDir'] = 'Crea Directory';
    $et['it']['CreateArq'] = 'Crea File';
    $et['it']['ExecCmd'] = 'Esegui Comando';
    $et['it']['Upload'] = 'Carica';
    $et['it']['UploadEnd'] = 'Caricamento terminato';
    $et['it']['Perm'] = 'Perm';
    $et['it']['Perms'] = 'Permessi';
    $et['it']['Owner'] = 'Proprietario';
    $et['it']['Group'] = 'Gruppo';
    $et['it']['Other'] = 'Altri';
    $et['it']['Size'] = 'Dimensioni';
    $et['it']['Date'] = 'Data';
    $et['it']['Type'] = 'Tipo';
    $et['it']['Free'] = 'liberi';
    $et['it']['Shell'] = 'Shell';
    $et['it']['Read'] = 'Lettura';
    $et['it']['Write'] = 'Scrittura';
    $et['it']['Exec'] = 'Esecuzione';
    $et['it']['Apply'] = 'Applica';
    $et['it']['StickyBit'] = 'Sticky Bit';
    $et['it']['Pass'] = 'Password';
    $et['it']['Lang'] = 'Lingua';
    $et['it']['File'] = 'File';
    $et['it']['File_s'] = 'file';
    $et['it']['Dir_s'] = 'directory';
    $et['it']['To'] = 'a';
    $et['it']['Destination'] = 'Destinazione';
    $et['it']['Configurations'] = 'Configurazione';
    $et['it']['JSError'] = 'Errore JavaScript';
    $et['it']['NoSel'] = 'Non ci sono elementi selezionati';
    $et['it']['SelDir'] = 'Scegli la directory di destinazione';
    $et['it']['TypeDir'] = 'Inserisci il nome della directory';
    $et['it']['TypeArq'] = 'Inserisci il nome del file';
    $et['it']['TypeCmd'] = 'Inserisci il comando';
    $et['it']['TypeArqComp'] = 'Inserisci il nome del file.\\nLa estensione definirà il tipo di compressione.\\nEsempio:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['it']['RemSel'] = 'ELIMINA gli elementi selezionati';
    $et['it']['NoDestDir'] = 'LA directory di destinazione non è stata selezionata';
    $et['it']['DestEqOrig'] = 'La directory di origine e di destinazione sono la stessa';
    $et['it']['InvalidDest'] = 'La directory di destinazione non è valida';
    $et['it']['NoNewPerm'] = 'Nuovi permessi non attivati';
    $et['it']['CopyTo'] = 'COPIA in';
    $et['it']['MoveTo'] = 'SPOSTA in';
    $et['it']['AlterPermTo'] = 'CAMBIA I PERMESSI: ';
    $et['it']['ConfExec'] = 'Conferma ESECUZIONE';
    $et['it']['ConfRem'] = 'Conferma ELIMINAZIONE';
    $et['it']['EmptyDir'] = 'Directory vuota';
    $et['it']['IOError'] = 'Errore di I/O';
    $et['it']['FileMan'] = 'PHP File Manager';
    $et['it']['TypePass'] = 'Immetti la password';
    $et['it']['InvPass'] = 'Password non valida';
    $et['it']['ReadDenied'] = 'Permesso di lettura negato';
    $et['it']['FileNotFound'] = 'File non trovato';
    $et['it']['AutoClose'] = 'Chiudi la finestra al termine';
    $et['it']['OutDocRoot'] = 'File oltre DOCUMENT_ROOT';
    $et['it']['NoCmd'] = 'Errore: Comando non informato';
    $et['it']['ConfTrySave'] = 'File senza permesso di scrittura.\\nProvo a salvare comunque';
    $et['it']['ConfSaved'] = 'Configurazione salvata';
    $et['it']['PassSaved'] = 'Password salvata';
    $et['it']['FileDirExists'] = 'Il file o la directory esiste già';
    $et['it']['NoPhpinfo'] = 'La funzione phpinfo è disabilitata';
    $et['it']['NoReturn'] = 'senza Return';
    $et['it']['FileSent'] = 'File inviato';
    $et['it']['SpaceLimReached'] = 'è stato raggiunto il limite di spazio disponibile';
    $et['it']['InvExt'] = 'Estensione non valida';
    $et['it']['FileNoOverw'] = 'Il file non può essere sovrascritto';
    $et['it']['FileOverw'] = 'File sovrascritto';
    $et['it']['FileIgnored'] = 'File ignorato';
    $et['it']['ChkVer'] = 'Controlla se è disponibile una nuova versione';
    $et['it']['ChkVerAvailable'] = 'è disponibile una nuova versione: premi qui per scaricarla.';
    $et['it']['ChkVerNotAvailable'] = 'Non è disponibile nessuna nuova versione. :(';
    $et['it']['ChkVerError'] = 'Errore di connessione.';
    $et['it']['Website'] = 'Sito Web';
    $et['it']['SendingForm'] = 'Invio file, attendere prego';
    $et['it']['NoFileSel'] = 'Nessun file selezionato';
    $et['it']['SelAll'] = 'Tutti';
    $et['it']['SelNone'] = 'Nessuno';
    $et['it']['SelInverse'] = 'Inverti';
    $et['it']['Selected_s'] = 'selezionato';
    $et['it']['Total'] = 'totali';
    $et['it']['Partition'] = 'Partizione';
    $et['it']['RenderTime'] = 'Tempo per elaborare questa pagina';
    $et['it']['Seconds'] = 'sec';
    $et['it']['ErrorReport'] = 'Error Reporting';

    // Turkish - by Necdet Yazilimlari
    $et['tr']['Version'] = 'Versiyon';
    $et['tr']['DocRoot'] = 'Kok dosya';
    $et['tr']['FMRoot'] = 'Kok dosya yoneticisi';
    $et['tr']['Name'] = 'Isim';
    $et['tr']['And'] = 've';
    $et['tr']['Enter'] = 'Giris';
    $et['tr']['Send'] = 'Yolla';
    $et['tr']['Refresh'] = 'Yenile';
    $et['tr']['SaveConfig'] = 'Ayarlari kaydet';
    $et['tr']['SavePass'] = 'Parolayi kaydet';
    $et['tr']['SaveFile'] = 'Dosyayi kaydet';
    $et['tr']['Save'] = 'Kaydet';
    $et['tr']['Leave'] = 'Ayril';
    $et['tr']['Edit'] = 'Duzenle';
    $et['tr']['View'] = 'Goster';
    $et['tr']['Config'] = 'Yapilandirma';
    $et['tr']['Ren'] = 'Yeniden adlandir';
    $et['tr']['Rem'] = 'Sil';
    $et['tr']['Compress'] = '.Zip';
    $et['tr']['Decompress'] = '.ZipCoz';
    $et['tr']['ResolveIDs'] = 'Kimlikleri coz';
    $et['tr']['Move'] = 'Tasi';
    $et['tr']['Copy'] = 'Kopyala';
    $et['tr']['ServerInfo'] = 'Sunucu Bilgisi';
    $et['tr']['CreateDir'] = 'Dizin olustur';
    $et['tr']['CreateArq'] = 'Dosya olusutur';
    $et['tr']['ExecCmd'] = 'Komut calistir';
    $et['tr']['Upload'] = 'Dosya yukle';
    $et['tr']['UploadEnd'] = 'Yukleme tamamlandi';
    $et['tr']['Perm'] = 'Izinler';
    $et['tr']['Perms'] = 'Izinler';
    $et['tr']['Owner'] = 'Sahip';
    $et['tr']['Group'] = 'Grup';
    $et['tr']['Other'] = 'Diger';
    $et['tr']['Size'] = 'Boyut';
    $et['tr']['Date'] = 'Tarih';
    $et['tr']['Type'] = 'Tip';
    $et['tr']['Free'] = 'Bos';
    $et['tr']['Shell'] = 'Kabuk';
    $et['tr']['Read'] = 'Oku';
    $et['tr']['Write'] = 'Yaz';
    $et['tr']['Exec'] = 'Calistir';
    $et['tr']['Apply'] = 'Uygula';
    $et['tr']['StickyBit'] = 'Sabit bit';
    $et['tr']['Pass'] = 'Parola';
    $et['tr']['Lang'] = 'Dil';
    $et['tr']['File'] = 'Dosya';
    $et['tr']['File_s'] = 'Dosya(lar)';
    $et['tr']['Dir_s'] = 'Dizin(ler)';
    $et['tr']['To'] = 'icin';
    $et['tr']['Destination'] = 'Hedef';
    $et['tr']['Configurations'] = 'Yapilandirmalar';
    $et['tr']['JSError'] = 'JavaScript hatasi';
    $et['tr']['NoSel'] = 'Secilen oge yok';
    $et['tr']['SelDir'] = 'Soldaki hedef dizin agaci secin';
    $et['tr']['TypeDir'] = 'Dizin adini girin';
    $et['tr']['TypeArq'] = 'Dosya adini girin';
    $et['tr']['TypeCmd'] = 'Komut girin';
    $et['tr']['TypeArqComp'] = 'Dosya ismini yazdiktan sonra sonuna .zip ekleyin';
    $et['tr']['RemSel'] = 'Secili ogeleri sil';
    $et['tr']['NoDestDir'] = 'Secili dizin yok';
    $et['tr']['DestEqOrig'] = 'Kokenli ve esit gidis rehberi';
    $et['tr']['InvalidDest'] = 'Hedef dizin gecersiz';
    $et['tr']['NoNewPerm'] = 'Izinler uygun degil';
    $et['tr']['CopyTo'] = 'Kopya icin';
    $et['tr']['MoveTo'] = 'Tasi icin';
    $et['tr']['AlterPermTo'] = 'Permission secin';
    $et['tr']['ConfExec'] = 'Yapilandirmayi onayla';
    $et['tr']['ConfRem'] = 'Simeyi onayla';
    $et['tr']['EmptyDir'] = 'Dizin bos';
    $et['tr']['IOError'] = 'Hata';
    $et['tr']['FileMan'] = 'Necdet_Yazilimlari';
    $et['tr']['TypePass'] = 'Parolayi girin';
    $et['tr']['InvPass'] = 'Gecersiz parola';
    $et['tr']['ReadDenied'] = 'Okumaya erisim engellendi';
    $et['tr']['FileNotFound'] = 'Dosya bulunamadi';
    $et['tr']['AutoClose'] = 'Otomatik kapat';
    $et['tr']['OutDocRoot'] = 'Kok klasor disindaki dosya';
    $et['tr']['NoCmd'] = 'Hata: Komut haberdar degil';
    $et['tr']['ConfTrySave'] = 'Dosya yazma izniniz yok. Yine de kaydetmeyi deneyebilirsiniz.';
    $et['tr']['ConfSaved'] = 'Ayarlar kaydedildi';
    $et['tr']['PassSaved'] = 'Parola kaydedildi';
    $et['tr']['FileDirExists'] = 'Dosya veya dizin zaten var';
    $et['tr']['NoPhpinfo'] = 'Php fonksiyon bilgisi devre disi';
    $et['tr']['NoReturn'] = 'Deger dondurmuyor';
    $et['tr']['FileSent'] = 'Dosya gonderildi';
    $et['tr']['SpaceLimReached'] = 'Disk limitine ulasildi';
    $et['tr']['InvExt'] = 'Gecersiz uzanti';
    $et['tr']['FileNoOverw'] = 'Dosya degistirilemiyor';
    $et['tr']['FileOverw'] = 'Dosya degistiribiliyor';
    $et['tr']['FileIgnored'] = 'Dosya kabul edildi';
    $et['tr']['ChkVer'] = 'Yeni versiyonu kontrol et';
    $et['tr']['ChkVerAvailable'] = 'Yeni surum bulundu. Indirmek icin buraya tiklayin.';
    $et['tr']['ChkVerNotAvailable'] = 'Yeni surum bulunamadi.';
    $et['tr']['ChkVerError'] = 'Baglanti hatasi';
    $et['tr']['Website'] = 'Website';
    $et['tr']['SendingForm'] = 'Dosyalar gonderiliyor, lutfen bekleyin';
    $et['tr']['NoFileSel'] = 'Secili dosya yok';
    $et['tr']['SelAll'] = 'Hepsi';
    $et['tr']['SelNone'] = 'Hicbiri';
    $et['tr']['SelInverse'] = 'Ters';
    $et['tr']['Selected_s'] = 'Secili oge(ler)';
    $et['tr']['Total'] = 'Toplam';
    $et['tr']['Partition'] = 'Bolme';
    $et['tr']['RenderTime'] = 'Olusturuluyor';
    $et['tr']['Seconds'] = 'Saniye';
    $et['tr']['ErrorReport'] = 'Hata raporu';

    // Russian - by Евгений Рашев, Алексей Гаврюшин
    $et['ru']['Version']='Версия';
    $et['ru']['DocRoot']='Корневая папка';
    $et['ru']['FMRoot']='Корневая папка файлового менеджера';
    $et['ru']['Name']='Имя';
    $et['ru']['And']='и';
    $et['ru']['Enter']='Войти';
    $et['ru']['Send']='Отправить';
    $et['ru']['Refresh']='Обновить';
    $et['ru']['SaveConfig']='Сохранить конфигурацию';
    $et['ru']['SavePass']='Сохранить пароль';
    $et['ru']['SaveFile']='Сохранить файл';
    $et['ru']['Save']='Сохранить';
    $et['ru']['Leave']='Уйти';
    $et['ru']['Edit']='Изменить';
    $et['ru']['View']='Просмотр';
    $et['ru']['Config']='Настройки';
    $et['ru']['Ren']='Переименовать';
    $et['ru']['Rem']='Удалить';
    $et['ru']['Compress']='Сжать';
    $et['ru']['Decompress']='Распаковать';
    $et['ru']['ResolveIDs']='Определить ID';
    $et['ru']['Move']='Переместить';
    $et['ru']['Copy']='Копировать';
    $et['ru']['ServerInfo']='Инфо о сервере';
    $et['ru']['CreateDir']='Создать папку';
    $et['ru']['CreateArq']='Создать файл';
    $et['ru']['ExecCmd']='Выполнить';
    $et['ru']['Upload']='Загрузить';
    $et['ru']['UploadEnd']='Загружено';
    $et['ru']['Perm']='Права';
    $et['ru']['Perms']='Разрешения';
    $et['ru']['Owner']='Владелец';
    $et['ru']['Group']='Группа';
    $et['ru']['Other']='Другие';
    $et['ru']['Size']='Размер';
    $et['ru']['Date']='Дата';
    $et['ru']['Type']='Тип';
    $et['ru']['Free']='Свободно';
    $et['ru']['Shell']='Командная строка';
    $et['ru']['Read']='Читать';
    $et['ru']['Write']='Писать';
    $et['ru']['Exec']='Выполнять';
    $et['ru']['Apply']='Применить';
    $et['ru']['StickyBit']='StickyBit';
    $et['ru']['Pass']='Пароль';
    $et['ru']['Lang']='Язык';
    $et['ru']['File']='Файл';
    $et['ru']['File_s']='Файл(ы)';
    $et['ru']['Dir_s']='Папка/и';
    $et['ru']['To']='в';
    $et['ru']['Destination']='Конечная папка';
    $et['ru']['Configurations']='Конфигурация';
    $et['ru']['JSError']='Ошибка JavaScript';
    $et['ru']['NoSel']='Нет выбранных элементов';
    $et['ru']['SelDir']='Выберите папку назначения в левом дереве';
    $et['ru']['TypeDir']='Введите имя папки';
    $et['ru']['TypeArq']='Введите имя файла';
    $et['ru']['TypeCmd']='Введите команду';
    $et['ru']['TypeArqComp']='Введите имя и расширение файла.\\nРасширение определит тип сжатия.\\n Пример: \\n nome.zip \\n nome.tar \\n nome.bzip \\n nome.gzip ';
    $et['ru']['RemSel']='Удалить выбранные элементы';
    $et['ru']['NoDestDir']='Не выбрана папка назначения';
    $et['ru']['DestEqOrig']='Исходные и конечные папки равны';
    $et['ru']['InvalidDest']='Конечная папка недействительна';
    $et['ru']['NoNewPerm']='Новые разрешения не установлены';
    $et['ru']['CopyTo']='Копировать в';
    $et['ru']['MoveTo']='Переместить в';
    $et['ru']['AlterPermTo']='Измененить разрешения на';
    $et['ru']['ConfExec']='Подтвердить ВЫПОЛНЕНИЕ';
    $et['ru']['ConfRem']='Подтвердить УДАЛЕНИЕ';
    $et['ru']['EmptyDir']='Пустая папка';
    $et['ru']['IOError']='Ошибка I/O';
    $et['ru']['FileMan']='Файловый менеджер';
    $et['ru']['TypePass']='Введите пароль';
    $et['ru']['InvPass']='Неверный пароль';
    $et['ru']['ReadDenied']='Доступ запрещен';
    $et['ru']['FileNotFound']='Файл не найден';
    $et['ru']['AutoClose']='Закрыть после окончания';
    $et['ru']['OutDocRoot']='Файлы за пределами DOCUMENT_ROOT';
    $et['ru']['NoCmd']='Ошибка: Команда не поддерживается';
    $et['ru']['ConfTrySave']='Файл без прав на запись.\\nПопытаться сохранить';
    $et['ru']['ConfSaved']='Конфигурация сохранена';
    $et['ru']['PassSaved']='Пароль сохранен';
    $et['ru']['FileDirExists']='Файл или папка уже существует';
    $et['ru']['NoPhpinfo']='Функция PHPInfo отключена';
    $et['ru']['NoReturn']='Нет возврата';
    $et['ru']['FileSent']='Файл отправлен';
    $et['ru']['SpaceLimReached']='Память полностью заполнена';
    $et['ru']['InvExt']='Недействительное расширение';
    $et['ru']['FileNoOverw']='Файл не может быть перезаписан';
    $et['ru']['FileOverw']='Файл перезаписан';
    $et['ru']['FileIgnored']='Файл игнорирован';
    $et['ru']['ChkVer']='Поиск обновлений';
    $et['ru']['ChkVerAvailable']=' Доступна новая версия; нажмите здесь, чтобы начать загрузку!';
    $et['ru']['ChkVerNotAvailable']='Не найдено новой версии.';
    $et['ru']['ChkVerError']='Ошибка подключения.';
    $et['ru']['Website']='Сайт';
    $et['ru']['SendingForm']='Отправка файлов; пожалуйста, подождите';
    $et['ru']['NoFileSel']='Нет выбранных файлов';
    $et['ru']['SelAll']='Выделить все';
    $et['ru']['SelNone']='Отмена';
    $et['ru']['SelInverse']='Обратить выбор';
    $et['ru']['Selected_s']='Выбран(ы)';
    $et['ru']['Total']='Всего';
    $et['ru']['Partition']='Раздел';
    $et['ru']['RenderTime']='Скрипт выполнен за';
    $et['ru']['Seconds']='секунд';
    $et['ru']['ErrorReport']='Отчет об ошибках';

    // Catalan - by Pere Borràs AKA @Norl
    $et['ca']['Version'] = 'Versió';
    $et['ca']['DocRoot'] = 'Arrel del programa';
    $et['ca']['FMRoot'] = 'Arrel de l`administrador d`arxius';
    $et['ca']['Name'] = 'Nom';
    $et['ca']['And'] = 'i';
    $et['ca']['Enter'] = 'Entrar';
    $et['ca']['Send'] = 'Enviar';
    $et['ca']['Refresh'] = 'Refrescar';
    $et['ca']['SaveConfig'] = 'Desar configuracions';
    $et['ca']['SavePass'] = 'Desar clau';
    $et['ca']['SaveFile'] = 'Desar Arxiu';
    $et['ca']['Save'] = 'Desar';
    $et['ca']['Leave'] = 'Sortir';
    $et['ca']['Edit'] = 'Editar';
    $et['ca']['View'] = 'Mirar';
    $et['ca']['Config'] = 'Config.';
    $et['ca']['Ren'] = 'Canviar nom';
    $et['ca']['Rem'] = 'Esborrar';
    $et['ca']['Compress'] = 'Comprimir';
    $et['ca']['Decompress'] = 'Descomprimir';
    $et['ca']['ResolveIDs'] = 'Resoldre IDs';
    $et['ca']['Move'] = 'Moure';
    $et['ca']['Copy'] = 'Copiar';
    $et['ca']['ServerInfo'] = 'Info del Server';
    $et['ca']['CreateDir'] = 'Crear Directori';
    $et['ca']['CreateArq'] = 'Crear Arxiu';
    $et['ca']['ExecCmd'] = 'Executar Comandament';
    $et['ca']['Upload'] = 'Pujar';
    $et['ca']['UploadEnd'] = 'Pujat amb èxit';
    $et['ca']['Perm'] = 'Perm';
    $et['ca']['Perms'] = 'Permisos';
    $et['ca']['Owner'] = 'Propietari';
    $et['ca']['Group'] = 'Grup';
    $et['ca']['Other'] = 'Altre';
    $et['ca']['Size'] = 'Tamany';
    $et['ca']['Date'] = 'Data';
    $et['ca']['Type'] = 'Tipus';
    $et['ca']['Free'] = 'lliure';
    $et['ca']['Shell'] = 'Executar';
    $et['ca']['Read'] = 'Llegir';
    $et['ca']['Write'] = 'Escriure';
    $et['ca']['Exec'] = 'Executar';
    $et['ca']['Apply'] = 'Aplicar';
    $et['ca']['StickyBit'] = 'Sticky Bit';
    $et['ca']['Pass'] = 'Clau';
    $et['ca']['Lang'] = 'Llenguatje';
    $et['ca']['File'] = 'Arxius';
    $et['ca']['File_s'] = 'arxiu(s)';
    $et['ca']['Dir_s'] = 'directori(s)';
    $et['ca']['To'] = 'a';
    $et['ca']['Destination'] = 'Destí';
    $et['ca']['Configurations'] = 'Configuracions';
    $et['ca']['JSError'] = 'Error de JavaScript';
    $et['ca']['NoSel'] = 'No hi ha items seleccionats';
    $et['ca']['SelDir'] = 'Seleccioneu el directori de destí a l`arbre de la dreta';
    $et['ca']['TypeDir'] = 'Escrigui el nom del directori';
    $et['ca']['TypeArq'] = 'Escrigui el nom de l`arxiu';
    $et['ca']['TypeCmd'] = 'Escrigui el comandament';
    $et['ca']['TypeArqComp'] = 'Escrigui el nombre del directorio.\\nL`extensió definirà el tipus de compressió.\\nEx:\\nnom.zip\\nnom.tar\\nnom.bzip\\nnom.gzip';
    $et['ca']['RemSel'] = 'ESBORRAR items seleccionats';
    $et['ca']['NoDestDir'] = 'No s`ha seleccionat el directori de destí';
    $et['ca']['DestEqOrig'] = 'L`origen i el destí són iguals';
    $et['ca']['InvalidDest'] = 'El destí del directori és invàlid';
    $et['ca']['NoNewPerm'] = 'Els permisos no s`han pogut establir';
    $et['ca']['CopyTo'] = 'COPIAR a';
    $et['ca']['MoveTo'] = 'MOURE a';
    $et['ca']['AlterPermTo'] = 'CAMBIAR PERMISOS a';
    $et['ca']['ConfExec'] = 'Confirmar EXECUCIÓ';
    $et['ca']['ConfRem'] = 'Confirmar ESBORRAT';
    $et['ca']['EmptyDir'] = 'Directori buit';
    $et['ca']['IOError'] = 'Error I/O';
    $et['ca']['FileMan'] = 'PHP File Manager';
    $et['ca']['TypePass'] = 'Escrigui la clau';
    $et['ca']['InvPass'] = 'Clau invàlida';
    $et['ca']['ReadDenied'] = 'Accés de lectura denegat';
    $et['ca']['FileNotFound'] = 'Arxiu no trobat';
    $et['ca']['AutoClose'] = 'Tancar al completar';
    $et['ca']['OutDocRoot'] = 'Arxiu abans de DOCUMENT_ROOT';
    $et['ca']['NoCmd'] = 'Error: No s`ha escrit cap comandament';
    $et['ca']['ConfTrySave'] = 'Arxiu sense permisos d`escriptura.\\nIntenteu desar a un altre lloc';
    $et['ca']['ConfSaved'] = 'Configuració Desada';
    $et['ca']['PassSaved'] = 'Clau desada';
    $et['ca']['FileDirExists'] = 'Arxiu o directori ja existent';
    $et['ca']['NoPhpinfo'] = 'Funció phpinfo() no habilitada';
    $et['ca']['NoReturn'] = 'sense retorn';
    $et['ca']['FileSent'] = 'Arxiu enviat';
    $et['ca']['SpaceLimReached'] = 'Límit d`espaci al disc assolit';
    $et['ca']['InvExt'] = 'Extensió no vàlida';
    $et['ca']['FileNoOverw'] = 'L`arxiu no ha pogut ser sobreescrit';
    $et['ca']['FileOverw'] = 'Arxiu sobreescrit';
    $et['ca']['FileIgnored'] = 'Arxiu ignorat';
    $et['ca']['ChkVer'] = 'Revisar les actualitzacions';
    $et['ca']['ChkVerAvailable'] = 'Nova versió, feu clic aquí per descarregar';
    $et['ca']['ChkVerNotAvailable'] = 'La vostra versió és la més recent.';
    $et['ca']['ChkVerError'] = 'Error de connexió.';
    $et['ca']['Website'] = 'Lloc Web';
    $et['ca']['SendingForm'] = 'Enviant arxius, esperi';
    $et['ca']['NoFileSel'] = 'Cap arxiu seleccionat';
    $et['ca']['SelAll'] = 'Tots';
    $et['ca']['SelNone'] = 'Cap';
    $et['ca']['SelInverse'] = 'Invers';
    $et['ca']['Selected_s'] = 'seleccionat';
    $et['ca']['Total'] = 'total';
    $et['ca']['Partition'] = 'Partició';
    $et['ca']['RenderTime'] = 'Generat en';
    $et['ca']['Seconds'] = 'seg';
    $et['ca']['ErrorReport'] = 'Informe d`error';

    // Chinese - by Wen.Xin
    $et['cn']['Version'] = '版本';
    $et['cn']['DocRoot'] = '文档根目录';
    $et['cn']['FMRoot'] = '文件管理根目录';
    $et['cn']['Name'] = '名称';
    $et['cn']['And'] = '&';
    $et['cn']['Enter'] = '确认';
    $et['cn']['Send'] = '确认';
    $et['cn']['Refresh'] = '刷新';
    $et['cn']['SaveConfig'] = '保存设置';
    $et['cn']['SavePass'] = '保存密码';
    $et['cn']['SaveFile'] = '保存文件';
    $et['cn']['Save'] = '保存';
    $et['cn']['Leave'] = '离开';
    $et['cn']['Edit'] = '编辑';
    $et['cn']['View'] = '查看';
    $et['cn']['Config'] = '设置';
    $et['cn']['Ren'] = '重命名';
    $et['cn']['Rem'] = '删除';
    $et['cn']['Compress'] = '压缩';
    $et['cn']['Decompress'] = '解压缩';
    $et['cn']['ResolveIDs'] = 'Resolve IDs';
    $et['cn']['Move'] = '移动';
    $et['cn']['Copy'] = '复制';
    $et['cn']['ServerInfo'] = '服务器信息';
    $et['cn']['CreateDir'] = '新建文件夹';
    $et['cn']['CreateArq'] = '新建文件';
    $et['cn']['ExecCmd'] = '执行命令';
    $et['cn']['Upload'] = '上传';
    $et['cn']['UploadEnd'] = '上传完成';
    $et['cn']['Perm'] = '权限';
    $et['cn']['Perms'] = '权限';
    $et['cn']['Owner'] = '所有者';
    $et['cn']['Group'] = '组';
    $et['cn']['Other'] = '公共';
    $et['cn']['Size'] = '大小';
    $et['cn']['Date'] = '日期';
    $et['cn']['Type'] = 'Type';
    $et['cn']['Free'] = '空闲';
    $et['cn']['Shell'] = '命令行';
    $et['cn']['Read'] = '读取';
    $et['cn']['Write'] = '写入';
    $et['cn']['Exec'] = '执行';
    $et['cn']['Apply'] = '应用';
    $et['cn']['StickyBit'] = '粘滞';
    $et['cn']['Pass'] = '密码';
    $et['cn']['Lang'] = '语言';
    $et['cn']['File'] = '文件';
    $et['cn']['File_s'] = '文件';
    $et['cn']['Dir_s'] = '文件夹';
    $et['cn']['To'] = '为';
    $et['cn']['Destination'] = '目标';
    $et['cn']['Configurations'] = '设置';
    $et['cn']['JSError'] = 'JavaScript 错误';
    $et['cn']['NoSel'] = '未选择项目';
    $et['cn']['SelDir'] = '从左边树目录选择目标文件夹';
    $et['cn']['TypeDir'] = '输入文件夹名称';
    $et['cn']['TypeArq'] = '输入文件名';
    $et['cn']['TypeCmd'] = '输入命令';
    $et['cn']['TypeArqComp'] = '输入文件名.\\n扩展名将定义压缩类型.\\n例如:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['cn']['RemSel'] = '删除选定项目';
    $et['cn']['NoDestDir'] = '未选定目标文件夹';
    $et['cn']['DestEqOrig'] = '目标文件夹与源文件夹相同';
    $et['cn']['InvalidDest'] = '目标文件夹无效';
    $et['cn']['NoNewPerm'] = '未设置新权限';
    $et['cn']['CopyTo'] = '复制到';
    $et['cn']['MoveTo'] = '移动到';
    $et['cn']['AlterPermTo'] = '修改权限为';
    $et['cn']['ConfExec'] = '确认执行';
    $et['cn']['ConfRem'] = '确认删除';
    $et['cn']['EmptyDir'] = '空文件夹';
    $et['cn']['IOError'] = 'I/O 错误';
    $et['cn']['FileMan'] = 'PHP文件管理器' ;
    $et['cn']['TypePass'] = '输入密码';
    $et['cn']['InvPass'] = '无效密码';
    $et['cn']['ReadDenied'] = '拒绝读取访问';
    $et['cn']['FileNotFound'] = '文件未找到';
    $et['cn']['AutoClose'] = '完成时关闭';
    $et['cn']['OutDocRoot'] = '文件超出 DOCUMENT_ROOT';
    $et['cn']['NoCmd'] = '错误: 指令无法识别';
    $et['cn']['ConfTrySave'] = '文件无-写入-权限.\\n尝试保存.';
    $et['cn']['ConfSaved'] = '设置密码';
    $et['cn']['PassSaved'] = '保存密码';
    $et['cn']['FileDirExists'] = '文件或目录已经存在';
    $et['cn']['NoPhpinfo'] = '函数 phpinfo 被禁用';
    $et['cn']['NoReturn'] = '无结果';
    $et['cn']['FileSent'] = '发送文件';
    $et['cn']['SpaceLimReached'] = '磁盘空间限制';
    $et['cn']['InvExt'] = '无效的扩展';
    $et['cn']['FileNoOverw'] = '文件无法被覆盖';
    $et['cn']['FileOverw'] = '覆盖文件';
    $et['cn']['FileIgnored'] = '忽略文件';
    $et['cn']['ChkVer'] = '检查新版本';
    $et['cn']['ChkVerAvailable'] = '有新版本, 点击此处开始下载!!';
    $et['cn']['ChkVerNotAvailable'] = '没有新版本可用. :(';
    $et['cn']['ChkVerError'] = '连接错误.';
    $et['cn']['Website'] = '官方网站';
    $et['cn']['SendingForm'] = '发送文件中, 请稍候...';
    $et['cn']['NoFileSel'] = '未选择文件';
    $et['cn']['SelAll'] = '全选';
    $et['cn']['SelNone'] = '取消';
    $et['cn']['SelInverse'] = '反选';
    $et['cn']['Selected_s'] = '选择';
    $et['cn']['Total'] = '总共';
    $et['cn']['Partition'] = '分区';
    $et['cn']['RenderTime'] = '此界面渲染耗时';
    $et['cn']['Seconds'] = '秒';
    $et['cn']['ErrorReport'] = '错误报告级别';
    $et['cn']['Close'] = '关闭';
    $et['cn']['SetPass'] = '设置密码';
    $et['cn']['ChangePass'] = '修改密码';
    $et['cn']['Portscan'] = '端口扫描';

    // Ukrainian - by Андрій Литвин
    $et['ua']['Version']='Версія';
    $et['ua']['DocRoot']='Коренева тека';
    $et['ua']['FMRoot']='Коренева тека файлового менеджера';
    $et['ua']['Name']='Им\'я';
    $et['ua']['And']='і';
    $et['ua']['Enter']='Увійти';
    $et['ua']['Send']='Відправити';
    $et['ua']['Refresh']='Оновити';
    $et['ua']['SaveConfig']='Зберегти налаштування';
    $et['ua']['SavePass']='Зберегти пароль';
    $et['ua']['SaveFile']='Зберегти файл';
    $et['ua']['Save']='Зберегти';
    $et['ua']['Leave']='Вихід';
    $et['ua']['Edit']='Змінити';
    $et['ua']['View']='Перегляд';
    $et['ua']['Config']='Налаштування';
    $et['ua']['Ren']='Перейменувати';
    $et['ua']['Rem']='Видалити';
    $et['ua']['Compress']='Стиснути';
    $et['ua']['Decompress']='Видобути з архіву';
    $et['ua']['ResolveIDs']='Визначити ID';
    $et['ua']['Move']='Перемістити';
    $et['ua']['Copy']='Копіювати';
    $et['ua']['ServerInfo']='Инфо о сервере';
    $et['ua']['CreateDir']='Створити теку';
    $et['ua']['CreateArq']='Створити файл';
    $et['ua']['ExecCmd']='Виконати';
    $et['ua']['Upload']='Завантажити';
    $et['ua']['UploadEnd']='Завантажено';
    $et['ua']['Perm']='Права';
    $et['ua']['Perms']='Дозволи';
    $et['ua']['Owner']='Власник';
    $et['ua']['Group']='Група';
    $et['ua']['Other']='Інші';
    $et['ua']['Size']='Розмір';
    $et['ua']['Date']='Дата';
    $et['ua']['Type']='Тип';
    $et['ua']['Free']='Вільно простору';
    $et['ua']['Shell']='Командний рядок';
    $et['ua']['Read']='Читати';
    $et['ua']['Write']='Писати';
    $et['ua']['Exec']='Виконати';
    $et['ua']['Apply']='Застосувати';
    $et['ua']['StickyBit']='StickyBit';
    $et['ua']['Pass']='Пароль';
    $et['ua']['Lang']='Мова';
    $et['ua']['File']='Файл';
    $et['ua']['File_s']='Файл(и)';
    $et['ua']['Dir_s']='Тека(и)';
    $et['ua']['To']='в';
    $et['ua']['Destination']='Кінцева тека';
    $et['ua']['Configurations']='Конфігурація';
    $et['ua']['JSError']='Помилка JavaScript';
    $et['ua']['NoSel']='Не обрано жодного елементу';
    $et['ua']['SelDir']='Выберіть теку призначення у дереві ліворуч';
    $et['ua']['TypeDir']='Введіть им\'я теки';
    $et['ua']['TypeArq']='Введіть им\'я файла';
    $et['ua']['TypeCmd']='Введіть команду';
    $et['ua']['TypeArqComp']='Введіть им\'я і розширення файлу.\\nРозширення визаче тип стиснення.\\n Наприклад: \\n name.zip \\n name.tar \\n name.bzip \\n name.gzip ';
    $et['ua']['RemSel']='Видалити обрані елементи';
    $et['ua']['NoDestDir']='Тека призначення не обана';
    $et['ua']['DestEqOrig']='Оберіть іншу теку';
    $et['ua']['InvalidDest']='Помилковий напрямок';
    $et['ua']['NoNewPerm']='Нові дозволи на файл не встановлені';
    $et['ua']['CopyTo']='Копіювати у';
    $et['ua']['MoveTo']='Перемістити у';
    $et['ua']['AlterPermTo']='Змінити дозволи на';
    $et['ua']['ConfExec']='Підтвердити ВИКОНАННЯ';
    $et['ua']['ConfRem']='Підтвердити ВИДАЛЕННЯ';
    $et['ua']['EmptyDir']='Порожня тека';
    $et['ua']['IOError']='Помилка I/O';
    $et['ua']['FileMan']='Файловий менеджер';
    $et['ua']['TypePass']='Введіть пароль';
    $et['ua']['InvPass']='Пароль хибний';
    $et['ua']['ReadDenied']='Доступ заборонено';
    $et['ua']['FileNotFound']='Файл не знайдено';
    $et['ua']['AutoClose']='Закрити після закінчення';
    $et['ua']['OutDocRoot']='Файли за межами DOCUMENT_ROOT';
    $et['ua']['NoCmd']='Помилка: Команда не підтримується';
    $et['ua']['ConfTrySave']='Файл без права на запис.\\nСпробувати зберегти';
    $et['ua']['ConfSaved']='Конфігурація збережена';
    $et['ua']['PassSaved']='Пароль збережено';
    $et['ua']['FileDirExists']='Файл або тека уже існує';
    $et['ua']['NoPhpinfo']='Функція PHPInfo вимкнена';
    $et['ua']['NoReturn']='Без відповіді';
    $et['ua']['FileSent']='Файл надіслано';
    $et['ua']['SpaceLimReached']='Пам\'ять повністью заповнена';
    $et['ua']['InvExt']='Розширення хибне';
    $et['ua']['FileNoOverw']='Файл не може бути перезаписаний';
    $et['ua']['FileOverw']='Файл перезаписаний';
    $et['ua']['FileIgnored']='Файл ігноровано';
    $et['ua']['ChkVer']='Пошук обновленнь';
    $et['ua']['ChkVerAvailable']=' Доступна нова версія; натисніть тут, щоб почати оновлення!';
    $et['ua']['ChkVerNotAvailable']='Не знайдено новох версії.';
    $et['ua']['ChkVerError']='Помилка підключення.';
    $et['ua']['Website']='Сайт';
    $et['ua']['SendingForm']='Надсилаю фалйи; будьласка, чекайте';
    $et['ua']['NoFileSel']='Оберіть файли';
    $et['ua']['SelAll']='Обрати все';
    $et['ua']['SelNone']='Відмінити';
    $et['ua']['SelInverse']='Зворотній відбір';
    $et['ua']['Selected_s']='Обрано(і)';
    $et['ua']['Total']='Всьго';
    $et['ua']['Partition']='Розділ';
    $et['ua']['RenderTime']='Виконано за';
    $et['ua']['Seconds']='секунд';
    $et['ua']['ErrorReport']='Звіт про помилки';

    // Persian/Dari - by Opensecure
    $et['fa']['Version'] = 'نسخه';
    $et['fa']['DocRoot'] = 'ریشه سند';
    $et['fa']['FMRoot'] = 'ریشه مدیریت فایل';
    $et['fa']['DateFormat'] = 'فرمت تاریخ';
    $et['fa']['GetSize'] = 'Get size';
    $et['fa']['Error'] = 'Error';
    $et['fa']['Name'] = 'نام';
    $et['fa']['And'] = 'و';
    $et['fa']['Enter'] = 'وارد شدن';
    $et['fa']['Send'] = 'ارسال';
    $et['fa']['Refresh'] = 'تازه سازی';
    $et['fa']['SaveConfig'] = 'ذخیره تنظیمات';
    //$et['fa']['SavePass'] = 'ذخیره رمز';
    //$et['fa']['TypePass'] = 'رمز خود را وارد نمایید';
    $et['fa']['SaveFile'] = 'ذخیره فایل';
    $et['fa']['Save'] = 'ذخیره';
    $et['fa']['Leave'] = 'ترک کردن';
    $et['fa']['Edit'] = 'ویرایش';
    $et['fa']['View'] = 'نمایش';
    $et['fa']['Config'] = 'تنظیم';
    $et['fa']['Ren'] = 'تغییر نام';
    $et['fa']['Rem'] = 'حذف';
    $et['fa']['Compress'] = 'فشرده سازی';
    $et['fa']['Decompress'] = 'باز کردن فایل فشرده';
    $et['fa']['ResolveIDs'] = 'رفع IDs';
    $et['fa']['Move'] = 'انتقال';
    $et['fa']['Copy'] = 'کپی';
    $et['fa']['ServerInfo'] = 'معلومات سرور';
    $et['fa']['CreateDir'] = 'ساخت دایرکتوری';
    $et['fa']['CreateArq'] = 'ساخت فایل';
    $et['fa']['Symlink'] = 'Symlink';
    $et['fa']['HardLink'] = 'Hardlink';
    $et['fa']['ExecCmd'] = 'احرای دستور';
    $et['fa']['Upload'] = 'بارگذاری';
    $et['fa']['UploadEnd'] = 'اتمام بارگذاری';
    $et['fa']['Perm'] = 'دسترسی';
    $et['fa']['Perms'] = 'دسترسی ها';
    $et['fa']['Owner'] = 'مالک';
    $et['fa']['Group'] = 'گروه';
    $et['fa']['Other'] = 'متفقره';
    $et['fa']['Size'] = 'حجم';
    $et['fa']['Date'] = 'تاریخ';
    $et['fa']['Type'] = 'نوعیت';
    $et['fa']['Free'] = 'خالی';
    $et['fa']['Shell'] = 'فرامین';
    $et['fa']['Read'] = 'خواندن';
    $et['fa']['Write'] = 'نوشتن';
    $et['fa']['Exec'] = 'اجرا';
    $et['fa']['Apply'] = 'استفاده';
    $et['fa']['StickyBit'] = 'Sticky Bit';
    $et['fa']['Pass'] = 'رمز';
    $et['fa']['Lang'] = 'زبان';
    $et['fa']['File'] = 'فایل';
    $et['fa']['File_s'] = 'فایل(ها)';
    $et['fa']['Dir_s'] = 'فولدر(ها)';
    $et['fa']['To'] = 'به';
    $et['fa']['Destination'] = 'مقصد';
    $et['fa']['Configurations'] = 'تنظیمات';
    $et['fa']['JSError'] = 'خطای JS';
    $et['fa']['NoSel'] = 'هیچ آیتمی انتخاب نشده';
    $et['fa']['SelDir'] = 'فولدر مقصد را از لیست سمت چپ انتخاب کنید';
    $et['fa']['TypeDir'] = 'نام فولدر را وارد کنید';
    $et['fa']['TypeArq'] = 'نام فایل را وارد کنید';
    $et['fa']['TypeCmd'] = 'فرمان را وارد کنید';
    $et['fa']['TypeArqComp'] = 'نام فایل را وارد کنید.\\nپسوند از نوع فشرده تعیین خواهد شد.\\nمثال:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['fa']['RemSel'] = 'آیتم ها انتخاب شده پاک خواهند شد';
    $et['fa']['NoDestDir'] = 'فولدر مقصد انتخاب نشده';
    $et['fa']['DestEqOrig'] = 'فولدر مبدا و مقصد یکسان است';
    $et['fa']['InvalidDest'] = 'فولدر مقصد اشتباه است';
    $et['fa']['NoNewPerm'] = 'دسترسی جدید اعمال نشده';
    $et['fa']['CopyTo'] = 'کپی به';
    $et['fa']['MoveTo'] = 'انتقال به';
    $et['fa']['AlterPermTo'] = 'نغییر دسترسی به';
    $et['fa']['ConfExec'] = 'تایید برای اجرا';
    $et['fa']['ConfRem'] = 'تایید برای پاک کردن';
    $et['fa']['EmptyDir'] = 'فولدر خالی';
    $et['fa']['IOError'] = 'خطای I/O';
    $et['fa']['FileMan'] = 'مدیریت فایل پی اچ پی';
    $et['fa']['InvPass'] = 'رمز اشتباه';
    $et['fa']['ReadDenied'] = 'عدم دسترسی خواند';
    $et['fa']['FileNotFound'] = 'فایل پیدا نشد';
    $et['fa']['AutoClose'] = 'بستن در صورت تکمیل شدن';
    $et['fa']['OutDocRoot'] = 'فایل خارج از DOCUMENT_ROOT';
    $et['fa']['NoCmd'] = 'خطا: فرمان شناخته نشد';
    $et['fa']['ConfTrySave'] = 'فایل بدون دسترسی نوشتن.\\nتلاش برای ذخیره';
    $et['fa']['ConfSaved'] = 'تنظیمات ذخیره شدند';
    $et['fa']['PassSaved'] = 'رمز ذخیره شد';
    $et['fa']['FileDirExists'] = 'فایل یا فولدر موجود است';
    $et['fa']['NoPhpinfo'] = 'تابع phpinfo غیر فعال است';
    $et['fa']['NoReturn'] = 'بدون بازگشت';
    $et['fa']['FileSent'] = 'فایل ارسال شد';
    $et['fa']['SpaceLimReached'] = 'به محدودیت فضا رسید';
    $et['fa']['InvExt'] = 'پسمند اشتباه';
    $et['fa']['FileNoOverw'] = 'فایل امکان دوباره نویسی ندارد';
    $et['fa']['FileOverw'] = 'فایل دوباره نویسی شد';
    $et['fa']['FileIgnored'] = 'فایل رد شد';
    $et['fa']['ChkVer'] = 'بررسی نسخه جدید';
    $et['fa']['ChkVerAvailable'] = 'نسخه جدید, برای دانلود اینجا کلیک کنید!!';
    $et['fa']['ChkVerNotAvailable'] = 'نسخه جدید موجود نمی باشد. :(';
    $et['fa']['ChkVerError'] = 'خطا در اتصال.';
    $et['fa']['Website'] = 'وبسایت';
    $et['fa']['SendingForm'] = 'در حال ارسال فایل ها, لطفا منتظر باشید';
    $et['fa']['NoFileSel'] = 'هیچ فایلی انتخاب نشده';
    $et['fa']['SelAll'] = 'همه';
    $et['fa']['SelNone'] = 'هیچکدام';
    $et['fa']['SelInverse'] = 'معکوس';
    $et['fa']['Selected_s'] = 'انتخاب شده اند';
    $et['fa']['Total'] = 'مجموع';
    $et['fa']['Partition'] = 'پارتیشن';
    $et['fa']['RenderTime'] = 'زمان برای تحویل این صفحه';
    $et['fa']['Seconds'] = 'ثانیه';
    $et['fa']['ErrorReport'] = 'خطرا در گزارش';
    $et['fa']['Close'] = 'بستن';
    $et['fa']['SetPass'] = 'تعیین پسورد';
    $et['fa']['ChangePass'] = 'تغییر پسورد';
    $et['fa']['Portscan'] = 'Portscan';
    $et['fa']['PHPOpenBasedir'] = 'PHP Open Basedir';
    $et['fa']['PHPOpenBasedirFullAccess'] = '(ثابت نشده) دسترسی کامل';
    $et['fa']['About'] = 'درباره';
    $et['fa']['FileSaved'] = 'فایل ذخیره شد';
    $et['fa']['FileSaveError'] = 'خطا در ذخیره فایل';

    // Serbian - by Miroljub Sunajko
    $et['sr']['Version'] = 'Verzija';
    $et['sr']['DocRoot'] = 'Koren dokumenta';
    $et['sr']['FMRoot'] = 'Koren menadžera datoteka';
    $et['sr']['DateFormat'] = 'Foramt datuma';
    $et['sr']['GetSize'] = 'dobivanje veličine';
    $et['sr']['Error'] = 'Greška';
    $et['sr']['Name'] = 'Ime';
    $et['sr']['And'] = 'i';
    $et['sr']['srter'] = 'srter';
    $et['sr']['Ssrd'] = 'Ssrd';
    $et['sr']['Refresh'] = 'Osveži';
    $et['sr']['SaveConfig'] = 'Sačuvaj konfiguraciju';
    //$et['sr']['SavePass'] = 'Save Password';
    //$et['sr']['TypePass'] = 'srter the password';
    $et['sr']['SaveFile'] = 'Sačuvaj datoteku';
    $et['sr']['Save'] = 'Sačuvaj';
    $et['sr']['Leave'] = 'Napusti';
    $et['sr']['Edit'] = 'Urediti';
    $et['sr']['View'] = 'Pogledati';
    $et['sr']['Config'] = 'Konfig';
    $et['sr']['Ren'] = 'Preimenovati';
    $et['sr']['Rsr'] = 'Rsrame';
    $et['sr']['Rem'] = 'Izbriši';
    $et['sr']['Compress'] = 'Komprimiraj';
    $et['sr']['Decompress'] = 'Dekomprimiraj';
    $et['sr']['ResolveIDs'] = 'Rešavanje IDs';
    $et['sr']['Move'] = 'Premesti';
    $et['sr']['Copy'] = 'Kopiraj';
    $et['sr']['ServerInfo'] = 'Podaci o serveru';
    $et['sr']['CreateDir'] = 'Kreiraj direktorijum';
    $et['sr']['CreateArq'] = 'Kreiraj datoteku';
    $et['sr']['Symlink'] = 'Symlink';
    $et['sr']['HardLink'] = 'Hard veza';
    $et['sr']['ExecCmd'] = 'Izvrši naredbu';
    $et['sr']['Upload'] = 'Prenos';
    $et['sr']['Uploadsrd'] = 'Prenos je završen';
    $et['sr']['Perm'] = 'Perm';
    $et['sr']['Perms'] = 'Dozvole';
    $et['sr']['Owner'] = 'Vlasnik';
    $et['sr']['Group'] = 'Grupa';
    $et['sr']['Other'] = 'Ostalo';
    $et['sr']['Size'] = 'Veličina';
    $et['sr']['Date'] = 'Datum';
    $et['sr']['Type'] = 'Vrsta';
    $et['sr']['Free'] = 'besplatno';
    $et['sr']['Shell'] = 'Školjka';
    $et['sr']['Read'] = 'Pročitaj';
    $et['sr']['Write'] = 'Piši';
    $et['sr']['Exec'] = 'Izvrši';
    $et['sr']['Apply'] = 'Primeni';
    $et['sr']['StickyBit'] = 'Lepljiv Bit';
    $et['sr']['Pass'] = 'Lozinka';
    $et['sr']['Lang'] = 'Jezik';
    $et['sr']['File'] = 'Datoteka';
    $et['sr']['File_s'] = 'datoteka(s)';
    $et['sr']['Dir_s'] = 'direktorij(s)';
    $et['sr']['To'] = 'do';
    $et['sr']['Destination'] = 'Odredište';
    $et['sr']['Configurations'] = 'Konfiguracija';
    $et['sr']['JSError'] = 'JavaScript greškar';
    $et['sr']['NoSel'] = 'Nema odabranih stavki';
    $et['sr']['SelDir'] = 'Odaberite odredišni direktorijum na levom stablu';
    $et['sr']['TypeDir'] = 'ime direktorija';
    $et['sr']['TypeArq'] = 'ime datoteke';
    $et['sr']['TypeCmd'] = 'naredba';
    $et['sr']['TypeArqComp'] = 'srter the file name.\\nThe extsrsion će definisati tip kompresije.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['sr']['RemSel'] = 'IZBRIŠI izabrane stavke';
    $et['sr']['NoDestDir'] = 'Nema izabranog odredišnog direktorijuma';
    $et['sr']['DestEqOrig'] = 'Izvorni i odredišni direktorijumi su jednaki';
    $et['sr']['InvalidDest'] = 'Direktorijum odredišta nije vašeći';
    $et['sr']['NoNewPerm'] = 'Nova dozvola nije postavljena';
    $et['sr']['CopyTo'] = 'Kopiraj u';
    $et['sr']['MoveTo'] = 'Premesti u';
    $et['sr']['AlterPermTo'] = 'PROMENI DOZVOLE u';
    $et['sr']['ConfExec'] = 'Potvrdi IZVRŠENJE';
    $et['sr']['ConfRem'] = 'Potvrdi BRISANJE';
    $et['sr']['EmptyDir'] = 'Prazan direktorijum';
    $et['sr']['IOError'] = 'I/O greška';
    $et['sr']['FileMan'] = 'Menadžer datoteka';
    $et['sr']['InvPass'] = 'Nevažeća lozinka';
    $et['sr']['ReadDsried'] = 'Pristup čitanju nije moguć';
    $et['sr']['FilsrotFound'] = 'Datoteka nije pronadjena';
    $et['sr']['AutoClose'] = 'Zatvori završeno';
    $et['sr']['OutDocRoot'] = 'Datoteka izvan DOCUMsrT_ROOT';
    $et['sr']['NoCmd'] = 'Greška: Naredba nije  informed';
    $et['sr']['ConfTrySave'] = 'Datoteka bez dozvole za pisanje.\\pokušajte ipak da je sačuvate';
    $et['sr']['ConfSaved'] = 'Konfiguracije su sačuvane';
    $et['sr']['PassSaved'] = 'Lozinka je sačuvana';
    $et['sr']['FileDirExists'] = 'Datoteka ili direktorijum već postoje';
    $et['sr']['NoPhpinfo'] = 'Funkcija phpinfo je onemogućena';
    $et['sr']['NoReturn'] = 'nema povratka';
    $et['sr']['FileSsrt'] = 'Datoteka ssrt';
    $et['sr']['SpaceLimReached'] = 'Dostignuta ograničenja prostora';
    $et['sr']['InvExt'] = 'Nevažeća extsrsion';
    $et['sr']['FilsroOverw'] = 'Datoteka se nemože prepisati';
    $et['sr']['FileOverw'] = 'Datoteka prepisana';
    $et['sr']['FileIgnored'] = 'Datoteka je ignorisana';
    $et['sr']['ChkVer'] = 'Proveri novu verziju';
    $et['sr']['ChkVerAvailable'] = 'Nova verzija, kliknite ovde da započnete preuzimanje!!';
    $et['sr']['ChkVerNotAvailable'] = 'Nova verzija nije dostupna. :(';
    $et['sr']['ChkVerError'] = 'Greška u povezivanju.';
    $et['sr']['Website'] = 'Veb lokacija';
    $et['sr']['SsrdingForm'] = 'Ssrding datoteke , molim pričekajte';
    $et['sr']['NoFileSel'] = 'Nije odabrana datoteka';
    $et['sr']['SelAll'] = 'Sve';
    $et['sr']['SelNone'] = 'Nema';
    $et['sr']['SelInverse'] = 'Inverzno';
    $et['sr']['Selected_s'] = 'izabrano';
    $et['sr']['Total'] = 'ukupno';
    $et['sr']['Partition'] = 'Particija';
    $et['sr']['RsrderTime'] = 'Vreme da se ova stranica izvrši';
    $et['sr']['Seconds'] = 'sec';
    $et['sr']['ErrorReport'] = 'Izveštaj o greškama';
    $et['sr']['Close'] = 'Zatvori';
    $et['sr']['SetPass'] = 'Postavi Lozinku';
    $et['sr']['ChangePass'] = 'Promeni Lozinku';
    $et['sr']['Portscan'] = 'Portscan';
    $et['sr']['PHPOpsrBasedir'] = 'PHP Opsr Basedir';
    $et['sr']['PHPOpsrBasedirFullAccess'] = '(ukida) Puni pristup';
    $et['sr']['About'] = 'O meni';
    $et['sr']['FileSaved'] = 'Datoteka je sačuvana';
    $et['sr']['FileSaveError'] = 'Greška prilikom čuvanja datoteke';

    // Japanese - by h3zjp
    $et['ja']['Version'] = 'バージョン';
    $et['ja']['DocRoot'] = 'ドキュメントルート';
    $et['ja']['FMRoot'] = 'File Manager Root';
    $et['ja']['DateFormat'] = '日付フォーマット';
    $et['ja']['GetSize'] = 'サイズの取得';
    $et['ja']['Error'] = 'エラー';
    $et['ja']['Name'] = '名前';
    $et['ja']['And'] = ', ';
    $et['ja']['Enter'] = '決定';
    $et['ja']['Send'] = '送信';
    $et['ja']['Refresh'] = '更新';
    $et['ja']['SaveConfig'] = '設定を保存';
    //$et['ja']['SavePass'] = 'パスワードを保存';
    //$et['ja']['TypePass'] = 'パスワードを入力';
    $et['ja']['SaveFile'] = 'ファイルを保存';
    $et['ja']['Save'] = '保存';
    $et['ja']['Leave'] = '閉じる';
    $et['ja']['Edit'] = '編集';
    $et['ja']['View'] = '表示';
    $et['ja']['Config'] = '設定';
    $et['ja']['Ren'] = '名前変更';
    $et['ja']['Rem'] = '削除';
    $et['ja']['Compress'] = '圧縮';
    $et['ja']['Decompress'] = '解凍';
    $et['ja']['ResolveIDs'] = 'ID→名前表示';
    $et['ja']['Move'] = '移動';
    $et['ja']['Copy'] = 'コピー';
    $et['ja']['ServerInfo'] = 'サーバー情報';
    $et['ja']['CreateDir'] = 'ディレクトリを作成';
    $et['ja']['CreateArq'] = 'ファイルを作成';
    $et['ja']['Symlink'] = 'シンボリックリンク';
    $et['ja']['HardLink'] = 'ハードリンク';
    $et['ja']['ExecCmd'] = 'コマンドを実行';
    $et['ja']['Upload'] = 'アップロード';
    $et['ja']['UploadEnd'] = 'アップロード完了';
    $et['ja']['Perm'] = 'パーミッション';
    $et['ja']['Perms'] = 'パーミッション';
    $et['ja']['Owner'] = '所有者';
    $et['ja']['Group'] = 'グループ';
    $et['ja']['Other'] = 'その他';
    $et['ja']['Size'] = 'サイズ';
    $et['ja']['Date'] = '日付';
    $et['ja']['Type'] = '種類';
    $et['ja']['Free'] = '空き';
    $et['ja']['Shell'] = 'シェル';
    $et['ja']['Read'] = '読み取り';
    $et['ja']['Write'] = '書き込み';
    $et['ja']['Exec'] = '実行';
    $et['ja']['Apply'] = '決定';
    $et['ja']['StickyBit'] = 'スティッキービット';
    $et['ja']['Pass'] = 'パスワード';
    $et['ja']['Lang'] = '言語選択';
    $et['ja']['File'] = 'ファイル';
    $et['ja']['File_s'] = 'ファイル';
    $et['ja']['Dir_s'] = 'ディレクトリ';
    $et['ja']['To'] = 'から';
    $et['ja']['Destination'] = '宛先';
    $et['ja']['Configurations'] = '設定';
    $et['ja']['JSError'] = 'JavaScript エラー';
    $et['ja']['NoSel'] = '項目が選択されていません';
    $et['ja']['SelDir'] = '宛先ディレクトリを、左のツリーから選択して下さい';
    $et['ja']['TypeDir'] = 'ディレクトリ名を入力して下さい';
    $et['ja']['TypeArq'] = 'ファイル名を入力して下さい';
    $et['ja']['TypeCmd'] = 'コマンドを入力して下さい';
    $et['ja']['TypeArqComp'] = 'ファイル名を入力して下さい。\\n圧縮形式は拡張子で指定されます。\\n例:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['ja']['RemSel'] = '選択した項目を削除しますか';
    $et['ja']['NoDestDir'] = '選択した宛先ディレクトリがありません';
    $et['ja']['DestEqOrig'] = '同じディレクトリが選択されています';
    $et['ja']['InvalidDest'] = '宛先のディレクトリが無効です';
    $et['ja']['NoNewPerm'] = '新しいパーミッションが設定されていません';
    $et['ja']['CopyTo'] = 'コピーしますか';
    $et['ja']['MoveTo'] = '移動しますか';
    $et['ja']['AlterPermTo'] = 'パーミッションを変更しても良いですか';
    $et['ja']['ConfExec'] = '実行しても良いですか';
    $et['ja']['ConfRem'] = '削除しても良いですか';
    $et['ja']['EmptyDir'] = '空のディレクトリ';
    $et['ja']['IOError'] = 'I/O エラー';
    $et['ja']['FileMan'] = 'PHP File Manager';
    $et['ja']['InvPass'] = 'パスワードに誤りがあります';
    $et['ja']['ReadDenied'] = 'アクセスが拒否されました';
    $et['ja']['FileNotFound'] = 'ファイルが見つかりません';
    $et['ja']['AutoClose'] = '完了時に閉じる';
    $et['ja']['OutDocRoot'] = 'ファイルが DOCUMENT_ROOT を超えています';
    $et['ja']['NoCmd'] = 'Error: コマンドが通知されません';
    $et['ja']['ConfTrySave'] = 'ファイルに書き込み権限がありません。\\再度保存してみて下さい';
    $et['ja']['ConfSaved'] = '設定を保存しました';
    $et['ja']['PassSaved'] = 'パスワードを保存しました';
    $et['ja']['FileDirExists'] = 'ファイルまたはディレクトリは既に存在します';
    $et['ja']['NoPhpinfo'] = '関数「phpinfo」は無効です';
    $et['ja']['NoReturn'] = '返り値はありません';
    $et['ja']['FileSent'] = '送信済';
    $et['ja']['SpaceLimReached'] = '容量制限に達しました';
    $et['ja']['InvExt'] = '無効な拡張子です';
    $et['ja']['FileNoOverw'] = 'ファイルを上書きできませんでした';
    $et['ja']['FileOverw'] = 'ファイルが上書きされました';
    $et['ja']['FileIgnored'] = 'ファイルは無視されました';
    $et['ja']['ChkVer'] = '新しいバージョンがあるか確認する';
    $et['ja']['ChkVerAvailable'] = '新しいバージョンがあります! ダウンロードを開始するには、ここをクリックして下さい!!';
    $et['ja']['ChkVerNotAvailable'] = '新しいバージョンはありませんでした。:(';
    $et['ja']['ChkVerError'] = '接続エラー';
    $et['ja']['Website'] = 'Webサイト';
    $et['ja']['SendingForm'] = 'ファイル送信中。お待ち下さい';
    $et['ja']['NoFileSel'] = 'ファイルが選択されていません';
    $et['ja']['SelAll'] = '全選択';
    $et['ja']['SelNone'] = '全解除';
    $et['ja']['SelInverse'] = '選択を反転';
    $et['ja']['Selected_s'] = '選択';
    $et['ja']['Total'] = '計';
    $et['ja']['Partition'] = 'ディスク容量';
    $et['ja']['RenderTime'] = 'ページ描画時間';
    $et['ja']['Seconds'] = '秒';
    $et['ja']['ErrorReport'] = 'エラー出力';
    $et['ja']['Close'] = '閉じる';
    $et['ja']['SetPass'] = 'パスワードを設定';
    $et['ja']['ChangePass'] = 'パスワードを変更';
    $et['ja']['Portscan'] = 'ポートスキャン';
    $et['ja']['PHPOpenBasedir'] = 'PHP open_basedir';
    $et['ja']['PHPOpenBasedirFullAccess'] = '(未設定) フルアクセス';
    $et['ja']['About'] = 'About';
    $et['ja']['FileSaved'] = 'ファイルを保存しました';
    $et['ja']['FileSaveError'] = 'ファイルの保存時にエラーが発生しました';
   
   // Bahasa Indonesia - by dirmanhana
    $et['id']['Version'] = 'Versi';
    $et['id']['DocRoot'] = 'Document Root ';
    $et['id']['FMRoot'] = 'File Manajer Root ';
    $et['id']['DateFormat'] = 'Format tanggal';
    $et['id']['GetSize'] = 'Lihat ukuran ';
    $et['id']['Error'] = 'Kesalahan';
    $et['id']['Name'] = 'Nama';
    $et['id']['And'] = 'dan';
    $et['id']['Enter'] = 'Memasukkan';
    $et['id']['Send'] = 'Kirim';
    $et['id']['Refresh'] = 'Rifres';
    $et['id']['SaveConfig'] = 'simpan Konfigurasi ';
    //$et['id']['SavePass'] = 'Simpan kata sandi';
    //$et['id']['TypePass'] = 'masukkan kata sandi';
    $et['id']['SaveFile'] = 'Simpan file';
    $et['id']['Save'] = 'Simpan';
    $et['id']['Leave'] = 'Tutup';
    $et['id']['Edit'] = ' Ubah ';
    $et['id']['View'] = 'lihat';
    $et['id']['Config'] = 'Konfigurasi ';
    $et['id']['Ren'] = ' ubah nama ';
    $et['id']['Rem'] = 'hapus';
    $et['id']['Compress'] = 'Kompres';
    $et['id']['Decompress'] = 'Ekstrak ';
    $et['id']['ResolveIDs'] = 'Selesaikan ID ';
    $et['id']['Move'] = 'Pindah';
    $et['id']['Copy'] = 'Salin';
    $et['id']['ServerInfo'] = ' Server Info ';
    $et['id']['CreateDir'] = 'Buat Direktori ';
    $et['id']['CreateArq'] = 'Buat Berkas ';
    $et['id']['Symlink'] = ' Symlink ';
    $et['id']['HardLink'] = ' Hardlink ';
    $et['id']['ExecCmd'] = 'Jalankan perintah ';
    $et['id']['Upload'] = ' Unggah ';
    $et['id']['UploadEnd'] = 'Unggah Selesai ';
    $et['id']['Perm'] = ' Perm ';
    $et['id']['Perms'] = ' Izin ';
    $et['id']['Owner'] = 'Pemilik';
    $et['id']['Group'] = 'Kelompok';
    $et['id']['Other'] = 'Lain';
    $et['id']['Size'] = 'Ukuran';
    $et['id']['Date'] = 'Tanggal';
    $et['id']['Type'] = 'Tipe';
    $et['id']['Free'] = 'Gratis';
    $et['id']['Shell'] = 'Shell';
    $et['id']['Read'] = 'Baca';
    $et['id']['Write'] = 'Menulis';
    $et['id']['Exec'] = 'Menjalankan';
    $et['id']['Apply'] = 'Menerapkan';
    $et['id']['StickyBit'] = 'Bit menempel ';
    $et['id']['Pass'] = 'Kata sandi';
    $et['id']['Lang'] = 'Bahasa';
    $et['id']['File'] = 'Berkas';
    $et['id']['File_s'] = 'file (s) ';
    $et['id']['Dir_s'] = 'directory (s) ';
    $et['id']['To'] = 'untuk';
    $et['id']['Destination'] = 'Tujuan';
    $et['id']['Configurations'] = ' Konfigurasi ';
    $et['id']['JSError'] = 'Kesalahan JavaScript';
    $et['id']['NoSel'] = 'tidak ada item yang dipilih';
    $et['id']['SelDir'] = 'Pilih direktori tujuan di pohon sebelah kiri ';
    $et['id']['TypeDir'] = 'masukkan nama direktori ';
    $et['id']['TypeArq'] = 'masukkan nama file ';
    $et['id']['TypeCmd'] = 'masukkan perintah ';
    $et['id']['TypeArqComp'] = 'Masukkan nama file. \\ nEkstensi akan menentukan jenis kompresi. \\ nEx: \\ nnome.zip \\ nnome.tar \\ nnome.bzip \\ nnome.gzip';
    $et['id']['RemSel'] = 'hapus item terpilih ';
    $et['id']['NoDestDir'] = 'Tidak ada direktori tujuan yang dipilih';
    $et['id']['DestEqOrig'] = 'Direktori asal dan tujuan sama';
    $et['id']['InvalidDest'] = 'Destinasi direktori tidak valid ';
    $et['id']['NoNewPerm'] = 'izin Baru belum diatur ';
    $et['id']['CopyTo'] = 'Salin ke';
    $et['id']['MoveTo'] = 'Pindah ke';
    $et['id']['AlterPermTo'] = 'Ubah Perizinan untuk ';
    $et['id']['ConfExec'] = 'Konfirmasi Jalankan ';
    $et['id']['ConfRem'] = 'Konfirmasi hapus ';
    $et['id']['EmptyDir'] = 'Direktori kosong';
    $et['id']['IOError'] = ' I/O Error ';
    $et['id']['FileMan'] = 'File Manager PHP ';
    $et['id']['InvPass'] = 'Kata sandi salah';
    $et['id']['ReadDenied'] = 'Read Akses Ditolak ';
    $et['id']['FileNotFound'] = 'Berkas tidak ditemukan';
    $et['id']['AutoClose'] = 'Tutup selesai ';
    $et['id']['OutDocRoot'] = 'File luar DOCUMENT_ROOT ';
    $et['id']['NoCmd'] = 'Kesalahan: Perintah tidak diinformasikan';
    $et['id']['ConfTrySave'] = 'File tanpa menulis permisson \\ Coba untuk menyimpan pula ';
    $et['id']['ConfSaved'] = 'Konfigurasi disimpan ';
    $et['id']['PassSaved'] = 'Password disimpan ';
    $et['id']['FileDirExists'] = 'File atau direktori sudah ada ';
    $et['id']['NoPhpinfo'] = 'Fungsi phpinfo ';
    $et['id']['NoReturn'] = 'Tidak kembali ';
    $et['id']['FileSent'] = 'Mengirim File';
    $et['id']['SpaceLimReached'] = 'Batas rung disk mencapai ';
    $et['id']['InvExt'] = 'Ekstensi tidak valid ';
    $et['id']['FileNoOverw'] = 'File tidak bisa ditimpa ';
    $et['id']['FileOverw'] = 'File ditimpa ';
    $et['id']['FileIgnored'] = 'File diabaikan ';
    $et['id']['ChkVer'] = 'Periksa untuk versi baru ';
    $et['id']['ChkVerAvailable'] = 'Versi New, klik di sini untuk mulai men-download !! ';
    $et['id']['ChkVerNotAvailable'] = 'Versi baru No tersedia. : (';
    $et['id']['ChkVerError'] = 'Koneksi error.';
    $et['id']['Website'] = 'Situs web';
    $et['id']['SendingForm'] = 'Mengirim file, silakan tunggu ';
    $et['id']['NoFileSel'] = 'Tidak ada file yang dipilih';
    $et['id']['SelAll'] = 'Semua';
    $et['id']['SelNone'] = ' Tidak ';
    $et['id']['SelInverse'] = 'Balikkan';
    $et['id']['Selected_s'] = 'terpilih';
    $et['id']['Total'] = 'total';
    $et['id']['Partition'] = ' Partisi ';
    $et['id']['RenderTime'] = 'Waktu untuk membuat halaman ini ';
    $et['id']['Seconds'] = 'detik';
    $et['id']['ErrorReport'] = 'Laporan error ';
    $et['id']['Close'] = 'Tutup';
    $et['id']['SetPass'] = 'Set Sandi ';
    $et['id']['ChangePass'] = 'Ganti kata sandi';
    $et['id']['Portscan'] = ' Portscan ';
    $et['id']['PHPOpenBasedir'] = 'PHP Terbuka Basedir ';
    $et['id']['PHPOpenBasedirFullAccess'] = ' (Unset) Akses Penuh ';
    $et['id']['About'] = 'Tentang';
    $et['id']['FileSaved'] = 'File disimpan ';
    $et['id']['FileSaveError'] = 'gagal menyimpan file ';


    if (!strlen($lang)) $lang = $sys_lang;
    if (isset($et[$lang][$tag])) return html_encode($et[$lang][$tag]);
    else if (isset($et['en'][$tag])) return html_encode($et['en'][$tag]);
    else return "$tag"; // So we can know what is missing
}
// +--------------------------------------------------
// | BASE64 FILES
// | So that PHP File Manager can remain a single file script,
// | and still work normally on offline enviroments
// +--------------------------------------------------
if(!function_exists('apache_request_headers')){
    function apache_request_headers(){
        $arh = array();
        $rx_http = '/\AHTTP_/';
        foreach($SERVER as $key => $val) {
            if( preg_match($rx_http, $key) ) {
                $arh_key = preg_replace($rx_http, '', $key);
                $rx_matches = array();
                // do some nasty string manipulations to restore the original letter case
                // this should work in most cases
                $rx_matches = explode('', $arh_key);
                if( count($rx_matches) > 0 and strlen($arh_key) > 2 ) {
                    foreach($rx_matches as $ak_key => $ak_val) {
                        $rx_matches[$ak_key] = ucfirst($ak_val);
                    }
                    $arh_key = implode('-', $rx_matches);
                }
                $arh[$arh_key] = $val;
            }
        }
        return $arh;
    }
}
function get_base64_file(){
    global $filename,$fm_path_info;
    // +--------------------------------------------------
    // | TOTAL: 26 files = 1.94 Mb = 568.79 Kb compressed
    // +--------------------------------------------------
    $base64_files = array();
    $base64_files['32px.png'] = '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';
    $base64_files['ace.js'] = 'eJzc/Wl720jSIIp+nn8hYjwqoAhSpBYvpCA+KpXc5WkvNbarl0uxfSESlNCmADYASlaL/O83InJPJCi5qvucc8/bb1lE7hkZGRkZGYs/X2XTKs0zP3gQP3dyPwsebuNiJ42SYba76yfjbLJe05/oYROEkA4/g2E691tpd5bM0yxZr+XP7jKefo2vkllQdfMivUqzeBGJzFD8iKqwViFq9XijRfKvVVqwVvlv1WyhN8tzQ/krKsJ6HWh5g1M6PTv/8v703fmnX+FX5HlhEmkgKJJqVWQ71XVabvxg2Ep2d6v7ZZLPd+7SbJbftSJvlbExzzwETMTSGSiMtmVNPpJ/lkblgHU1xDFVaghJmIVF8ACt8doJ1CqrIs2uvOBBgXOkfnbj5XJx7+OYw7i4Wt0kWVUGA3+aZ2W+SLpJUeSF782KfLmEZnZu8tlqkexcJtN4VSY7bEA7d3GZ/VDtxDuss64XhKKBqoiniR8EQzbkjeyku0iyq+o6ivYBFEWUBWHVZa2X4wQRpgLw3y/yeIbfsCx6dpStFotgM5RpgFmhqgBfBJtMh00VZjpsqkiDDcPXEkvRaqStSEKbA3sHcBlWOUw3yQJmDoU+XP4zmUKnRV7l2Gi3yj+x+U/jxcKvggi6GOdUaue0KOL7Ce8qj8aT4RwAix+rqBfGUcXhMVwdx8N2e8UKztmYxiu2X+aRGtburkJkgQ95d7kqr/15sNHGzJcYIRbmAeyJ3mYTFgZkBAAyH3EaYcDrpw0djorHMCjdwEY3+0DYdwHjk28f5r7X8oJWFHX6rO8MAFAuF2lFGbJ7ROlxbxK0IbXNvvqTYEMtTa/j4rTyewBmr8sBW0SJaGbPC7rlIgXk64XQS/efeZpR6rCKijb8aFfDu+t0keiD6vJB7e7ChuNgKaMKqlRAFJYLxOW9i72L7sXeXkhdyNTxPy72Jm3KY7lesBHLUG3CUgcGbNIiSunHkHchkbuYEDkogwdMlVuAJXPcLWHKojmJUrADVtFDOhsU4apIB7iS35Z5UZWDPBSEbACLD8hmrovAFb+gtd+EiHVxmIerYJhH8/V61eUthfowozycJYukSnaMYW7MyUT5el0KOJSbYe4bhC7YBLCnGIb5HgByb5Fe7hXJFfTohWOP0z8v9PgQ4Bdr3JuE9ub2kCThnp5W3lA7kBIxRz/pXi3yS8Bf78oDCAVtSEmvsrxIzuIyGXmpTL1ZLap0AaMaeTcyMflWJYAqs5H3TaaVVTr9ej/y7illI7tdaSSHNr9GKDi+CcoiE3ysIAkDEMX1ujcsjhNBG4p2O4DmEoRrBPjJ6xd8v3T6G1bvIfmWTAcfk6vzb0utW0wNq6Ss6lmYGt7E1fR6wGmYyqPkkCN6PZtnhLTv6tmUjMSgoP4Zbdzzg9GI9gjs50gjMvo+YYidRHv/2LsSFKGgkbJGEqwftgA6cVm9QQjisQvwKXd3U0ESnUDQNgDrpBKjcxIzOFZjbfcl6uSAczp4aKXwhy/RCZCOFSwjjOwEyYgfR2wE1Ga3zFcFgKoQQGMTySkzCAEpsWJg5yeckHFCFYRxqHNeHF2SqD9Mju3ztbM/TABrZDIengZR9ytMUqfdJiAY0nC/fGM7Eeanf8KolgDc5H18k5SB6H8O/c+P5Tk2h16BqjfWG887/UmY0QCAM6zGczjjWiXvim3T3d1WBeSfN8mz5GqfcHjY6Z2OTneBk3BiezMOsNMbUSCRJ1H1HxlX2GpVG4BwjeAl5VGnvE5vvpvkSXJTACYo4nOHk6qKe0HbOavCuv0VmLmkqO5xA5WAE5C08EJkzdVnClRpM8WND3zMw0a1/IuipoBx7SQEHjNKRknUG+Cv3u4u/unv8R8d+gWsrp+c9NZrOIh/fBdX1935Ige0oZ/xJfA4AWB9onr5SS2K2HRD2WlE3N96XSF/pZhinnCZA9sZZ+IzW91cJoX44ttWdfRP2RHyzoj42LUkzMMMGIrbeLFKPsw1CpCZ528VZXyjBqyFSrZQbZAlEYyh1kRhN1E0N1FdF/ndTpbc7XyGyufIkm9e87oaVl8C1gG2N+QofK8kywXoqc+qpQ/J0anvNbS9g0NPZjsA0DSb5jfLuEov4ZrgtTPG4KTRik1P0qGwH5i0ntMcaKCs4mxKbI44ATKdLqdduFsAavp2k4G8ZXB8B2BGhJwDupMJPkc0trWlzVAWl3PFi4r6irScsNTTAWZFaJTE20pYbgQwHGDEAQBALE4hzCP7lgFMXsnOA2DkUgK/n0sMC4B5k4nXcfnhLhPbPQgX4TS8DpfhDBcdEMLPQ+/LF7Z//pRUVVJ8+QLHz0K1YOfCva6e+UlmXuuZsMO/rpaq5rKeKWvigMb9cH9C7ALy7AEnrq1oH1melkvUkCgqgTAn2PlJe19RbSDScLIAi9ELqw0rOYZDZ1jxfiQqJP5+L8AraD39OaRn8n4mi/hHYS/0/va3vwEPkrX7kbrBwXCNBL6RgfWGe7DNCrLGHLcxfnbyNoF6jpITEqfAVXkARPA2T2c7PUZ4jxmNJXJ6E3+D7pMQp5O0q+MMr9JR1kkY8hWsWcZQJFgCJTK13bmPuzPVZkRkNxDHM14zjT0ZDPFWzG8ibBxw3QKiCv0CnibtHBAzbpedPFzAYGLAo6yT0532OJYsxHXUG14fL+D+ex1gu+N5+3pCAx7H8Gsobt7zE1bnOloMrzudobMwYwRx3NNAA2UELPC2KRhF2+WQ9YPjKtW4EuwqHV9P5BWv2CgI3NrbmK/y8EmLzxu0GbnRrT7aMc6LowAgQFipT20CHaB8kyYiB2scBIMxTIENKy3pL6CL8W2cG2JsJNywZRucvN1wkgXcDWyNq+gGNiGcLDGcwS2/B/R95yaoQQKgfB5Pr2XntRzH8fWas81FdLW7G7MPbVSMIE48BhAuFfCCQQb4rthh4EFL4FKA0BaChT85ITkiTrKlmhM0e+I8Grkood0uj/MAD7GdAi8FBPE0LMYldAP8GvBY9vxu4qVj1pD6n52xPjtxzvhpAPPWYfHd8/artrcDp3aWo/hPcQ+6dGu4Ok6HK7gOrDhc/HK8gp3KLz8AndUkXAF0JN0uHXCapws4K1wIQhn/VWjBmZHDufvfhdQcIDUHSOHFaS4gBWgJF6OQw2oFw5gDoHZ3Gf3y8+0wS26T4t4BMkr/r0LsvwuqHECVA6hyJg/JObRaHEwloFSOS5YJJrrVH8pDuA6mMr9JHFDC5P/3AakZRj0Bo74DRkUyW01dUGIZ/z04/ecAQ29DMJTaC0TffdlhM9vBy+fNsrqHExlmvnOXVtfQNkAzrdJ4sUO3Q0/IcXshMTV2HyfAxVqUlniZWY73HnZeBA+42ct2ezK8LJL4K0q54Tw5idL/wPA27Hxq9Rh+DEtADOhKHlVAaDhiMC4izNWhJUlM3ogXH9Or66oROSj3/70YQtP7LjSBUzft9JsQpWxElJwjSgmIknc6GqJ0Ovlx7z81SA1ZZvkOdYpLgAe3hSU6FeEsEIxLP5PY26Zb/r1ej3thfyKl33ABhEXs9GuXJF7AgULfhTgK3zILfVpFIETo/IreG9aWBsW5afSLr69OgLen9CTqjdKBvH71wqKd8o2WHhfDlFHgFAGJL3Lj1BDfp0p874SWFCAqiGlJ+Lx14AabVur/StAV8KsBePJmmIY2HDVAFh0pGJRghJxhCqilwRHvPAhLFxy51OQqqX4V4EDo+c501xWn6n75QpD88oXeovE9uypW0yovRsaXgvcgDzi+q140+cvPSTkt0iVUYStwH3mPlNPEajFsU7gwU/nBjjd8pKY2I+vVG4gka8WTOgaVLvdjglISWLmoyX2bPZC32FuVrohQhGlYDvHxKYNlLeLLRTJo9VARYJ5ercQ3ofiMQWAVaVAear+jnKPSNfUCrNKSPY3pZVb0UL9el3L9ST4HIIETMyzpo4QPxFp5S2fC3AifHCB14wQjPU8YuGJnuhCGl/6a3JeQaiLCFMh0xWVVl0NboqfNiUF+dFlXK3mQhQZYZLMZXNZfyh42kvurcJMkQTKumLKEFJ/ruBsllowQEpb855vyXK4jJKelvmFQpP02B/RMGMHQZNxKYB7pMyP1g2QTGhCx0JSwiATSAgWL6NLnchknDrtPPF5OAnjstUXVtjfZaUU7P7D6P3hCIquBEjBUE91WSPKgebjEa7OppDC5JeQuu7uuR5Y0Kf0CURiQTamMmO8wbOLn0Z2PbzCfxIvHLJ8SebQeOe58kcGBeL5I8Mv3Zumtxx7vWufrdetTgM1+i5x9bjTsNHPW629sQJ8jT6TtzDhlQanrzaqsdi6TnRgYQkGPwveSmJmtaSTMIGDhWeRdkfS33NndKfmvaZwRU3YpNIuoIj0L/DO+jdkYduBAgSxJA80ODZQytaH+KO17z2mfeMFxNFeYzRXbmvvcLqi5b4H2UPeNsVdsaiGbAn+HSwE1UfYJ+ORxRg1PQ3zCZWRyvWZUMpB6K03UVSpuIBmk51dOGEO9WMk0nfR8uRVbM+eczuC4xvHB0nrB7u6CLQKS0CCkjJJlTHkGfAbqsXbTsIMULbZzLAIiNSeIQwjmPoLPvTFRuA8bc1xM1GsB7D5etEziheoVv5w8gqowL5Lk34mqwr4bKg1xwY2Cvk5/xIJ/DR4ebU0mZaoDxxvlKBtUUGSzMccXbORZlNwCDTlH/ZYSKmggr2U9Aom0/ATgSmaqBZHiqEiiBlnsdZH/O8n0iizl0Yp8cHBS6ZVVqtGAJMNMQ69yinMZi+x5/FLDuZ2sHXkjb0g7otXj7ylca4dDQt9ZhckFIGvAtuZbqB2eRmNPHJpe6JkHqsf3+Ic5/DLPaEgwDmP4dp3ZkKyd9N4k/BCdSt0Mvk/ewT55EGNgfEUAY+sPtRFL2O28wec2U7nUpn+JSf+SbfTP0zpp4HT58fxGV5fkjM2cHkt2d98wQSijzG/lS1IWwSUs+jDM4PqVwfWLKziewrIMsWqqqqaSAr3ZbH6GA7Wb5XeAR+JnnRfzcSKYHSBl+5zeJH7AHz++RN7/uMguvvUuL+YXxc7FqteLexer/vOX+O/LXnKx2u/1evRvn/7dp38P6N9D+veI/n1O/76gf1/Sv6/o3xj/3Z/jv0fw7wFvbZ/K7EOZeTKfe4R3NV0s+L5Zr7/QXx+OCRgt8EZfgCnyaPQ/E6vDFZa8f2AWZP7oBeGveg5LfQar4+zBoRPNyrE7pFSZ/BmVneTXr0xjEofx2tDNYY+PzWgETMMP1Q7g+i1sgR2vnbS9nSrfkRhkqwRsHPo38/RbvphdQusl8CGPaOGENT3Fuh7PI8qJ0HVX1A5C+pJVg5BvJs7YWWrjLZ5sSNlu8tuk6ZyrlQ89VsELjataP7wr0qrh2hYSNRpoK8seUeMCmn6fzxLxMCwT+KjOgH7O2MJvnKpPAJYivoJKf0zds+p++BQ9vH3z/re/DTz644XvTs8GHvzjhX998/7nD3/9NPD4Dw+1xfFi98mlwA9nx7t4OsImu9gGJrxNs9U3lsQ6oZ+8uY2uRRPfplcxkFztlqLfkiNflugC5ldAsW6YiqW/dxNP13dptl5gZ3spcHRjL6+uEyDfAeqb4RlxlxSoq4qa6JFqCaF4ilAc4mD/mmYRKhhBW17Ip0MJ0AFLoOlQEvXFEt+cay3GyyXedaHEu3Ra5GU+r3beZMCmZ0m1A1RgkRekV1WrobSp3306XS5/yUuAAAp2ADfK5PUijyvfT8WU/dHg3ac35zvrz0U6g/Ff7I17nVeT9viiS3+H3R+L20Hgm6nBHsJmgtqjwaCp3d/dIgHjw2IG8GBgwVcT/Hv8irL+lEy/5pT1Lv93uligHg7vdofyLvYuZu093g7swphbenRxS8ZyozZZDuiFdeEcNTVha/XX5PLPaRVpc0+FuI5l7ZFuLUxK6dZivTMgobCqrno7LK+h4vnsqqEa5jRUOn3zEWAjEeJ0ll8mkEb4wFDu13iml0jhW+WeZrMCLtdGEyxJlWGDho2sFdo5Kz582tF6gew9bHqd/nqdZwn8yWd7pAbqIyfQ4hB/9wmWIYlvRCVUTuW7p9Vjy/kuvwSGMBJjhyujGqeDus3yx3Q6QwclfITWcUsHPDVUHaQH3nVVLQd7e3d3d927g25eXO31X716tffturpZII28XAE1/jlXRzRqx9uWMYZ+cyIMKyypw+fkG5F539SRRSKQZDNG9QsUeyiJNlcoMfQrtV6ZmgjveL1uYYLg2zT+r4x6w1KpxJeCuVtFMBV8siJufLW7mzL2biXZu5SYi9ieiZCfUH/hPEpQJ2SBysySrZ1HGqtrzWYO+OMvov1AG+HCHiEfWqxdFBZk+aRLDeeBUHbxdf6HG3mNk8kQ+WlvuojL0hvFXfpBNNocURXAOcXMXWAPDKqBZvFkMudcjjCKUQW8GlDzRTKH6yLMKUPRYQz1W8R87e7GeF0/rWCBLldVQvw3YHxt1eMgjPnx+jOH9C9JPDN4OrH+aBco1wMYoe51gnsqwcp8Xcqf7j/HVzhN38NcD09CLCKq8XLYpbGgbrUq9+K//zRqyvCr9ToNk2DQhDYB9qwxO4V+YYW54oGYJcUvn9+9hQulGqbYQW7dP7TRu4NqAoSye6WXWtuIqu3XQBQsGAhESkbJIy2LRkQB0ZhPHcBl9KwszxD3nCP3E4WYbWTw2TGxd1G2964CNXpp8sIsrrDpeDZzNZ2h7aLWLSUh5mgdRR4pG2tLsW2MWk1rePTYNBQ0Tx8lkqqCDNbo0XWYCT3QIuwHG61FqCU3H46nyq+uFr9zPHCHbfWMQaW1QaXaoKB4P5QjS3Fk4uUDLQH5VTlsGC1Qa1RvTSrnKpDV2shYJVqJgQ1ySlWowp8FXPOGOzqa1q3XEgUJyFX3X6ukuP+ULBKUXZwCSwTnwv0CJZ5MHgPXeqFcizXGcMWfdIFRiKJEadvieX2Dp61jEDCbMBVy0pQ9/JO5MBCej3lOOyooJWlick/UiNXymbFRq1yvyyhKtdIbpn5TmvsMitH0kF7qkAEEKuWJyJ5qkPoCSl9kez/+zx1mM/Tbx7cRMgrTstzz2gXccX/c4+IRfEazngI4tIYrgzLnNsnI0NYIOlsh7Ap8Z4ty/spvUW/UNAtLwDzgN6qfEsDIxF9BwjwtyopaDyx43y/K6ySpahtZsCD+GK8eX+ESWiSLARsx1fDCaziDBslmUj9EcMSEo3AjWSwu4+Kv6ay6rlG5rA4RgN0XosMAFdgg2Fv3jip7/V7vf3mhSLxJM9ao11t+U8nXCSmxePs9I3mWwl6L7yPvcpFPvwrWzNl7DodmQWxawSrjO1NepjjwyIsvy3wBJbwQta7n0FMHxsU6S7uwu4r5Ir8DDi+dwaUG0/jo90UZa+CpHHL/iCdYgw0LAzsyocNUO1qHpcXWDRmCZ918PgdyQd0O9VGy9fE4eprlhDJRFK0Q9dDwZZFCL5SLSKYLDgAp885qE257E2NcetNOR4E6nov5zRLAO0PEbNC45pcAQLkzvTCzM1yvHzacOtabQMzGl1Y4yZjHA3x0JUT95fTTl7NPn76cvn/z7vTzmw/vkUCr5M8fT99/ev3h47tPPP3Nl59/fQMgoTv8aJv7AD7aWXILpP7X9Fuy+BjDeE6ifvdowDwhWEAzXQhw2rf1MXEoRoQKpwzhqyLOSpRZtCwrQuec4NLUKvjlUXLToqk4S29wyBmeQ7ZzBCfoekiiSEzt6g7OJhrdwnhZFstjjz/yZGHfa5PCSZHDEOB8bHvLb+GOkZhRYuBtBk/qJF9GtcpeKLJpf9d69FyCyTz/g2bQaIt4nRRpZXMeMJjVMim+RFWYaO/dxvu8r0sNH7TnhMEDkwcm4ZMliCj9Q/vx9FuaWUORQnvSNAsSZg+aTaTOAj9a6nw9nSjUJGM6HBDEq9WTr+AI7qdfvrF0EBrKA1wP492Hn9+8fnP+8cufz//+afDQfz7wPl2nczjb+i8G3llVLODXy4F3uoCk/f3DgfcuqWK4HED5L1AZ6kyh0KAfxotqsB/m9PQOP0psZXAYerR43uBleAMV4Q/Qt5s4m+GvG/h3E77+7f0Z7ho+BOjsp3j6tVzCVL3w1cD7HF/CGA4G3kcCMvyGxF/RqweMCAZ5Xk698GAfBs6qHBxg9lXyGyDkwSH7/TMwOPB1BKWzGfyAaf6S32BhaOBtgvM9gI6pCrROOoheeNgbeKzmIbYD5BoToZE3xF3Ab2jnZ3pHg5HC7/erm2U868HHC/HRh4+X4mMfPl6JjwOYSa8nvg7xqy++jvBrX3w9x68D8fUCvw7F10v8OhJfrwBFOv0DT3yfoxwUSvShrdd9/AHNvN7HH9DCaxxCHyq/xt5x7V9jx7jyr7FPXPjX2B1C/DX2tA/jff0Kf/SxwR7+oqax7X1su4+NH7LhscO7jxD7ROcsJWzCXz++ef/59Ke353zJcfF2AJrQHbR4CJ1Bc0fQFbR1BB3BMI+gCAzyCLqAIR5B+zDAI2gYhncEA4fBHcGwYWhHUH3ohc+hXgR/oEgMf6AIYNFzKALI8hw6Aix4DiVh4V5AR3P4AxWu4A90dA1/oKMU/kBH/4Q/0ArM5AW0AvvhBbRyA3+gFUCNF9BK7oUvoRXAnpfQyr/gD7QCcH8JrcD2fQmtALa8hFZW8AdauYU/0Mod/IFWgOK+hFbuATuglX/jikJmG/9CcgcXANK7uBOf0+T6WDnCv1A7xL+83Cte7hUMYw//wjj+v7BNcAHHuIEh/+ICf0CBCf6FAj9gB7xCDzr40UMGIszoOkekLukamzSAy7mZAjTQkvkTa0FS2DdwSmfQcqC3Z6IANWgmPa1FqS0nSGvSNSgaeihQWVanRp45QUhIcOtECdJjIjsTTCun8RKVzOAHfM6SBRZgL+lYYNx/cTCJcCUsSltFYw/IHT51E0n1YqSnHhFJT4kMM3bYLvM7fz+UVpnDDC0Hk64guXTqcGsiJYDT/KPsamWryUa4lOl4cHx3vA3CUhXoTcg/lEro9CElzYCvhHkk6KlCwKmCm2hIMsAzuJR9zmsXZjHZFGWAppZH1dJktX4V8WeEeZHfnF3HxRkTDAUkhtBW3XVQkprHk09Kdqx+v+xaCp5jkc2EsisuzYArOAncgePEsx2Y8Xf5LJ2nSfGpAo6EOEM70fc+fEIO3ZUDbLQXoIg2XkcvmXeQLmDJn5hmmH+wiy8sB+KFjudFPRRbZ1EU9V+u1/T3hXDI5AG1Ja4VfSSgmE58D2gJ3/KvoWjgxe7uHP8GJSJY1Oe2FlV6k8AQb5aBtGpl/e3uxvD3gNXaZ70u9AqdfLg4PkKLXzFa4Is3mw2RgMLcqChIQOlQGO9Cw9lJ9Ar6z46jVwcih2AeQyJ2fvA7JonDhHrAK4Zx2MmYhhy+QcerRfUrUx6STrRICTLVXm1gtrsvRe1HKg/j3ajzigu0Wq0YVoZN2SAyMtUkSyPRBbCpyv3D3EdjCpPnZa7FNDaPUJ381tkvLuwyEqKlFcnF3qZllWRJUbsYoA4DFjjHCYlSyv2PnUPacS22OJBbVfH0mgoIwaRGB4XriZBfCAlmwWaYdb/cFXhtL6IiNBrxPVjXdoWahUpeun3orEzD6B2ZcgJIzWXHu7vGpxiHGimsHRPvwAWKirgeDVg2qjfEVzHPC6We2s8MdzCt1RdtaYUt0byVO6ql+MEAnTNk02Tx0+oSdcmYZNHszmrVzBzZCdQmm81fSB2djRSI10+rqrLGKMFM17PIm10uposUGD60+xaJcNeqkm8VXI9W3notSSiMHM7FPyf3u7utBImF+EknJHyM9geO0V7SKODaMuiF+3DpOBz0N2ORPKFXBubIpyYflhsrxaGTx7yERIwFWyQT16QmM54vsK+YUgogTu/xsivgCtPHSs5gp5ZVjHcKKitVTfXNun0UWwrqQ3AXs/sPU/7M8TlfTa/fNWw7oQkfpiZVQUFUhRV5k463nS7lJyU6rAAWZIhPGEy69jdUF+G//76xhyxaZnPf0jAj0MKmR1dsKVmPSffuOkkWf4uKTim75ol/j1KZ+PewiEptbCodu2WyAhjhOwT0X7FyA6SAhtBiUAfktmhUm5pWwDG3l2LMcOWs4r/pcq2RL6fTMQrtVWpORs7f96pgoGr1GopBKT5PuOVk28beOOzuwdGwvEtR64RY5ip+h28WD1Ng8IBa/Pzh3Zefz99+Pv3y65u/nb8dyCHxwn/7sVqvteHx5L9TMrMrHNaaevvm/fmg3sHpn85V+2I0f4N2gh+PVA8i4+8sY8PnX5sxNEyrzu625tSBiH1DQ0T2N4JR//Lh45v/zwc46N9+Of3bm0/aivnssEkX9kB6DStkVQgsTESHgDQwlF04sTHElxxFA6fkhEuRdfhED1mjHF228K5O+iM/b7fD/OSQGMN+EAzg3yFnk96cs+WeRspVltg0nVVwcrRe1zL+3okhgxlprdfTIGeqDNNFEheoq5qvKn+Oig4l012lb8VPzJmANczGOVxZ1uvnvR56iSDGdRXJ3tGpi+gQnz+/0KFURsxu2Gd7bkZSHubSCmYYIKMkuN1cko8dqrFAQ9JEc6B4jeDLo/3wjw7eMaDQ6JJby4crdKwXLqIHuL3LYzY8GHhwd1kuEv59OPD+tYpn7GsztHVbSKUBLmp4G3Spc7ipExvYFE4IoXpGahVmSTWma8RL/roibkz0fMn1zdZrD073yzwuGGOJxIXxhyMHb9Gjt3TGKYzg0A/wm3ELwCCwT8kxHPIElDvi90v43gyaWhWlntqqGAW1OrQudLVrsZRTyFv2CpInQpeAiUShuW2nbGSAWWw8WALS5GPM1Aemttfym6AaCCes7P0WFwtuDWxR9QHnsGn4PR/OYFEOGLCyNAtKRztZmIRoV7qR3oVWj3VSjmUnk8jXv5CwtfvcbTRrW2ZKqc+KzgLzBhZW24eLL3ly8VA5h60z/hJLjL85NgR0i5dMPrKGK+7RWfWC3FXjrJipAjl3hCsc1GHLEHpz4L1wbAHcbbQnMJata3Hx29IyL6t3MJ0Y36dacvOJa3cfUDADxvoz7DoLeTL0zspa4W8C3r+TIu9UjCp1blirHa+9APquPRKgZ9/uLK7gml9IQOg3jtLB02ZAJ1iDHkqL0KP2xuIOrSKZPjc0vfoR1eur7rN0tkh+QpEx+jXHR8c8ezMzHzSVMZGDzJKrSbOdkVasQPE7XHBQW4jd5lTJNzN2Ya66l+zT6NZs9c3MIvtmZhDaU+nZXbmPiBoENmGyXuOYcay42K8L1ItpxByhnotisqSsTsUrJlUTKNG9yf/9cWuBu+Tya1ptL3NTbs/PndmBPo+RMSf1m7ni49RroBcyNp0CYRL2X9TkhkWcIbr9kQdKS6ChP8jDJTm/61T4L1KPab5Y3WSdiv+wHYyzGyjzW4AXpOgB6g2SkJUeoIIg5iXZjOVkIqcAUmFgCBZLy3M45RdOAYTsAkeGOkfqi5tBQCcyj//mOawk61mryhK02loJ9cmnUNVExGJs3kdckMEOWjwbo2QOz+0BoDV050SW5iNVZVXPaCLEe0dZQ5xm9nuyDhxyAVowFVHgeGVFSqUh1qXbYcamGhYCKFLUHRmNZjhGIG9sYAG6vgMm2ipUUKHCLLQ/qJD/Rl4Ef3X6o87+4Ak1sWB/QE0cIudizufXPG0QVBmgoGYFEgcWLOswcbRBHfkcOAH52nVlAww1oKf43lIC5SodDwq1ZdG1uXHeZBHdo3/7osHyXHcmW1t7ifqJA5sr2cgn2qLNzWj7K3FuHdEUKeTU29J02TnlHvn1VsR6hFaftFpwTbSTw3oTVaAGUodM4zA0qJiDEPAzhiATQ7uy7B6wKK0pE2/ZlCO1mpQEi6ytDCWNWv1Bqzdo9Y0uHlu5R/pxN7odpxqabB4pr+BsssVr04X+LR5lAXMTai72qDquLTaRgRNrCZCeDJJjqzaUTE70tYNi9YNjVJ1E9V56gw4vrJ0jMJ7I7rk3gL7NKf/xfTUSnetQNzv5IxRg9Gjrbx7D5Kd18AdnukiXH/M7+5QTnvH5EE6qgD0wE0dRtfuCp+htpKBDL3+c6OUTrbQoKEfNmy4ebVrW4I0X9caFAQy9C9M5UfoF3/BUPcz4Fx4eglGiYBfNnol1oPHXzl6gLRNP6/Sdo6r4LJjouJb3+IjL+oiByKBzs4aYTMbO0xfFzZlZiCW7kGTj0W5aZjcSsXJnXWOq2jztScJwFvGyTEzkrG8QMZHeiNzXWLgS9kLprszK0ceMT8fALDW0oJcMJVsE3Om0SJKsgc/T1Is/85K/ci1orYeA2MHtBREo0p6EjZBNQJynFqfIx4f36p/u7XPa5JZdJ307qowZt+unMRSBGxL3+qtUJ1Gqpxa3IfoOTcDkEkNzPjCB1GD2SgpWZqb8rotU1WWLlTrUQhYxeqP4Yyqo6IjO+ag5FlZynf6EPdbiveYj+qctnfxwonzSdQtWzBeKOF6gN7FMYvsctJx6VCc9WPjdPrO2YFLq6uQk6gcJfEoPTxt+Rd37x0V5Uf64B9fOPfr1bG8ouvtcpDeo7+gesnBxUITGGLGS5RrTVSsVtab58p6pKjh2leb6i+mCBeSlJNHUaCvRiOXXW7Yx1lWmenQR4zaMwo0GNqecfZBCi+RrWRgXRqLEQCnqH1y2nEOZJcnyDIoqY9Sy0cMI2oMqq1Ea7lAGVtIMSx/sWcDQ1SxgBjSUko1LjebxaG70dqMssenPxFNDalyBWl8onMbhfs7f6U6+nSvpGj82N4n65qqS6oq7PYd2y9NQhUb5keSQTQrbNL7IHCAyq4Qmwr89KhUSAjM9P+ZEZDvO7/nj7o/t0T+ePWz8YD2+mFzsXVxMgr2r0Lu4eNb3tObIrrLeGJCDdqKFZ9vFurv/8+DlUA/a5vHUQyP1B576ykg9ZqnPe0PWPT5NoNH/B7JtcRv2jZUOu2yoMsTa3CjvgVnIDJRPzHogp0nIfg0EvMmfRsa20jwpimR2BqjqQAESumY6t8DTSEpbuNai4EovPkpANDFghtJSfFSTPFrRLafXCR4EEUY9mRpDsO5xoklUPC02oejEUd4U/eIgaMBUKS1/hTPXKQBDzC0YRBbxfQ0gamVYa4YilQaS1ABJFnELaOBnDUk3gKLSQsWkrFezriXFzpCzqTeCR7sEY4qnugXGGvyIGahBz9kdexNNt8INxam2dPcrf+zaQ90iUl19snooVyZ1eXkxfSNYfIapX/pkU4yu1qnQ1OtaHaO6nkrHzvFdW6XQAPAlSuknHvdfUpAdfIinwDoi4+T5QbiIDnu9cKq1wBUFr6OpfJCkqDfkSyKcRcsRMA57g72LbC+8tUmqOAP/CmvyDV8zsu7lYlX4+JJDr1rw61ukKy/+hWlE8EexKNp/gTa+ZJjDCcRx1i3JiBaKk2AAUPhqvfY/R7xcEL6PzjD8xakfBOHffO35/X/DOAxUehaEzxreVC5xa3DjpmlZon1pdBleRhifD5+ysllSJEX32Vc48THzFM6i0+psVZR5IffWowXphUeVwXNJlPmcszL4LIY3ETmL/6NrGRdsh6fo4SyrK126X1MLa0cViF+oA4j6XA2t2G+XRQPcUnp+Ym9P6G2bXYb1mujgUVjoxZB6m0ivUFEm1K+YH9wr7fPWdDlkowEqrqqk82wWspfrEKN1iMi9i5yZJnPD916QA16vllL4UKBSM6Zdw4aQqeXJ2e7u53GJnOFF5lEBWDJV6/g95heoDo9G+1QADeKg7+sus3PSC5MTTahy1sJ/4Xcpa1h9ymivpfA5QAMQymr7VA/XtzZWYywFcuSuwUBpsvQ+qw2GqgwLWBL0OrxaQ1169Qb6QnidZ0oVgcXhXYU5br0iPItK2HsY9HEzVAtdwym5VtNr9uJGb8SAIt4sAWqY3xumEbIhl2auq60N04HJUAvPNANFyg+Xy5isppXTADJoxrwOPxYy0zeIhwq9QM2Bq8HwWFZmvKryaQ78yrTaXiZeplW8SP+dNBYrl8liAecmKsW0+oG0y86X8TSt7iO0fEpMs/UMFXOU2TptkVt8Cb/Bf67wn3v8B8lXeIdU5xwJRiqd/wABFd3M86z6BOOLvP7yGzfHJ1NepNThZ2zhPdykzlBBvLgnIvQ1cm9odJXIHX++DR42hf22j4eBSVXIdyzf54gMP+FxAST9a0TeMWstCN2Ihia+8vjpKbfXJbe05OpVjPc6Ll+zk0io87PxQkMbHADLTJgSEzah6wWcBoNTnxzGICfzjAbDVPxICwETKU3nTaD3y/V6ziV9Rp3I49765B1MHJMPXJ+ZFUTLU7Yu6OpCmudKHwDKAn+efktmyrIfbXjJkl6uHIZ5RGU+tNkFJuqMlN8+4i03wNKtqMfhUQiuaiO9F+GlVphcZ9xLnrCuZ9KIEm2sMzQAIpXufsD9F5VoEm/tDdh8Wc51vj06iFql2Sg2prmqGJVRabquAKpdVgNMNupttkARXf2kTp02YQPQOEZcd/cRWF8HcwnYGmj8BSYm7JRnWIMbwzSIYHyTlNgSWuruZyXT+3XDqeglkQY4CEnTCwsZBJWUnqer4sOS4ufgjy43uO1mzEkeIzEioDzfUlcwbslr4cz+jWzWqfQWegosobUdW1/X61vU0RdtMB9JnifC98GhthNfkpvL6SzZmV/BIYdnD++FIMX6+xwVwr35IZz4hxitmh2GFNFAngNCbu4H+KAUBEP/fSsChgJOuTJAlhKfWEVh9kyc4gH0Hi4qcH5tBiakgMG811iR1leYzc8SIsJvLiqjyBGQqAnRkxonBh6hDAwdCUBL8pihJLEUrE1JXcMVtVWid2Jshd70Usa36NL4VNiaOUqjJZTqBh9TIAnAUYZ5O4o52Np9DALWRraivdpIJkUIhGUPc1cP7T5GU5eFTyBhNOcND3LsZqV3s2LdzDci9QR55PIY/s2PFyMoIPmdRTDwV8RthRSACJWIh0xrmFpBBJm2os8GakyJ858KY8jwZ8h9X2cUzyxGkaAKiJGv14Ak5XptZreiMzo2XDhTMp6nhDZzTiiv4eDAA3cz/IobS5wgbPQfGuS/xgAjFnLYGMRJ9FlGZubBCKAYTP+zXRI4trNN+M7muCUnfTtCxmDwwc+4yiLVRX9EtIuBxLDABkOhAPAGuaFfgCwsElOq8iVKOD26aiol5/hlw53xwrn4q35NhHMFlwkzaB1uxNF3iiIBBsFf4xJ9swWMm/G8oXAa9fgN4D2gnYBc5wwVvNEbnkhI4cIrP0q49/ZEwJ+THnLR0wnK/aaTYIrq7J3OMIZ9w1B0imFj+7z4ioqLhqYn7zFM+uexSqF2EvVJDa6gQeHyvBNN4ca6YH9UL70wlpVgs4WtgmwoY4kLLeDGWyv4bzHyvIF/j6xdrCXPMWu9Rj8ieYY3S1onH13gmQnhA3sbRYk/bF32QZL8wSosgCHP+Tv8YC4+AcID1Fi9Z3xhIohnGAMS/dKEgDu/8b1QCfIOlPJXv6LLorLDWbThCrlez5hDywLNXfGMCX+qGfNxiQm9bpNo5+e4iqU6oZHKYvus1yv9KplGaHU58hAY3oBuB3vLRZxmjEsSMrgRefbHVuCkIAdvsIsoDABLCxTjiL2IiyyG/Q5pcptN+E998NJVV8Xc8yzvcQTCAZe0I6gbAQ6xyTIY+XBy+6fITN0C0N2syC2/jWMoIsKBsxWa6rH72/IeRZb1DoD23jJpDSM0ZSj2ld/E8tBlA7esu5cN0hXTBfY/YRIIlfBNPRlF6/+qyXzLCOOYD4XHHeXRc4SMpiIUGOM+TLmTW4Nbb5isxszckOHxsHDr2vtZaN58mcZpFThuJgxgXvjOkccvmL84sqaY8dqVAYD0wjeOnCXO2gv/FYR+C+1PsQmKFYHBafEba+oJrAKlwLYqbJMMp8iIX6LIBLMltd7xCUuoyEt7c2HAJZTwmfnW8xcDdLavm2G9fD74l530cvCa+TOnvfmxRkWgR74EgrsmqoSG8s+gmdmHbHGvGLMHUkL5JIemkOG3sCfEDZqxyl9lQGnck9Zhj94NhJqOxlWFOt9mc3VX3Zu4+JoU7C26gG/rrH8fuqYD1BKKwrA+c1nF67x48+58pKOqfhMnJL4p/8TP4TN2RUHJaJdfVyJHPjLumTy83ZWualVgb/5mXWhbjmX5bTmLq8S5LtqSoGgYvx2TDZwNCghowbkTcZAMf0UmwQC5Phv6reWZ2jG1lZH1SBtBXx32Omb1pCNBczfts47dER4M/7bx3IYmnLUNKM7NHcyyPuH2fG4hNzJUv+Ap+rco11+TYDcc9QL5WMOoGntgo6dVBzGSvXHD3Y9OkiVLrWjxvPA3RzEuXP6LO4uN/W/bm0/QVdO/A8mN1tzl6m9CgrHlZPyd6a82ePgErEzWFZCOpAImVPkoEo3yJDyT5ZNA72J5/9e0uqa7qCQnRu1zyUXjIhLCvUuylVHmZ4qtQov6JblBKXAWo5hNN5EPH2AhYOqDKpzlNyQfHSRCNEXvCjlZeopj107XWZM8eLiESV1G1gOIkkWKFxE/H3n/7pDz1gH5duwNgYfygjY39Rx5XGo56HX7PMvjQlZ0ZD/Y6Xht/337LPhReweZXsdFPK0S5grzx+4R+pIbCteLlVAxT4om2RWw0KXpHtHXaqGt5QqFLm1fOgmKu5d5Ab1/zpfMaSO9CC/oAjuvtIIrXhAZZa0k3Esho6rym868I4zSfyFvlZ390HTnKYBIPvOU7euis8986uliIRldUpnCzqHBKXevN0SGk7nUQL6oFWkbXslRtz9CPeWdiuhAaL+dpcynI/IQ3HuCDubwOvzfgQu3zxY54Nv/puV8Fv7ZMpeqxKXErISk/X/7gjczLMSE44I/O4iERv9M6Z7tvoIatxvQ4MLcf8KsDMcUzj7tAsCnizc7NHCTt67o1nqcpsHucUPFL9fsNv10T3/f77AoZ7B4Ria4ij7R/V9oNiazFG57Q3ITyqHF7/nG6cKXWVqTs0MkIT9NjprK7pdX/DlfXS6SM0x7pKphucxrf6a0p9RWds6i7v+BlKfU1F0u6LMlVw6PjVl5ohAjFu4yZE0eoGssrw4ena2f5Bf9IK+EnpTa6J8/3f8VSFNpJqGkjieh646/xmml/WQZJB6nnMkwq0vDK+YJlhTh0EsYTQFtwY0+Ik3DWqLST/yKlFD8PCxHPJGn16ZBP6E2luO11WP4SpnJ8ROeKGb5L2CipYe0rJOE+0FbfhedCr61VmKpCa/ZvWmGblzDff9Hwcd1TLauo7N/8nXV3RbKhlq2jVxLbyCQ/p5Z44dKrZyNAVvRGu/ItqXq8HFv9MCkzQNeMIyz6TV9QtnNQOWifZrMo6IbzVNUXeMkhStHGR0d9eoGhtr2dypJp5lcWp9pQ2u+sKUidDDkvAmnLcxrUsKFNQxPiCah8ovmioJ5QkN3FMJyPXXd4sIVML/yeWDor+gFvB/gQ5B6P2CckRwTBezF4BbA1zQeUF3BeAWk0MUD6aB2sn3YCNXJjWOm5BUtEpHa2KwqbsjNn30wzlkqNGikmQV7S+THM1RgiSZpZ+1kpPDPEpmHFcGwcg9ziiBwBpIf75yDlMOXzoccZTRtc9YTvVILEAnnGif9IKzDZ1OrbHv6jRJhK0GoYJzTSQLUFU/ZsxxIRgq8csLND76xdu8FrdVaILGbYzkkF+VYKcQu7grAD0aa8Jn/0hAoCQaV8bJgYxgCTBiDCFlbVmc/6FbBAI3PWNvyfa5awPhfer3kvZNSmLXk/NBRlxcT6twNcFgZGxCJ1PdCXqKriZnSdYUjzzQHzbS4FYm7vKGdg5u7oRyzyZWShDSKnWNDL34ZUBNGM8MEfjKKuamMNVe05pSyaxay1TYUyQzFMragjP2Ge0f+lzS5kxujdk46bY/1lUKFqe9cqdB4YhknE9uOePtSlk9YylRYxuRPKpzwx7oS1x4fDZHUV80oQEJL+ZJZMFuRVDtpMZFPpoj4YOQjKHMQVJ5s6YThD3WjPcrKjvQz3uoKD2GphcWng4jK82CfpTZ2rpqwswB6DNdPjp0V/OTYmW3HTtsUZysBKxzkqAE7JaMaaZ+MV9VTFLtqpgqOtaYq7LqmhPohsMoeIXeOw4JRzQJKxmUiKev3lJbzlqdm3Xv6ynedH99CV+p9aO3DSucG/OQkhXOi08Q5nNR5gUC3BuRnccNxVmfG1A1eu6E5uTtndQcZ4moEFDQEubcinn4VehJodjli6lqMPyOOy2C1O6G+g9vtxpMsGPgGBevqdwgb+d2NcBT1AqHiZWFgqiO8r0ClXUd/L6iGDQOi3SE1Z7KGdwrLFLyQXhnseY+cJMUGm7y46donbpiQM5It1cWNioj54Ps617utwVxe45ucQmiCDKXy4ByA8/XHjSHQiqfGoOQBtkCf1vx0Ok0WxCxKTSiTh0RlDua5j66EzJ8f+aGSng5Ztu75b+iYI80KTRSZrhsqR1lJ0UM16IW33/Cfe/gnXizyu2Q2EKqFHBm1GqTRJPl36bsZ93En61ZwhqcjMdC9dJB1b7+h5YFI+ztLux+mxyX5BfTzNpYJ9vahmL/Cj3v4YN3HyjtgvrdCiW2rP4xP8ETWmKSUq05iPI6f7iWYfkQzrSSZhT2kH3MKshIfb6+rnCaK2rIuuYQOsi4HUVQo3rIjU49L4WBLDTw4xsg1P8oEmu7urvxeOQoAh7wYUb+h1mMwUB89OKirqMDn+W9Rjn/uoxUbo/QFa51ZLtjUphsyR8E6GRMyKlNEq52N/DlCF43R6y0zMMx1e+GqawrFyii3xJ9VngPNeiw4jBnZxDS9earcs5TzIEd4mVTXfZbwlyPFWzxT8Z+jRPehLYYg3WhLG5y6ZORZmqWu5yiz09QZscgcWU1jXQDNLGWF8sryTIgetfkYIbCM+lanSs+r+WXNqCDUm3HaGl9Y0aNRDZlUu6h2TJeSrCKhj6r5S3WzeKSmikmp1RPnq8s43qitv8mwd5imMvguU7H3F/XSJ1fFIPxGZMFae6F6K7zO72qaTYmIUqpDjwQFIiOzSyhvAqHgaRiGixPAMR07hJqxL+RT4bXhv8TYPfiA9FjbGgLKLRcotGIvZU1YZTTMrEpZBdWAFTTv0fpUnlfn9iYNs6vRBg5tudVqAeMdObXI8WqnSWpZmtTyM9vYUbn1kehqVVVJId6Knkw6TTtFk5Dqdo6CujyVsOIznbL7W/hCqrNys7xcFTrrPouzLK9IS70cFxNTB27qi+h8pg4yaQr6QhqUK1VoefotMYac8LShSzp64QpuVtQ9vvE+W+bk2yU+UT3Yjjo+wvVrwWoI5lkb4IaFjRBjHs6jkigZ9+NwfFnsneBJIUgZevxNaduzZ/0yvcpijAkKKX+iNf0sCHtqKCrxU3bKX32f8RV6nSN3UBIDGmCEaCU3WMIEFdtGSgJouNn4dn7L5ObWVh7eMto4Y6ZhjELeEi2c8ZdvHvFNLj+A5SEnVs94OMawm3O61yFN8ZG34x40JRQwwwUFp/GXCRbb23JqkMUErtUJrPzGfN00BZnP2KZ6G98nBQrBkrud2NAfGIp6rqc+Vtn17lwI1R5NkL9eF/oTRkv6G5JKzmhDkFyx+jw2rjfPFzOgYJBVenr5kl2pGzaavn/kDYuZFBi3kCCX4h+/BB6aoRKVk3jEXH1jNBcVwkK7VtUULRFm9WtWwz2vlFENkuYbMIpV9ReHwtUrv8zk4SqcP3XVrIABykOUvYtQI0smlcWU7xgGUT24c0bE9AuuWueOls3TaQe6Mnfv5N1dim28iqjRXCx13mB7Kyxe6fKYsiZ+Rc/GyWwEqzJAOoWaXmi51KTnwJGfa07kKysoA/fUzD2xP3VEWseMlDE7zU8MGXHbGm+xUI8diXhSCm/mRc3SXbeJZ4x46bCcF/bw4igLxMmK5o88jqQfoyGHff43c48MIbiKObGdxE+ooM92uFk9Hizco/WajJN5tCorFvIHUMHxoEJ2ZDJRuNXaUf8orOjfpJ2eUADXDrC1aQe5wnZ5Qko/nWi/1y4BQpqHGG3O+hKgE7kNS4hNNoWRaWH5sXIyK/Tvl+8LxtXsbeE/7kGh6tJOsaPzyGuC2OPSORZREeE66xt3EMS0uLRoAkx8q+f+XcUXEHexvNSvmtoDuZa8VI60P8F5u+ROrhnrajo1J8Oj2u2zMV4QsMk1V93GlIPmEQgnjU1Rg7Btixy7mq7PoCdff/NljSevhTJyDcLXbhb2Wdh4c4WlGMlf3EcprU/TW0DzE5qBASKghFpx5d7UoRKq/DHq2NBiLiUCY8RavrA/1ETtXM5cEw6T4aeUrwd1xGv1Fe+YRU1wFGoaRtVKyZltR3VNI1crZQeK0vz2KA7JRCFVWXAvTcurzmleUFUVUtmIGziMHmuCGz8YRqLOgtwywnnDc9/qgCrNALv/4H3ud9NOeQjPjXvcZz22hHqLQqchGaq30Ktnxi9zLEk8egoEII7h03qdrtdlUJHyA3s9NFUgPkVF+C16+DZYhveD2UYhYh4t/G/AvH/r3ofLcBYM85N49Ik2xaDofDqhwOuPPp+Hn3hMBsVuvG+cm9YaasoXZxT8ubuANeOHcdlUxlRgJmPe+itis+4yzP8BL1uDZYfpH4cFs8Rjd6/OcgPQeQBKOJh1SJE5ZBewgdRBnm02cK2SysNx9xtrB39QG6jbrGXfUyv4lzWACs3MgSmtKndiKpZ1M5zvlcekDjWVbiJFH8eyj1HnYLAPHe2lJHuHsuRikvd2rHpDp7V9xqlfRxydqDDcRRUqia7QSMtCu+E1szC/GZ2Pis75SZQbon4nMkyDwXlUwH/kSkriw5l8s70aXj1FvQWxMfzsX6HV2Xv6oxr7Co3dGPecKv9QpHTQiWela+1WhjGZyHLEvwn1F2zkkc1HKfbKTeqmdLnWFeuMC6YBiGdMR4Butsjq/QTI/BXwz0c/I9TOG/Stfgt38NsgPCNhAJkA88SzcL+HBp+9MH083NwHDRBvheclvX01b3av51O/RphwiYACHDobNUF3U5tp6+6Js63YrZpZbCAUb1iHV+wPTpDhBScYMN2nhPnTZ/wBZnwqHUGdNtyPToUA93p39y2yLQBfrZF3Rrg6ODbKoXD4vV4zR5Ea657fJJxnd8XdQY8OmnErbCBIIKPXjdbjF811Jrc5pD9sgl6M0cu8VYZy/ZTc2MzgTEGlZV5AK4vQ3loNo+WxE1cE1xlIa0Kgv1Z5ssZFLwoYZ+ZzEWflHJY1mc+Z0AGfxqyAwMqTCztBmBBa+vhDXCHLlQ9zPw1OKIoZm/Igq2fQTAZWDRJusTpwjaoLlQr7QSe9uSK3Q2UxjTycyCC9gZN57yqdDy9h1M8Pw4+9xZ8+/Ly4Pv0/pz+d4v+d/XL00+n5n09Pz0/fUgKmn8OfN2ef4e8HjOQSliqkU81tmXeHp9Cgv/w2vKaDi34K26kBOYkZ4mnSG9Kp0xsKk579/uGLw5cHzw9fDKUdz5ArH8xh0Rs1yklJ4GdI4jm41+5ZllASxszJcP5kdXOXD6mn2B9wtxGmYQoQ7fA2vAmvaK9fhnfhefgp/DYUqi4wONvrvGLMmYtCLLNet6ZdnN8VviLrKowCy9zbvjB0cYKwsJVn0ReMSy/2psEylQkLzb0xTM3dEVlUb8SRnf68o42qY5FuZqW/E2akVkon6me4oPW4UBvB8eaGYk6Z334W9nA2Wtt60/rDSIZt0TFBNvWiZfzNKFVoPABgEgdAwLxaWSoauDKadgYOyXTzD4eSWj68VN/Jm7VshZlAMsGteWrwG5JFkZB/Pye4D1uXFISa0Q6ctnne+c61NN0LNh5hvWCjX0xt1Tea1TbNt4SbdvE6NTBVlrcPujYa8wfkf+ebk5d6LRz7l5o4ZKYJP4BdA9YovG+3w0boRZfRF+Z4q2azbwz1w+1/eaQ+H2oQnra0A52ZxP3h4b9NYku/4r7TQXS7P8bz5Vpc+YE7CC8FM7KtyXxpQ6N1pb8R2AiLfd0F3Gr/klnr89PuRl3nr4gdv5JqYzfRA5GwATC82WxwtRkgaRL+K4F9vdLt+jmlsYuQJaq84nFtNm27B0OrG7WDmG8qYLcLclwsvIkyCG00mDmBZXKvUyOqsX0EKMsuZy0yPTYJzKM1KrzZ27vtkVoANrMS4v0jdRaIW14N27bWypeejkvmMXpqXZYWf8T66nGhvhDdlg2i2zza7/Xgdo3/xtFRXfApmJK6Qq666Tdq0g5FsBtGOq/YmfYzms37hkotJkuRo8YH1XvV25NHIAaU188g1fB36+pa+tfGoAQL1qjL9ZR7kwkP/Qb1nz2MarA0bYIQ4g2epCmr1W8QiCqgVzrQUfnvaZfkpNs0taFwN0o20SOPC7aBvyJiOkwa51vXPpbrZeuWmhN36bdqU0TTAu4GR4Cuwkuf1jpnYRZ/QD19mJ0cIG+DrSLFYLoQeoeRuif8hzrsEX/6n9o16IHDvj7UHXKQ4HpG1Br7nG0xDOPGiratlG0AWZjmi+Qi0HpgX6/7/M0fJWgFcw2XcY1ivuA1cz5SGDbUjVFaZj7xbzNrsw0Q2e05qT9/J87nbw+3P44FwYRuhkgHpKunRnAL9PhThElXaWq0h5LLP6eVY2v36m4ghitjM28cu4lhHzO5sSn3kPeh38Bqu467esKrKHF9jmcrKeefW3qvXKov3eM5QtJkydOfRp+g6aqpqTKNVIKzO2pAcrfzt3dvf6mqJQ+9Osy6Odz3fO9P55+9MOFewfMMXZzc055mz/emh1LK/cR3/CFQBHKKUi7zjHn2wdi5sCjcswxxbYs8nn2aFunSPTJDl+UXaJ72iHwnt0QrJTWEWEXSFfThol9bU+R28gy7jNKtk6H3AAz0RdHH1bTQokufpIdtJTOvlo5Wa4ukSrwgjbb3yXzsrNd4tUeAYHjWdH7/28e3DiLfNHF0ZC2VcK6LZI7v1PTDDn4geSpS264efV96EpI9GKEl+IZteDAuawVd+2jI9coBAb6gAimK8Rof55laAWpIwbDuhZqrmQpj5Efsl5mpgy7LW+lYQzeDMNsbY9jxMQownZUhm+QFmXLTWGi+r7gDu8qIBFQFFCWnIikv+bLFHxHRD+vNm3m6tZ70ST3OvOlQOet1vqTYGdy7pIqZk0e9YX4sxjvM4bL7kI3zic90HDilri9qQFc8PO8LNDivrab0YigawlAnXMvPueVdq7dew2JImApAuqZRwDQKNY0CppGNi4neeQ4HibNnEtpR7zUxYyK3AcUJz5xqiOjKFGWUy+WCO8SX0W5QC41YCOnWG0guLN5NCieNwY1HyYZGWVNQaxxyDfmGiB8NedED7ifiXr4MHjZsWGjZK2NJwG8y+1XlCPDk4cpIi9AFON2u0aF3IeI8pFI+XgXDskV2ramImVRizCTsAgPdCsnf756ngQ1CfmCNm80uigDySkfeUv1LUG0Q2dZAmfUE3By80KeTsukUYjopTofhVFTUsKamze+iSw3YLpwQOimPfL+ARWkqQ2ujD55ZGBdjuJcAH4ZsINxLcOm8CUUiomnM51FhvXPJhOa5ff/Mmmiqe0m1FcBwFDiPTCxBQVG4xBhPFwsxwrJ+yzW7EzYLTtDhUUwTPmfHZFQ4DlLY6V+m9Nz/Ow2WzJPYcdZm+U6z1yZ+ivDIJi18LWMjnHm7uyLeyV1cZOYXJ1A8SadRpksdnTs8Lwr0ZYDvVig4RMU3o3MVME/1lWAd65O8qDjfQ6rrIr/byTa6UMi0rTKBFRjLA2zFA7T7gWKblAN95XmgOIxiBJ/OtyZBFlh1OCvw8Ylfu+HPlbthxpIx/6KtxKBUz1iQlXKYRHr3GXSfLmC4Bsnnz7lIplAdfpYgEIgO2XEA8TgHzs5stJKuZHYSZxiDisgt13TiUxTiYtr3cuYDc1PzO/zYe+a1kYRGlSlENqZqb15A0R/gdKNIJslsh5Xa8X5oJ+0fvB/YsYPDBYycfc51rbaxlj5hNNtI0laKgvRmXaYqVX5KKs7MiSGju0Lu6p//0TRaK31pHStbm570A12p0YzYE2V9xHqSAfgBWg9hyoj+VQNiptB86IPt4INDJ647R+DnI0dWQE1TERROA7yV0JWBIJAqBUygGqKaTYQkcglYSFNisz98sFWFiOG2kd+x9wTXUU2EW+dCuXUGEg23CwnIQUHu+TA2BZ58LEhFhXdxuUwscRIV6GKZNAf+gn5hUQaBCs8JgVcW6uplmO8/BaKEwhHBRLloCG6ykhBEjRRGDqV5upkGJpy3dyuGmDFX/ooQCVe3G82AkjMvNOYGV+jO5cEbi3vhABR42SlgMAhxC7vtPvUC1OkAK3KvxFnDQO1AkiYFq4MqU1TZ6Btu5iHG9VTUmYrhuRblYp3w9KUTC5XRnSrrp8sl09OLYutc/87z3IrvZx7vJNFxcQvfcdIvhM3QCq6IK2kZICgxzCuefo2v0EKc3IzxL3Q0pX6v+Bbf3WV/ZRbXGnjAe7nnhbkmYVgVaLnIZDOaacIXIyOco55d3s3vgOMSchpVOoQrnmZIVv50/zm+QhNZTVYjbm7XcHO7Pl6Im9s1XkCZ7dpifD0hc7WymK7XZLWmx8oqpkyO2JoFKA5Ms1XCo18tu7EoV8p+bqJeeBXdin5ujq+GN6Kv++h2fDMZ3hN9kGwnael0YBk7XsDEr346nvq8lIyk+g9ZbA9jGweT6F7sXmz7Mpp1b0gdae8ffvfH4GIPa110Lu7aweii+8/SvxitnwV7wRDjDpbR5bgPWF6SlRzqBUXsz3pd4pVLLHqLlC8w49e4uuZlIOUuR0U6nqY+UFDFSwAqizrip5ZbXcOK8Wz5W+bPEhRu7bAvCdk7DLubBpyMp+O7icWTkl9M/y7ELI3bnLqD5Xb8LobGNemGlHJV+W/LpdTzCmyrfB72MrXt9EuVgLtT2AbZGzRQFAL4C77/o4p44ZxLn92q3+s1nz8z8LEgwBI3TMVXLOIAtU7kEg1IciCWZMBtQPgKsE+x3APYsuVqPk+/DTxAIC98xujTb8WixMt9TeTLKEmMlmkf7jIUHiVFRRGmOfstWX3vt+xrBrt6hwFkBwj1YAdjDwsuKIZTY8M8nUY1tvEPdhFzAUHVdUfdLfRY3DHd1XDmCTIdIeoXcCDUBxZ3NRCh1EPMxkqXahI85OIeys8jdN83FrKlzj6cp54QgVbItGQpoCScEyMoP/A6HspRVPk+i5cGBdlie/SaA8VkBDUADQsj7Xv/8NpV2xtfXHS+TNbsD6U8gwMFXxpRrCx2Skmh1P1WCvsTmXRkdXkMFdS5NgaxPxGPOfEYmkMs8iRnmzPdlhFkSpIywDHuISdWRQWFPiWCz+RunX7Q4
