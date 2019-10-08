<!DOCTYPE html>
<html><meta http-equiv=”Content-Type” content=”text/html; charset=utf-8”>
		<title>Block Message</title>
<body>
<H2> You've been blocked! if your intent is malicious, you can ignore this message, <br>if you are wrongly being blocked, please email me the 4 lines below to X(at)Y(dot)Z</H2>
	<?PHP
	function getUserIP() {
    if( array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER) && !empty($_SERVER['HTTP_X_FORWARDED_FOR']) ) {
        if (strpos($_SERVER['HTTP_X_FORWARDED_FOR'], ',')>0) {
            $addr = explode(",",$_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($addr[0]);
        } else {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
    }
    else {
        return $_SERVER['REMOTE_ADDR'];
    }
}
	
	$user_ip = getUserIP();
	echo "<br><strong>User IP: </strong>". $user_ip;
	echo " <strong>Method: </strong>".$_SERVER['REQUEST_METHOD'];
	echo "<br><strong>Event URL: </strong>". $_SERVER['HTTP_REFERER'];
	date_default_timezone_set('America/New_York');
	echo "<br><strong>Event Time: </strong>". date('Y-m-d H:i:s T', time()) . "\n";
	echo "<br><strong>User Agent: </strong>". $_SERVER['HTTP_USER_AGENT'] . "\n\n";
	$browser = get_browser(null, true);
	print_r($browser);
	
		?>
</body></html>
