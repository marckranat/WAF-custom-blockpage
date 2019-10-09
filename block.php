<html>
  <head>
    <title>403 Block Message</title>
  </head>
  <body>
	  <h1 style="text-align: center;">⛔&nbsp;<strong>You've been blocked</strong>&nbsp;⛔</h1>
<h2 style="text-align: center;">if your intent is malicious, you can ignore this message,<br />if you are wrongly being blocked, please email me the 4 lines below to marc(at)kranat(dot)com</h2>
<p style="text-align: center;">If you are unsure which is which, malicious would be attempting to harm this site or its users,<br />be deceptive or fraudulent to same, or attempting to hijack this site to try and take over the world.</p>
<p style="text-align: center;">But mistakes do happen.</p>
<p></p>
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

  </body>
</html>
