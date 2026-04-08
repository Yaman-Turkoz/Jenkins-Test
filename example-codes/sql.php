
<?php
if($_POST['submit']) {
	$sqli_db = sqlite_open(":memory:", 0666, $sqliteerror);

	sqlite_query($sqli_db, "CREATE TABLE users (userid smallint(2), username varchar(10), password varchar(30))");
	sqlite_query($sqli_db, "INSERT INTO users VALUES (1, 'admin', 'password')");
	sqlite_query($sqli_db, "INSERT INTO users VALUES (2, 'user', '12345')");

	$username = (isset($_POST['username'])) ? stripslashes( $_POST['username'] ) : '';
	$password = (isset($_POST['password'])) ? stripslashes( $_POST['password'] ) : '';

	$query  = "SELECT * FROM users WHERE username='$username' AND password='$password'";
	$output = "";

	ob_start();

	if(!$line = sqlite_array_query($sqli_db, $query, SQLITE_ASSOC)) {
		$errorstring = strip_tags(ob_get_contents());

		if(strlen($errorstring)) {
			$error = preg_match("/sqlite_array_query\(\) \[.*\]: (.*) in/", $errorstring, $m);
		}
	}

	ob_end_clean();

	echo $error ? "<p>SQL Error: {$m[1]}</p>" : '';

	if ($line) {
		echo '<p style="color:green;font-weight:bold;">CONGRATS YOU JUST WON SORRY ALL OUT OF COOKIES.</p>';
	}
	else {
		echo '<p style="color:red;font-weight:bold;">I AM SUPER SECURE.</p>';
	}

	sqlite_close($sqli_db);
}
?>
