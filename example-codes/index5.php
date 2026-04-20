<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Get input
	$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );

	// Validate URL to prevent SSRF
	$parsedUrl = parse_url($name);
	if ($parsedUrl === false || !in_array($parsedUrl['scheme'], ['http', 'https'])) {
		$name = 'http://example.com'; // default to a safe URL
	}

	// Feedback for end user
	$html .= "<pre>Hello {$name}</pre>";

	// Initialize curl with validated URL
	$ch = curl_init($name);
}
?>
