<?php

/**
 * MySimpleCertViewer - a simple server certificate viewer in PHP
 *
 * T.Gries
 *
 * License: MIT/X11
 * http://www.opensource.org/licenses/mit-license.php
 *
 */
define( 'CERTVIEWER_VERSION', "1.01 20130317" );

function getCertificateInfo( $server, $port = 443, $timeout = false ) {
	$context = stream_context_create( array( 'ssl' => array(
		'capture_peer_cert' => true
	) ) );

	$timeout = $timeout ?: ini_get( "default_socket_timeout" );
	$errno = $errstr = 0;
	$fp = stream_socket_client(
		"ssl://$server:$port",
		$errno,
		$errstr,
		$timeout,
		STREAM_CLIENT_CONNECT,
		$context
	);

	$params = stream_context_get_params( $fp );
	fclose( $fp );
	$cp = $params['options']['ssl']['peer_certificate'];
	$cert = '';
	openssl_x509_export( $cp, $cert );
	$certArray = openssl_x509_parse( $cp );
	openssl_x509_free( $cp );

	$now = time();
	$certArray['x-server-port'] = "$server:$port";
	$certArray['x-server'] = $server;
	$certArray['x-port'] = $port;
	$certArray['x-retrieval-time'] = array(
		'utc' => date( "YmdHis", $now ) . "Z",
		'unix' => date( "U", $now),
	);
	$certArray['extensions']['x-subjectAltName'] = explode( ",", $certArray['extensions']['subjectAltName'] );
	$certArray['x-certificate-base64'] = $cert;
	$certArray['x-mysimplecertviewer-version'] = CERTVIEWER_VERSION;

	// Decode the certificate to get fingerprints.
	$decCert = preg_replace( '/\-+(BEGIN|END) CERTIFICATE\-+/', '', $cert );
	$decCert = str_replace( array( "\n\r", "\n", "\r" ), '', trim( $cert ) );
	$decCert = base64_decode( $cert );
	$certArray['x-fingerprints'] = array(
		"sha1" => sha1( $decCert ),
		"md5" => md5( $decCert ),
		"sha256" => hash( 'sha256', $decCert ),
	);

	return $certArray;
}
