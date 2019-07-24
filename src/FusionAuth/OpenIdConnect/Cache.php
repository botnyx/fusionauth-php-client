<?php

namespace FusionAuth\OpenIdConnect;

class Cache 
{
	static function exists($hash){
		return file_exists(sys_get_temp_dir()."/".$hash);
	}
	
	static function get($hash){
		$fp = fopen(sys_get_temp_dir()."/".$hash, 'r');
		$contents = fread($fp, filesize(sys_get_temp_dir()."/".$hash));
		fclose($fp);
		return $contents;
	}
	
	static function set($hash,$data){
		$fp = fopen(sys_get_temp_dir()."/".$hash, 'w');
		fwrite($fp, $data);
		fclose($fp);
	}
}