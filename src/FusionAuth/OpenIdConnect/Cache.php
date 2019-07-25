<?php

namespace FusionAuth\OpenIdConnect;

class Cache 
{
	var $cacheLifeTime = 3600;
	
	function __construct($cacheLifeTime = 3600){
		$this->cacheLifeTime = $cacheLifeTime;
	}
	
	public function exists($hash){
		$filename = sys_get_temp_dir()."/".$hash;
		
		$fileExists = file_exists($filename);
		if(!$fileExists){
			echo "$filename File doesnt exist!<br>";
			return $fileExists;
		}
		
		$fileMtime = filectime($filename);
   		//echo "$filename was last modified: " . date ("F d Y H:i:s.", $fileMtime)."<br>";

		if (file_exists($filename)) {
			
			
			if((time()-$fileMtime)>$this->cacheLifeTime){
				unlink($filename);
				return false;
			};
		}
		return $fileExists;
	}
	
	public function get($hash){
		$fp = fopen(sys_get_temp_dir()."/".$hash, 'r');
		$contents = fread($fp, filesize(sys_get_temp_dir()."/".$hash));
		fclose($fp);
		return $contents;
	}
	
	public function set($hash,$data){
		$fp = fopen(sys_get_temp_dir()."/".$hash, 'w');
		fwrite($fp, $data);
		fclose($fp);
	}
}