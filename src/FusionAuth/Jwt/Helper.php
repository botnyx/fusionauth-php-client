<?php

namespace FusionAuth\Jwt;


use Jose\Component\Core\JWK;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;

use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;

use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;

use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Core\JWKSet;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker;



class Helper{
	
	public function __construct( $token, $jwkset=false, $discovery=false ){
		/* The token */
		$this->token = $token;
		
		if($jwkset!=false){
			$this->key = $jwkset;
		}
		if($discovery!=false){
			$this->algs =$discovery->id_token_signing_alg_values_supported;
			$this->iss =array($discovery->issuer);
			
		}
		$this->exp = true;
		$this->iat = true;
	}
	
	public function algs(array $algs){
		/* The supported algoritms */
		$this->algs = $algs;
		return $this;
	}
	public function exp(array $exp=array()){
		if( count($exp)==0 ){
			$this->exp = true;
		}else{
			$this->exp = $exp;
		}
		return $this;
	}	
	public function iat(int $iat=0){
		/* The Issued At claim.  leeway in seconds */
		if( $iat==0 ){
			$this->iat = true;
		}else{
			$this->iat = $iat;
		}
		
		return $this;
	}	

	public function aud( $aud ){
		if( is_string($aud)){
			$this->aud = $aud;
		}
		
		return $this;
	}
	public function iss( $iss){
		if( is_string($iss) ){
			$this->iss = array($iss);
		}elseif( is_array($iss) ){
			$this->iss = $iss;
		}
		
		return $this;
	}	
	public function sub( $sub){
		#if( ){
			
		#}else{
			
		#}
		$this->sub = $sub;
		return $this;
	}

	public function key(JWKSet $key){
		$this->key = $key;
		return $this;
	}	
	
	
	
	public function run(){
		
		if(property_exists($this,'algs')){
			
			$algorythms=array();
			foreach($this->algs as $alg){
				$alg = "Jose\\Component\\Signature\\Algorithm\\".strtoupper($alg);
				$algorythms[]= new $alg();
			}
						
			$algorithmManager = new AlgorithmManager( $algorythms );
			// We instantiate our JWS Verifier.
			$jwsVerifier = new JWSVerifier( $algorithmManager );	
		}else{
			throw new \Exception('Missing algo');
		}
		
		
		$claimchecks = array();
		if(property_exists($this,'iat')){
			if(is_bool($this->iat)){
				$claimchecks[] = new Checker\IssuedAtChecker(); 
			}else{
				$claimchecks[] = new Checker\IssuedAtChecker($this->iat); /* 1000 ms leeway*/
			}
			$claimcheck[]='iat';
			
		}
		if(property_exists($this,'exp')){
			if(is_bool($this->exp)){
				$claimchecks[] =  new Checker\ExpirationTimeChecker();
			}else{
				$claimchecks[] =  new Checker\ExpirationTimeChecker($allowedTimeDrift=0);
			}
			
			$claimcheck[]='exp';
		}
		if(property_exists($this,'aud')){
			$claimchecks[] = new Checker\AudienceChecker($this->aud);
			
			$claimcheck[]='aud';
		}
		if(property_exists($this,'iss')){
			
			if(is_string($this->iss)){
				$claimchecks[] = new Checker\IssuerChecker($this->iss);
			}elseif(is_array($this->iss)){
				$claimchecks[] = new Checker\IssuerChecker($this->iss);
			}
			
			$claimcheck[]='iss';
		}
		
		
		if(property_exists($this,'key')){
			
		}

		$claimCheckerManager = new ClaimCheckerManager($claimchecks);
		
		
		
		// The serializer manager. We only use the JWS Compact Serialization Mode.
		$serializerManager =  new JWSSerializerManager([new CompactSerializer()]);
		
		// We try to load the token.
		$jws = $serializerManager->unserialize($this->token);
		
		
		$isVerified = $jwsVerifier->verifyWithKeySet($jws,  $this->key, 0, null, $jwk );

		if(!$isVerified){
			throw new \Exception("Token not verified");
		}
		
		$this->payload =json_decode($jws->getPayload(), true);

		
		$r = $claimCheckerManager->check($this->payload, $claimcheck);	

		$this->verifiedClaims = $r;	

		
		return $this;
	}
}

