<?php
namespace FusionAuth;

use Jose\Component\Core\JWKSet;

class OidcClient
{
  /**
   * @var string
   */
  protected $clientId;
  /**
   * @var string
   */
  protected $clientSecret;
  /**
   * @var string
   */
  protected $redirectUri;

  /**
   * @var string
   */
  protected $baseURL;

  /**
   * @var int
   */
  public $connectTimeout = 2000;
  /**
   * @var int
   */
  public $readTimeout  = 2000;
  /**
   * @var mixed
   */
  public $openidConfiguration = false;
  


	
  public function __construct(array $options)
  {
  	  $this->cache = new OpenIdConnect\Cache(); 
	  
	  
	  
	  if( array_key_exists('openidProvider',$options)){
		  $this->openIdDiscovery($options['openidProvider']);
	  }else{
		  throw new \Exception("No openidprovider specified.");
	  }
	  if( array_key_exists('clientId',$options) ){
		  $this->setClientId($options['clientId']);
	  }
	  if( array_key_exists('clientSecret',$options) ){
		  $this->setClientSecret($options['clientSecret']);
	  }
	  
	  if( array_key_exists('redirectUrl',$options) ){
		  $this->setredirectUri($options['redirectUrl']);
	  }
	  
	  if( array_key_exists('cache',$options) ){
		  //$this->cache = $cache; 
	  }
	  
	  
  }
  public function validate($token){
	  return new Jwt\Helper($token,$this->jwkset,$this->openidConfiguration);
  }
  // AuthorizationCode Grant Request	
  public function AuthorizationCodeGrantRequest($state="", array $extrascopes = array()){
	  
	  if($state==""){
		  $state = time();
	  }
	  
	  $scopes = array_merge( $extrascopes,array("openid"));
	  $option = array(
		  "client_id"=>$this->clientId,
		  "redirect_uri"=>$this->redirectUri,
		  "nonce"=>1,
		  "state"=>$state,
		  "response_type"=>"code",
		  "scope"=>implode(" ",$scopes)
	  );
	  
	  return $this->openidConfiguration->authorization_endpoint."?".http_build_query($option);
  }	
	

  
  public function setClientId($clientId){
	  $this->clientId = $clientId;
  }
  public function setClientSecret($clientSecret){
	  $this->clientSecret = $clientSecret;
  }  	
  public function setredirectUri($redirectUri){
	  $this->redirectUri = $redirectUri;
  }  	

  /**
   * Attempts to get autodiscovery information for the provided authserver.
   *
   * @return Object The Response.
   * @throws \Exception
   */
  public function openIdDiscovery ($openIdDiscoveryUrl){
	  
	  // create hash from discovery uri for caching
	  $idp_provider = hash('md5',$openIdDiscoveryUrl);
	  
	  if( $this->cache->exists($idp_provider)){
		  // get the configuration
		  #
		  $this->openidConfiguration = json_decode($this->cache->get($idp_provider));
		  
		  $this->jwks($this->openidConfiguration->jwks_uri);
	  	  return $this->openidConfiguration;		  
	  }
	  
	  

	  
	  
	  $urlParts = parse_url($openIdDiscoveryUrl);
	  if( strtolower($urlParts['scheme'])!="https" ){
		  throw new OpenIdConnect\InsecureConnectionException("Discovery not secure.");
	  }
	  if(!array_key_exists('path',$urlParts)){
		 // only domain. 
		 $urlParts['path']="/.well-known/openid-configuration"; 
	  }
	  unset($urlParts['scheme']);
	  $url = 'https://'.implode("",$urlParts);

	  
	  $req = $this->getOpenidConfiguration($urlParts);  
	  if($req->status!=200){
		  throw new OpenIdConnect\AutoDiscoveryException("Server returned status ".$req->status);
	  }
	  $this->openidConfiguration =  $req->successResponse;  
	  
	  
	  $this->jwks($this->openidConfiguration->jwks_uri);
	  
	  return $this->openidConfiguration;	  
  }
	
  /**
   * Gets the openid configuration..
   * @param array parse_url results of the discoveryUrl.
   *
   * @return Object
   * @throws \Exception
   */	
  private function getOpenidConfiguration($urlParts){
	  // Construct the baseUrl.
	  $baseUrl = 'https://'.$urlParts['host'];
	  if(array_key_exists('port',$urlParts) ){
		  $baseUrl .= ':'.$urlParts['port'];
	  }
	  
	  $rest = new RestClient\RESTClient();
	  return $rest->url($baseUrl)
        ->connectTimeout($this->connectTimeout)
        ->readTimeout($this->readTimeout)
        ->successResponseHandler(new RestClient\JSONResponseHandler())
        ->errorResponseHandler(new RestClient\JSONResponseHandler())
		->uri($urlParts['path'])
		->get()
		->go();
  }	
  
  /**
   * Gets the jwks from the openid configuration..
   *
   *
   * @return Object
   * @throws \Exception
   */	
  public function jwks($jwks_uri){
	  
	  $idp_provider_jwks = hash('md5',$jwks_uri);
	  if( $this->cache->exists($idp_provider_jwks)){
		  $this->jwks = json_decode($this->cache->get($idp_provider_jwks),true);
		  $this->jwkset = JWKSet::createFromKeyData($this->jwks);
	  
		  return $this->jwks;
	  }

	  $req =  $this->getJWKS($jwks_uri);
	  if($req->status!=200){
		  throw new OpenIdConnect\JsonWebKeySetException($req->errorResponse);
	  }
	  
	  $this->jwks =  (array)$req->successResponse; 
	  $this->cache->set($idp_provider_jwks,json_encode($this->jwks));
	
	  $this->jwkset = JWKSet::createFromKeyData($this->jwks);
	  
	  return $this->jwks;
  }	
	
  /**
   * Gets the jwks from the openid configuration..
   *
   * @param string $url The url of the jwks.
   *
   * @return ClientResponse The ClientResponse.
   * @throws \Exception
   */	
  private function getJWKS($url){
	$rest = new RestClient\RESTClient();
    return $rest->url($this->baseURL)
        ->connectTimeout($this->connectTimeout)
        ->readTimeout($this->readTimeout)
        ->successResponseHandler(new RestClient\JSONResponseHandler(true))
        ->errorResponseHandler(new RestClient\JSONResponseHandler())
		->url($url)
		->get()
		->go();
  }
	
	
	
	
  public function getTokenFromCode($code){
	  
	  $request=array(
		  "grant_type"=>"authorization_code",
		  "code"=>$code,
		  "redirect_uri"=>$this->redirectUri
	  );
	  
	  $rest = new RestClient\RESTClient();

	  
      $req =  $rest->basicAuthorization($this->clientId,$this->clientSecret)
        ->url($this->openidConfiguration->token_endpoint)
        ->connectTimeout($this->connectTimeout)
        ->readTimeout($this->readTimeout)
        ->successResponseHandler(new RestClient\JSONResponseHandler())
        ->errorResponseHandler(new RestClient\JSONResponseHandler())
		->bodyHandler(new RestClient\RAWBodyHandler($request))
		->post()
		->go();
	  
	  if($req->status!=200){
		  throw new OpenIdConnect\AuthorizationCodeException($req->errorResponse->error_description);
	  }
	  return $req->successResponse; 
  }
	

	
  
	
  protected function tokenAuth()
  {
    $rest = new RestClient\RESTClient();
    return $rest->authorization($this->apiKey)
        ->url($this->baseURL)
        ->connectTimeout($this->connectTimeout)
        ->readTimeout($this->readTimeout)
        ->successResponseHandler(new RestClient\JSONResponseHandler())
        ->errorResponseHandler(new RestClient\JSONResponseHandler());
  }
	

}


