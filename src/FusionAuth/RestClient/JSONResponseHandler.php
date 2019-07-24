<?php
namespace FusionAuth\RestClient;




class JSONResponseHandler implements ResponseHandlerInterface
{
  var $jsonAssoc = false;
	
  public function __construct($jsonAssoc=false){
	  $this->jsonAssoc = $jsonAssoc;
  }
	
  public function call(&$response)
  {
    return json_decode($response,$this->jsonAssoc);
  }
}


interface ResponseHandlerInterface
{
  public function __construct($jsonAssoc);
  /**
   * Handles the HTTP response.
   *
   * @param string $response The HTTP response as a String.
   * @return mixed The response as an object.
   */
  public function call(&$response);
}