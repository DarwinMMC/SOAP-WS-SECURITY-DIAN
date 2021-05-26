<?php

class EnvelopeSoap{

    protected $signedinfo;
    protected $privateKey;
    protected $XML_SOAP;
    protected $soap;
    protected $to;

    protected $id = [
        'BinarySecurityToken' => 'BIN',
        'ID' => 'ID',
    ];

    const ADDRESSING = 'http://www.w3.org/2005/08/addressing';
    const SOAP_ENVELOPE = 'http://www.w3.org/2003/05/soap-envelope';
    const DIAN = 'http://wcf.dian.colombia';
    const XMLDSIG = 'http://www.w3.org/2000/09/xmldsig#';
    const WS_WSSECURITY = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    const WS_WSSECURITY_UTILITY = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const X509V3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    const BASE64BINARY = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';
    
    public function __construct($pathCertificate = null, $password = null, $xmlString = null,$wsaAction_method = null){
        $certificado = $this->get_certificado($pathCertificate,$password);
        $this->setUUID();
        $this->soap = $this->enveloped_soap($xmlString,$wsaAction_method,$certificado);
    }
   
    private function setUUID()
    {
        foreach ($this->id as $key => $value) {
            $this->id[$key] = mb_strtoupper("{$value}-".sha1(uniqid()));
        }
    }

    private function get_certificado($pathCertificate,$password)
    {
        $certs = null;
        openssl_pkcs12_read(file_get_contents($pathCertificate), $certs, $password);
        openssl_x509_export($certs['cert'], $stringCert);
        $stringCert = str_replace(["\r", "\n", '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $stringCert);
        $this->privateKey = $certs["pkey"];
            
        return $stringCert;
    }

    public function Digest_to(){
       $this->to = '<wsa:To xmlns:soap="'.self::SOAP_ENVELOPE.'" xmlns:wcf="'.self::DIAN.'" xmlns:wsa="'.self::ADDRESSING.'" xmlns:wsu="'.self::WS_WSSECURITY_UTILITY.'" wsu:Id="'.$this->id['ID'].'" >https://vpfe-hab.dian.gov.co/WcfDianCustomerServices.svc</wsa:To>';
       $dom = new DOMDocument(); 
       $dom->loadXML($this->to);
       return base64_encode(hash('sha256',$dom->C14N(),true));
    }

    public function signature(){
        $hash = $this->Digest_to();

        $signedinfo_SIG =  '<ds:SignedInfo xmlns:ds="'.self::XMLDSIG.'" xmlns:wsa="'.self::ADDRESSING.'" xmlns:soap="'.self::SOAP_ENVELOPE.'" xmlns:wcf="'.self::DIAN.'">'.
                            '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'">'.
                                '<ec:InclusiveNamespaces xmlns:ec="'.self::EXC_C14N.'" PrefixList="wsa soap wcf"/>'.
                            '</ds:CanonicalizationMethod>'.
                            '<ds:SignatureMethod Algorithm="'.self::RSA_SHA256.'"/>'.
                            '<ds:Reference URI="#'.$this->id['ID'].'">'.
                                '<ds:Transforms>'.
                                    '<ds:Transform Algorithm="'.self::EXC_C14N.'">'.
                                        '<ec:InclusiveNamespaces PrefixList="soap wcf" xmlns:ec="'.self::EXC_C14N.'"/>'.
                                    '</ds:Transform>'.
                                '</ds:Transforms>'.
                                '<ds:DigestMethod Algorithm="'.self::SHA256.'"/>'.
                                '<ds:DigestValue>'.$hash.'</ds:DigestValue>'.
                            '</ds:Reference>'.
                        '</ds:SignedInfo>';

        $DOM = new DOMDocument();
        $DOM->loadXML($signedinfo_SIG);
                   
        openssl_sign($DOM->C14N(), $signatureResult, $this->privateKey, "SHA256");
        $signatureValue = base64_encode($signatureResult);

        $this->signedinfo = str_replace('<ds:SignedInfo xmlns:ds="'.self::XMLDSIG.'" xmlns:wsa="'.self::ADDRESSING.'" xmlns:soap="'.self::SOAP_ENVELOPE.'" xmlns:wcf="'.self::DIAN.'">',"<ds:SignedInfo>",$signedinfo_SIG);

        return $signatureValue;
    }


    public function enveloped_soap($xmlString,$method,$certificado){

        $Time = time();
        $firma = $this->signature();

        $this->XML_SOAP = '<soap:Envelope xmlns:soap="'.self::SOAP_ENVELOPE.'" xmlns:wcf="'.self::DIAN.'">'.
                                '<soap:Header xmlns:wsa="'.self::ADDRESSING.'">'.
                                    '<wsse:Security xmlns:wsse="'.self::WS_WSSECURITY.'" xmlns:wsu="'.self::WS_WSSECURITY_UTILITY.'">'.
                                        '<wsu:Timestamp>'.
                                            '<wsu:Created>'.gmdate("Y-m-d\TH:i:s\Z", $Time).'</wsu:Created>'.
                                            '<wsu:Expires>'.gmdate("Y-m-d\TH:i:s\Z", $Time +  60000).'</wsu:Expires>'.
                                        '</wsu:Timestamp>'.
                                        '<wsse:BinarySecurityToken EncodingType="'.self::BASE64BINARY.'" ValueType="'.self::X509V3.'" wsu:Id="'.$this->id['BinarySecurityToken'].'">'.$certificado.'</wsse:BinarySecurityToken>'.
                                        '<ds:Signature xmlns:ds="'.self::XMLDSIG.'">'.
                                        
                                            $this->signedinfo.
                
                                            '<ds:SignatureValue>'.$firma.'</ds:SignatureValue>'.
            
                                            '<ds:KeyInfo>'.
                                                '<wsse:SecurityTokenReference>'.
                                                    '<wsse:Reference URI="#'.$this->id['BinarySecurityToken'].'" ValueType="'.self::X509V3.'"/>'.
                                                '</wsse:SecurityTokenReference>'.
                                            '</ds:KeyInfo>'.
                                        '</ds:Signature>'.
                                    '</wsse:Security>'.
        
                                    '<wsa:Action>http://wcf.dian.colombia/IWcfDianCustomerServices/'.$method.'</wsa:Action>'.
                                    $this->to.
                                    '</soap:Header>'.
                                        $xmlString.
                                    '</soap:Envelope>'
                                ;
        return $this->XML_SOAP;
    }

    public function get_soap(){
        return $this->soap;
    }

   
}


?>