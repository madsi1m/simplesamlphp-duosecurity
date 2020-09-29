<?php
/**
 * Duo Security Authentication Processing filter
 *
 * Filter to present Duo two factor authentication form
 *
 * @package simpleSAMLphp
 */
class sspmod_duosecurity_Auth_Process_Duosecurity extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * Include attribute values
     *
     * @var bool
     */
    private $_includeValues = false;

    private $_duoComplete = null;

    private $_enabled = true;

    private $_akey;

    private $_ikey;

    private $_skey;

    private $_host;

    private $_authSources = "all";

    private $_usernameAttribute = "username";
    private $_sourceipattribute = "HTTP_X_FORWARDED_FOR";
    private $_url;
    private $_userpass;
    private $_useragent;
    private $_action;

    /**
     * Initialize Duo Security 
     *
     * Validates and parses the configuration
     *
     * @param array $config   Configuration information
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('enabled', $config)) {
            $this->_enabled = $config['enabled'];
        }

        $this->_host = $config['host'];
        $this->_akey = $config['akey'];
        $this->_ikey = $config['ikey'];
        $this->_skey = $config['skey'];

        if (array_key_exists('authSources', $config)) {
            $this->_authSources = $config['authSources'];
        }
        if (array_key_exists('usernameAttribute', $config)) {
            $this->_usernameAttribute = $config['usernameAttribute'];
        }
        if (array_key_exists('sourceipattribute', $config)) {
            $this->_sourceipattribute = $config['sourceipattribute'];
        }
        if (array_key_exists('url', $config)) {
            $this->_url = $config['url'];
        }
        if (array_key_exists('userpass', $config)) {
            $this->_userpass = $config['userpass'];
        }
        if (array_key_exists('useragent', $config)) {
            $this->_useragent = $config['useragent'];
        }
        if (array_key_exists('action', $config)) {
            $this->_action = $config['action'];
        }
    }

    private function auditlog($uid, $message) {
      $data = array(
        'message' => $message,
        'action' => $this->_action,
        'sourceip' => $_SERVER[$this->_sourceipattribute],
      );
      $ch = curl_init($this->_url.'/'.$uid);
      $postString = http_build_query($data, '', '&');
      curl_setopt($ch, CURLOPT_USERPWD, $this->_userpass);
      curl_setopt($ch, CURLOPT_USERAGENT, $this->useragent);
      curl_setopt($ch, CURLOPT_POST, 1);
      curl_setopt($ch, CURLOPT_POSTFIELDS, $postString);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      $response = curl_exec($ch);
      curl_close($ch);
      $xml = simplexml_load_string($response);
      \SimpleSAML\Logger::debug("auditlogmessage: xml = ".print_r($xml,true));
      if ($xml !== false && isSet($xml->meta->status) && $xml->meta->status == 'ok') {
        \SimpleSAML\Logger::debug("auditlogmessage: logged \"$message\" for \"$uid\"");
      } else {
        throw new \Exception("Can not log to SDS Audit");
      }
    }

    /**
     * Helper function to check whether Duo is disabled.
     *
     * @param mixed $option  The consent.disable option. Either an array or a boolean.
     * @param string $entityIdD  The entityID of the SP/IdP.
     * @return boolean  TRUE if disabled, FALSE if not.
     */
    private static function checkDisable($option, $entityId) {
        if (is_array($option)) {
            return in_array($entityId, $option, TRUE);
        } else {
            return (boolean)$option;
        }
    }

    /**
     * Process a authentication response
     *
     * This function saves the state, and redirects the user to the page where
     * the user can log in with their second factor.
     *
     * @param array &$state The state of the response.
     *
     * @return void
     */
    public function process(&$state)
    {
        assert('is_array($state)');
        assert('array_key_exists("Destination", $state)');
        assert('array_key_exists("entityid", $state["Destination"])');
        assert('array_key_exists("metadata-set", $state["Destination"])');		
        assert('array_key_exists("Source", $state)');
        assert('array_key_exists("entityid", $state["Source"])');
        assert('array_key_exists("metadata-set", $state["Source"])');

        $attributes = &$state['Attributes'];
        $uid = $attributes[$this->_usernameAttribute];
        # Just in case there is multiple values for the attribute
        if (is_array($uid)) {
            $uid = $uid[0];
        }
        $uid = strtolower($uid);

        // Bypass DUO if it is not enabled in config
        if (!$this->_enabled) {
            $this->auditlog($uid, 'User: '.$uid.' is bypassing DUO because DUO is not enabled');
            return;
        }

        $spEntityId = $state['Destination']['entityid'];
        $idpEntityId = $state['Source']['entityid'];

        $metadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();

        /**
         * If the Duo Security module is active on a bridge $state['saml:sp:IdP']
         * will contain an entry id for the remote IdP. If not, then
         * it is active on a local IdP and nothing needs to be
         * done.
         */
        if (isset($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            $idpmeta         = $metadata->getMetaData($idpEntityId, 'saml20-idp-remote');
            $state['Source'] = $idpmeta;
        }

        // Get idP session from auth request
        $session = SimpleSAML_Session::getSessionFromRequest();

        // Has user already passed DUO authorization in this idP session instance?
        $isAuthorized = $session->getData('duosecurity:request', 'is_authorized');

        // Bypass DUO if already authenticated with the idP and DUO
        if (isset($state['AuthnInstant']) && $isAuthorized) {
            $this->auditlog($uid, 'User: '.$uid.' is bypassing DUO because user is already authenticated with DUO');
            return;
        }

        $session->setData('duosecurity:request', 'is_authorized', false);

        // Set Keys for Duo SDK
        $state['duosecurity:akey'] = $this->_akey;
        $state['duosecurity:ikey'] = $this->_ikey;
        $state['duosecurity:skey'] = $this->_skey;
        $state['duosecurity:host'] = $this->_host;
        $state['duosecurity:authSources'] = $this->_authSources;
        $state['duosecurity:usernameAttribute'] = $this->_usernameAttribute;
        $state['duosecurity:sourceipattribute'] = $this->_sourceipattribute;

        // User interaction nessesary. Throw exception on isPassive request	
        if (isset($state['isPassive']) && $state['isPassive'] == true) {
            throw new SimpleSAML_Error_NoPassive(
                'Unable to login with passive request.'
            );
        }

        // Save state and redirect
        $id  = SimpleSAML_Auth_State::saveState($state, 'duosecurity:request');
        $url = SimpleSAML_Module::getModuleURL('duosecurity/getduo.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
    }
}
