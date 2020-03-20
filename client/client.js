
Okta = {

    serviceName: 'okta',

    // Request Okta credentials for the user
    // @param options {optional}
    // @param credentialRequestCompleteCallback {Function} Callback function to call on
    //   completion. Takes one argument, credentialToken on success, or Error on
    //   error.

    requestCredential: function (options, credentialRequestCompleteCallback) {

        // support both (options, callback) and (callback).
        if (!credentialRequestCompleteCallback && typeof options === 'function') {
            credentialRequestCompleteCallback = options;
            options = {};
        } else if (!options) {
            options = {};
        }

        // Fetch the service configuration from the database
        const config = ServiceConfiguration.configurations.findOne({service: Okta.serviceName});
        // If none exist, throw the default ServiceConfiguration error

        // Note: The code that is commented out in this block would, if there is no configuration
        // found, allow the client to define the configuration from a simple popup box. I highly
        // recommend for production releases for this code to remain inactive and to configure
        // this package safely from the meteor server 

        if (!config) {
            // credentialRequestCompleteCallback &&
            // credentialRequestCompleteCallback(new ServiceConfiguration.ConfigError());
            //return;
            throw new ServiceConfiguration.ConfigError();
        }

        // Generate a token to be used in the state and the OAuth flow
        const credentialToken = Random.secret();

        // Other option is "popup" which opens a pop up window. For my purposes, I've chosen
        // to force the redirect loginStyle regardless of configuration
        const loginStyle = "redirect";  

        OAuth.launchLogin({
            loginService: Okta.serviceName,
            loginStyle: loginStyle,
            loginUrl: getLoginUrlOptions(loginStyle, credentialToken, config, options),
            credentialRequestCompleteCallback: credentialRequestCompleteCallback,
            credentialToken: credentialToken,
            popupOptions: { width: 445, height: 625 }
        });
    }
};

var getLoginUrlOptions = function(loginStyle, credentialToken, config, options) {

    // Per default permissions we need the user to be able to sign in
    let scope = ['openid email profile'];
    // If requestOfflineToken is set to true, we request a refresh token through the wl.offline_access scope
    if (options.requestOfflineToken) {
        scope.push('wl.offline_access');
    }
    // All other request permissions in the options object is parsed afterward
    if (options.requestPermissions) {
        scope = _.union(scope, options.requestPermissions);
    }

    const loginUrlParameters = {};
    // First insert the ServiceConfiguration values
    if (config.loginUrlParameters){
        _.extend(loginUrlParameters, config.loginUrlParameters);
    }
    // Secondly insert the options that were inserted with the function call,
    // so they will override any ServiceConfiguration
    if (options.loginUrlParameters){
        _.extend(loginUrlParameters, options.loginUrlParameters);
    }
    // Make sure no url parameter was used as an option or config
    const illegal_parameters = ['response_type', 'client_id', 'scope', 'redirect_uri', 'state'];
    _.each(_.keys(loginUrlParameters), function (key) {
        if (_.contains(illegal_parameters, key)) {
            throw new Meteor.Error('okta-error', 'Okta.requestCredential: Invalid loginUrlParameter: ' + key);
        }
    });


    // Once we've actually completed the authentication, we will need to set in the
    // options where to return once we've finished. We will allow a session variable
    // called 'routeAfterOktaOauth' to be uniquely defined, otherwise it will default
    // to the root URL of the site. The format should be "/route/after/okta/here"
    fromWhere = Session.get('routeAfterOktaOauth') || '/';

    // Delete the leading / because Meteor.absouluteURL adds one too
    fromWhere = fromWhere.replace('/','');
    options.redirectUrl = Meteor.absoluteUrl(fromWhere);

    // Create all the necessary url options
    _.extend(loginUrlParameters, {
        response_type: 'code',
        client_id:  config.clientId,
        scope: scope.join(' '), // space delimited, everything is urlencoded later
        redirect_uri: OAuth._redirectUri(Okta.serviceName, config),
	    nonce: Random.secret(),
        state: OAuth._stateParam(loginStyle, credentialToken, options.redirectUrl)
    });

    // Build the actual urlencoded complete URL and return it so that we can launch login
    const oktacall =  'https://' + config.domain + '/oauth2/v1/authorize?' +
        _.map(loginUrlParameters, function(value, param){
            return encodeURIComponent(param) + '=' + encodeURIComponent(value);
        }).join('&');

    return oktacall;
};
