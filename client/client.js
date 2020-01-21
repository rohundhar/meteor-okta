
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
        var config = ServiceConfiguration.configurations.findOne({service: Okta.serviceName});
        // If none exist, try loading from Meteor settings else, throw the default ServiceConfiguration error
        if (!config) {
            //If config is not available construct one from env variables.
            console.log("Loading Okta config from Meteor settings");
            if(Meteor.settings && Meteor.settings.public &&  Meteor.settings.public.okta) {
                config = {
                    clientId : Meteor.settings.public.okta.clientId,
                    domain : Meteor.settings.public.okta.domain
                }
            } else {
                console.error("Okta serviceconfiguration error. Okta settings not found");
                credentialRequestCompleteCallback &&
                credentialRequestCompleteCallback(new ServiceConfiguration.ConfigError());
                return;
            }
        }

        // Generate a token to be used in the state and the OAuth flow
        var credentialToken = Random.secret(),
            loginStyle = "redirect";   //other option is "popup" which opens a pop up window


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
    var scope = ['openid email profile'];
    // If requestOfflineToken is set to true, we request a refresh token through the wl.offline_access scope
    if (options.requestOfflineToken) {
        scope.push('wl.offline_access');
    }
    // All other request permissions in the options object is afterward parsed
    if (options.requestPermissions) {
        scope = _.union(scope, options.requestPermissions);
    }

    var loginUrlParameters = {};
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
    var illegal_parameters = ['response_type', 'client_id', 'scope', 'redirect_uri', 'state'];
    _.each(_.keys(loginUrlParameters), function (key) {
        if (_.contains(illegal_parameters, key)) {
            throw new Error('Okta.requestCredential: Invalid loginUrlParameter: ' + key);
        }
    });

    //in your router get the initial url the user is trying to access and
    //redirect the user back to that uri on successful authentication
    //in this case user is being redirected to /library/processes
    fromWhere = Session.get('fromWhere') || '/library/processes';
    //delete the leading / because Meteor.absouluteURL adds one too
    fromWhere = fromWhere.replace('/','');
    options.redirectUrl = Meteor.absoluteUrl(fromWhere);
    // Create all the necessary url options
    _.extend(loginUrlParameters, {
        response_type: 'code',
        client_id:  config.clientId,
        scope: scope.join(' '), // space delimited, everything is later urlencoded!
        redirect_uri: OAuth._redirectUri(Okta.serviceName, config),
        nonce: Random.secret(),
        state: OAuth._stateParam(loginStyle, credentialToken, options.redirectUrl)
    });

    var oktacall =  'https://' + config.domain + '/oauth2/v1/authorize?' +
        _.map(loginUrlParameters, function(value, param){
            return encodeURIComponent(param) + '=' + encodeURIComponent(value);
        }).join('&');

    return oktacall;
};
