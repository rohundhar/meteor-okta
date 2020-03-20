Okta = {

    serviceName: 'okta',
    whitelistedFields: ['id', 'emails', 'first_name', 'last_name', 'name'],

    retrieveCredential: function(credentialToken, credentialSecret) {
        return OAuth.retrieveCredential(credentialToken, credentialSecret);
    }
};


/**
 * Register the Okta Service 
 * @param ServiceName : This is the name identifier for the service we are using. In this case, 'okta'
 * @param OAuth Version: The version of oauth that we are going to be using. In this case, 2
 * @param Oauth1 URLS: 
 * @param Callback(query): 'query' contains the return value from the redirect URI, which usually holds
 * a code and a state, which we use to get access tokens 
 *
 * @return: the return value is an object that contains 'serviceData', which holds the tokens we've received
 * and other relevant information, and 'options', which will populate the Meteor user's profile information 
 */
OAuth.registerService(Okta.serviceName, 2, null, function(query) {
    const config = ServiceConfiguration.configurations.findOne({service: Okta.serviceName});

    // If there is no configuration available, throw a config error
    if (!config) {
        throw new ServiceConfiguration.ConfigError();
    }

    const response = getTokens(query, config);

    // The + in front of the new Date gives it to us in milliseconds
    const expiresAt = (+new Date()) + (1000 * parseInt(response.expiresIn, 10));
    const identity = getIdentity(response.accessToken, config);

    const serviceData = {
        accessToken: response.accessToken,
        idToken: response.idToken,
        expiresAt: expiresAt,
        scope: response.scope
    };



    // Meteor accounts requires an id field in the identity object, but Okta does not provide
    // a specific id attribute. The user info return object does contain a field called 'sub',
    // for subject, which can be used for uniqueness 

    // This identity code block should customized to your okta domain

    if( identity && identity.sub) {
        identity.id = identity.sub;
    }

    if(!identity.id) {
        throw new Meteor.Error('okta-error', "Missing ID from okta profile");
    }

    _.extend(serviceData, identity);

    // Only set the token in serviceData if it's there. this ensures
    // that we don't lose old ones (since we only get this on the first
    // log in attempt)
    if (response.refreshToken)
        serviceData.refreshToken = response.refreshToken;


    // You can choose what information you want to return to the Meteor.profile(). In this case, we are
    // returning the name and email of the user
    return {
        serviceData: serviceData,
        options: {
            profile: {
                name: identity.name,
                email: identity.email
            }
        }
    };
});


/**
 * Use the data returned by the redirect URI and the configuration to actually grab access tokens 

 * @param query: data returned from the result of the redirect URI, containing a code and a state
 * @param config: the configuration of the okta service 
 * 
 * @return: an object that contains all of the relevant token data that we will need to authenticate
 * the user
 */
function getTokens(query, config) {
    let response;
    try {
        response = HTTP.post(
            "https://" + config.domain + "/oauth2/v1/token", {params: {
                code: query.code,
                client_id: config.clientId,
                client_secret: OAuth.openSecret(config.secret),
                redirect_uri: OAuth._redirectUri(Okta.serviceName, config),  //whitelist the redirect uri in the Okta app, the value is <domain>/_oauth/okta?close
		        grant_type: 'authorization_code'
            }});
    } 
    catch (err) {
        throw new Meteor.Error('okta-error', "HTTP.post Failure to complete Oauth handshake with Okta." + err.message, err.response)
    }

    if (response.data.error) { 
        // if the http response was a json object with an error attribute
        throw new Meteor.Error('okta-error', "Response Error: Failed to complete Oauth handshake with Okta.", response.data.error)
    } 
    else {
        return {
            accessToken: response.data.access_token,
            refreshToken: response.data.refresh_token,
            expiresIn: response.data.expires_in,
            idToken: response.data.id_token
        };
    }
};

/**
 * Get user profile info using accessToken. This can also be found in the idToken, but this needs to be
 * decoded from the JWTs
 * @param accessToken: accessToken from a previous step
 * @param config: the configuration of the okta service 
 * 
 * @return: The user profile that we receive from the okta domain 
 */
function getIdentity(accessToken, config) {
    try {
        const response = HTTP.get(
            "https://"+ config.domain + "/oauth2/v1/userinfo",
            { headers: 
                { Authorization: "Bearer " + accessToken,
                    Accept: "application/json"} 
            });
        return response.data;
    } 
    catch (err) {
        throw new Meteor.Error('okta-error', "Failed to fetch identity from Okta." + err.message, err.response)
    }
};
