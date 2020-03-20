Template.configureLoginServiceDialogForOkta.helpers({
	// Our expected redirect URI for the okta authentication to work
    siteUrl: function () {
         return Meteor.absoluteUrl() + "_oauth/" + Okta.serviceName;
    }
});

// This defines a user interface where you can setup the okta configuration
// from the client. In production, the configuration should be handled on the server 
// so that this is NOT available to the client
Template.configureLoginServiceDialogForOkta.fields = function () {
    return [
        {property: 'clientId', label: 'Client ID'},
        {property: 'secret', label: 'Client secret'},
        {property: 'domain', label: 'Okta Domain URL'}
    ];
};