Package.describe({
  name: 'roni:okta',
  version: '0.1.0',
  summary: 'An implementation of the Okta OAuth flow.',
  git: 'https://github.com/rohundhar/meteor-okta',
  documentation: 'README.md'
});

Package.onUse(function(api) {
  // Meteor Version 
  api.versionsFrom('1.8.0.2');
  
  api.use('ecmascript');
  api.use('templating', 'client');
  api.use('random', 'client');
  api.use('oauth2', ['client', 'server']);
  api.use('oauth', ['client', 'server']);
  api.use('http', 'server');
  api.use('service-configuration', ['client', 'server']);

  api.export('Okta');

  api.addFiles('client/configure.html', 'client');
  api.addFiles('server/server.js', 'server');
  api.addFiles(['client/client.js', 'client/configure.js'], 'client');
});
