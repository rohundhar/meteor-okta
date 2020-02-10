# Okta meteor package
__An implementation of the Okta OAuth flow__


## Getting started

Add the package to meteor (cannot add it yet)
```
meteor add roni:okta
```

## Basic usage

The usage is pretty much the same as all other OAuth flow implementations for meteor. It's inspired by the official Google meteor package.
Basically you can use:

```javascript
var callback = Accounts.oauth.credentialRequestCompleteHandler(callback);
Okta.requestCredential(options, callback);
```


## References

### Accounts package

* [roni:accounts-okta](https://github.com/rohundhar/meteor-accounts-okta)


