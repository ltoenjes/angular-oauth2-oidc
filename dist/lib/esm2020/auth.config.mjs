export class AuthConfig {
    constructor(json) {
        /**
         * The client's id as registered with the auth server
         */
        this.clientId = '';
        /**
         * The client's redirectUri as registered with the auth server
         */
        this.redirectUri = '';
        /**
         * An optional second redirectUri where the auth server
         * redirects the user to after logging out.
         */
        this.postLogoutRedirectUri = '';
        /**
         * Defines whether to use 'redirectUri' as a replacement
         * of 'postLogoutRedirectUri' if the latter is not set.
         */
        this.redirectUriAsPostLogoutRedirectUriFallback = true;
        /**
         * The auth server's endpoint that allows to log
         * the user in when using implicit flow.
         */
        this.loginUrl = '';
        /**
         * The requested scopes
         */
        this.scope = 'openid profile';
        this.resource = '';
        this.rngUrl = '';
        /**
         * Defines whether to use OpenId Connect during
         * implicit flow.
         */
        this.oidc = true;
        /**
         * Defines whether to request an access token during
         * implicit flow.
         */
        this.requestAccessToken = true;
        this.options = null;
        /**
         * The issuer's uri.
         */
        this.issuer = '';
        /**
         * The logout url.
         */
        this.logoutUrl = '';
        /**
         * Defines whether to clear the hash fragment after logging in.
         */
        this.clearHashAfterLogin = true;
        /**
         * Url of the token endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.tokenEndpoint = null;
        /**
         * Url of the revocation endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.revocationEndpoint = null;
        /**
         * Names of known parameters sent out in the TokenResponse. https://tools.ietf.org/html/rfc6749#section-5.1
         */
        this.customTokenParameters = [];
        /**
         * Url of the userinfo endpoint as defined by OpenId Connect.
         */
        this.userinfoEndpoint = null;
        this.responseType = '';
        /**
         * Defines whether additional debug information should
         * be shown at the console. Note that in certain browsers
         * the verbosity of the console needs to be explicitly set
         * to include Debug level messages.
         */
        this.showDebugInformation = false;
        /**
         * The redirect uri used when doing silent refresh.
         */
        this.silentRefreshRedirectUri = '';
        this.silentRefreshMessagePrefix = '';
        /**
         * Set this to true to display the iframe used for
         * silent refresh for debugging.
         */
        this.silentRefreshShowIFrame = false;
        /**
         * Timeout for silent refresh.
         * @internal
         * depreacted b/c of typo, see silentRefreshTimeout
         */
        this.siletRefreshTimeout = 1000 * 20;
        /**
         * Timeout for silent refresh.
         */
        this.silentRefreshTimeout = 1000 * 20;
        /**
         * Some auth servers don't allow using password flow
         * w/o a client secret while the standards do not
         * demand for it. In this case, you can set a password
         * here. As this password is exposed to the public
         * it does not bring additional security and is therefore
         * as good as using no password.
         */
        this.dummyClientSecret = null;
        /**
         * Defines whether https is required.
         * The default value is remoteOnly which only allows
         * http for localhost, while every other domains need
         * to be used with https.
         */
        this.requireHttps = 'remoteOnly';
        /**
         * Defines whether every url provided by the discovery
         * document has to start with the issuer's url.
         */
        this.strictDiscoveryDocumentValidation = true;
        /**
         * JSON Web Key Set (https://tools.ietf.org/html/rfc7517)
         * with keys used to validate received id_tokens.
         * This is taken out of the disovery document. Can be set manually too.
         */
        this.jwks = null;
        /**
         * Map with additional query parameter that are appended to
         * the request when initializing implicit flow.
         */
        this.customQueryParams = null;
        this.silentRefreshIFrameName = 'angular-oauth-oidc-silent-refresh-iframe';
        /**
         * Defines when the token_timeout event should be raised.
         * If you set this to the default value 0.75, the event
         * is triggered after 75% of the token's life time.
         */
        this.timeoutFactor = 0.75;
        /**
         * If true, the lib will try to check whether the user
         * is still logged in on a regular basis as described
         * in http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionChecksEnabled = false;
        /**
         * Interval in msec for checking the session
         * according to http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionCheckIntervall = 3 * 1000;
        /**
         * Url for the iframe used for session checks
         */
        this.sessionCheckIFrameUrl = null;
        /**
         * Name of the iframe to use for session checks
         */
        this.sessionCheckIFrameName = 'angular-oauth-oidc-check-session-iframe';
        /**
         * This property has been introduced to disable at_hash checks
         * and is indented for Identity Provider that does not deliver
         * an at_hash EVEN THOUGH its recommended by the OIDC specs.
         * Of course, when disabling these checks then we are bypassing
         * a security check which means we are more vulnerable.
         */
        this.disableAtHashCheck = false;
        /**
         * Defines wether to check the subject of a refreshed token after silent refresh.
         * Normally, it should be the same as before.
         */
        this.skipSubjectCheck = false;
        this.useIdTokenHintForSilentRefresh = false;
        /**
         * Defined whether to skip the validation of the issuer in the discovery document.
         * Normally, the discovey document's url starts with the url of the issuer.
         */
        this.skipIssuerCheck = false;
        /**
         * final state sent to issuer is built as follows:
         * state = nonce + nonceStateSeparator + additional state
         * Default separator is ';' (encoded %3B).
         * In rare cases, this character might be forbidden or inconvenient to use by the issuer so it can be customized.
         */
        this.nonceStateSeparator = ';';
        /**
         * Set this to true to use HTTP BASIC auth for AJAX calls
         */
        this.useHttpBasicAuth = false;
        /**
         * The interceptors waits this time span if there is no token
         */
        this.waitForTokenInMsec = 0;
        /**
         * Code Flow is by defauld used together with PKCI which is also higly recommented.
         * You can disbale it here by setting this flag to true.
         * https://tools.ietf.org/html/rfc7636#section-1.1
         */
        this.disablePKCE = false;
        /**
         * Set this to true to preserve the requested route including query parameters after code flow login.
         * This setting enables deep linking for the code flow.
         */
        this.preserveRequestedRoute = false;
        /**
         * This property allows you to override the method that is used to open the login url,
         * allowing a way for implementations to specify their own method of routing to new
         * urls.
         */
        this.openUri = (uri) => {
            location.href = uri;
        };
        if (json) {
            Object.assign(this, json);
        }
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5jb25maWcuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9wcm9qZWN0cy9saWIvc3JjL2F1dGguY29uZmlnLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLE1BQU0sT0FBTyxVQUFVO0lBeVFyQixZQUFZLElBQTBCO1FBeFF0Qzs7V0FFRztRQUNJLGFBQVEsR0FBSSxFQUFFLENBQUM7UUFFdEI7O1dBRUc7UUFDSSxnQkFBVyxHQUFJLEVBQUUsQ0FBQztRQUV6Qjs7O1dBR0c7UUFDSSwwQkFBcUIsR0FBSSxFQUFFLENBQUM7UUFFbkM7OztXQUdHO1FBQ0ksK0NBQTBDLEdBQUksSUFBSSxDQUFDO1FBRTFEOzs7V0FHRztRQUNJLGFBQVEsR0FBSSxFQUFFLENBQUM7UUFFdEI7O1dBRUc7UUFDSSxVQUFLLEdBQUksZ0JBQWdCLENBQUM7UUFFMUIsYUFBUSxHQUFJLEVBQUUsQ0FBQztRQUVmLFdBQU0sR0FBSSxFQUFFLENBQUM7UUFFcEI7OztXQUdHO1FBQ0ksU0FBSSxHQUFJLElBQUksQ0FBQztRQUVwQjs7O1dBR0c7UUFDSSx1QkFBa0IsR0FBSSxJQUFJLENBQUM7UUFFM0IsWUFBTyxHQUFTLElBQUksQ0FBQztRQUU1Qjs7V0FFRztRQUNJLFdBQU0sR0FBSSxFQUFFLENBQUM7UUFFcEI7O1dBRUc7UUFDSSxjQUFTLEdBQUksRUFBRSxDQUFDO1FBRXZCOztXQUVHO1FBQ0ksd0JBQW1CLEdBQUksSUFBSSxDQUFDO1FBRW5DOztXQUVHO1FBQ0ksa0JBQWEsR0FBWSxJQUFJLENBQUM7UUFFckM7O1dBRUc7UUFDSSx1QkFBa0IsR0FBWSxJQUFJLENBQUM7UUFFMUM7O1dBRUc7UUFDSSwwQkFBcUIsR0FBYyxFQUFFLENBQUM7UUFFN0M7O1dBRUc7UUFDSSxxQkFBZ0IsR0FBWSxJQUFJLENBQUM7UUFFakMsaUJBQVksR0FBSSxFQUFFLENBQUM7UUFFMUI7Ozs7O1dBS0c7UUFDSSx5QkFBb0IsR0FBSSxLQUFLLENBQUM7UUFFckM7O1dBRUc7UUFDSSw2QkFBd0IsR0FBSSxFQUFFLENBQUM7UUFFL0IsK0JBQTBCLEdBQUksRUFBRSxDQUFDO1FBRXhDOzs7V0FHRztRQUNJLDRCQUF1QixHQUFJLEtBQUssQ0FBQztRQUV4Qzs7OztXQUlHO1FBQ0ksd0JBQW1CLEdBQVksSUFBSSxHQUFHLEVBQUUsQ0FBQztRQUVoRDs7V0FFRztRQUNJLHlCQUFvQixHQUFZLElBQUksR0FBRyxFQUFFLENBQUM7UUFFakQ7Ozs7Ozs7V0FPRztRQUNJLHNCQUFpQixHQUFZLElBQUksQ0FBQztRQUV6Qzs7Ozs7V0FLRztRQUNJLGlCQUFZLEdBQTRCLFlBQVksQ0FBQztRQUU1RDs7O1dBR0c7UUFDSSxzQ0FBaUMsR0FBSSxJQUFJLENBQUM7UUFFakQ7Ozs7V0FJRztRQUNJLFNBQUksR0FBWSxJQUFJLENBQUM7UUFFNUI7OztXQUdHO1FBQ0ksc0JBQWlCLEdBQVksSUFBSSxDQUFDO1FBRWxDLDRCQUF1QixHQUFJLDBDQUEwQyxDQUFDO1FBRTdFOzs7O1dBSUc7UUFDSSxrQkFBYSxHQUFJLElBQUksQ0FBQztRQUU3Qjs7OztXQUlHO1FBQ0kseUJBQW9CLEdBQUksS0FBSyxDQUFDO1FBRXJDOzs7V0FHRztRQUNJLDBCQUFxQixHQUFJLENBQUMsR0FBRyxJQUFJLENBQUM7UUFFekM7O1dBRUc7UUFDSSwwQkFBcUIsR0FBWSxJQUFJLENBQUM7UUFFN0M7O1dBRUc7UUFDSSwyQkFBc0IsR0FBSSx5Q0FBeUMsQ0FBQztRQUUzRTs7Ozs7O1dBTUc7UUFDSSx1QkFBa0IsR0FBSSxLQUFLLENBQUM7UUFFbkM7OztXQUdHO1FBQ0kscUJBQWdCLEdBQUksS0FBSyxDQUFDO1FBRTFCLG1DQUE4QixHQUFJLEtBQUssQ0FBQztRQUUvQzs7O1dBR0c7UUFDSSxvQkFBZSxHQUFJLEtBQUssQ0FBQztRQVNoQzs7Ozs7V0FLRztRQUNJLHdCQUFtQixHQUFJLEdBQUcsQ0FBQztRQUVsQzs7V0FFRztRQUNJLHFCQUFnQixHQUFJLEtBQUssQ0FBQztRQU9qQzs7V0FFRztRQUNJLHVCQUFrQixHQUFJLENBQUMsQ0FBQztRQVUvQjs7OztXQUlHO1FBQ0ksZ0JBQVcsR0FBSSxLQUFLLENBQUM7UUFFNUI7OztXQUdHO1FBQ0ksMkJBQXNCLEdBQUksS0FBSyxDQUFDO1FBUXZDOzs7O1dBSUc7UUFDSSxZQUFPLEdBQTJCLENBQUMsR0FBRyxFQUFFLEVBQUU7WUFDL0MsUUFBUSxDQUFDLElBQUksR0FBRyxHQUFHLENBQUM7UUFDdEIsQ0FBQyxDQUFDO1FBWkEsSUFBSSxJQUFJLEVBQUU7WUFDUixNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksRUFBRSxJQUFJLENBQUMsQ0FBQztTQUMzQjtJQUNILENBQUM7Q0FVRiIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBjbGFzcyBBdXRoQ29uZmlnIHtcbiAgLyoqXG4gICAqIFRoZSBjbGllbnQncyBpZCBhcyByZWdpc3RlcmVkIHdpdGggdGhlIGF1dGggc2VydmVyXG4gICAqL1xuICBwdWJsaWMgY2xpZW50SWQ/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFRoZSBjbGllbnQncyByZWRpcmVjdFVyaSBhcyByZWdpc3RlcmVkIHdpdGggdGhlIGF1dGggc2VydmVyXG4gICAqL1xuICBwdWJsaWMgcmVkaXJlY3RVcmk/ID0gJyc7XG5cbiAgLyoqXG4gICAqIEFuIG9wdGlvbmFsIHNlY29uZCByZWRpcmVjdFVyaSB3aGVyZSB0aGUgYXV0aCBzZXJ2ZXJcbiAgICogcmVkaXJlY3RzIHRoZSB1c2VyIHRvIGFmdGVyIGxvZ2dpbmcgb3V0LlxuICAgKi9cbiAgcHVibGljIHBvc3RMb2dvdXRSZWRpcmVjdFVyaT8gPSAnJztcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIHRvIHVzZSAncmVkaXJlY3RVcmknIGFzIGEgcmVwbGFjZW1lbnRcbiAgICogb2YgJ3Bvc3RMb2dvdXRSZWRpcmVjdFVyaScgaWYgdGhlIGxhdHRlciBpcyBub3Qgc2V0LlxuICAgKi9cbiAgcHVibGljIHJlZGlyZWN0VXJpQXNQb3N0TG9nb3V0UmVkaXJlY3RVcmlGYWxsYmFjaz8gPSB0cnVlO1xuXG4gIC8qKlxuICAgKiBUaGUgYXV0aCBzZXJ2ZXIncyBlbmRwb2ludCB0aGF0IGFsbG93cyB0byBsb2dcbiAgICogdGhlIHVzZXIgaW4gd2hlbiB1c2luZyBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIGxvZ2luVXJsPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBUaGUgcmVxdWVzdGVkIHNjb3Blc1xuICAgKi9cbiAgcHVibGljIHNjb3BlPyA9ICdvcGVuaWQgcHJvZmlsZSc7XG5cbiAgcHVibGljIHJlc291cmNlPyA9ICcnO1xuXG4gIHB1YmxpYyBybmdVcmw/ID0gJyc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciB0byB1c2UgT3BlbklkIENvbm5lY3QgZHVyaW5nXG4gICAqIGltcGxpY2l0IGZsb3cuXG4gICAqL1xuICBwdWJsaWMgb2lkYz8gPSB0cnVlO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgdG8gcmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gZHVyaW5nXG4gICAqIGltcGxpY2l0IGZsb3cuXG4gICAqL1xuICBwdWJsaWMgcmVxdWVzdEFjY2Vzc1Rva2VuPyA9IHRydWU7XG5cbiAgcHVibGljIG9wdGlvbnM/OiBhbnkgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBUaGUgaXNzdWVyJ3MgdXJpLlxuICAgKi9cbiAgcHVibGljIGlzc3Vlcj8gPSAnJztcblxuICAvKipcbiAgICogVGhlIGxvZ291dCB1cmwuXG4gICAqL1xuICBwdWJsaWMgbG9nb3V0VXJsPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgdG8gY2xlYXIgdGhlIGhhc2ggZnJhZ21lbnQgYWZ0ZXIgbG9nZ2luZyBpbi5cbiAgICovXG4gIHB1YmxpYyBjbGVhckhhc2hBZnRlckxvZ2luPyA9IHRydWU7XG5cbiAgLyoqXG4gICAqIFVybCBvZiB0aGUgdG9rZW4gZW5kcG9pbnQgYXMgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdCBhbmQgT0F1dGggMi5cbiAgICovXG4gIHB1YmxpYyB0b2tlbkVuZHBvaW50Pzogc3RyaW5nID0gbnVsbDtcblxuICAvKipcbiAgICogVXJsIG9mIHRoZSByZXZvY2F0aW9uIGVuZHBvaW50IGFzIGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QgYW5kIE9BdXRoIDIuXG4gICAqL1xuICBwdWJsaWMgcmV2b2NhdGlvbkVuZHBvaW50Pzogc3RyaW5nID0gbnVsbDtcblxuICAvKipcbiAgICogTmFtZXMgb2Yga25vd24gcGFyYW1ldGVycyBzZW50IG91dCBpbiB0aGUgVG9rZW5SZXNwb25zZS4gaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi01LjFcbiAgICovXG4gIHB1YmxpYyBjdXN0b21Ub2tlblBhcmFtZXRlcnM/OiBzdHJpbmdbXSA9IFtdO1xuXG4gIC8qKlxuICAgKiBVcmwgb2YgdGhlIHVzZXJpbmZvIGVuZHBvaW50IGFzIGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QuXG4gICAqL1xuICBwdWJsaWMgdXNlcmluZm9FbmRwb2ludD86IHN0cmluZyA9IG51bGw7XG5cbiAgcHVibGljIHJlc3BvbnNlVHlwZT8gPSAnJztcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIGFkZGl0aW9uYWwgZGVidWcgaW5mb3JtYXRpb24gc2hvdWxkXG4gICAqIGJlIHNob3duIGF0IHRoZSBjb25zb2xlLiBOb3RlIHRoYXQgaW4gY2VydGFpbiBicm93c2Vyc1xuICAgKiB0aGUgdmVyYm9zaXR5IG9mIHRoZSBjb25zb2xlIG5lZWRzIHRvIGJlIGV4cGxpY2l0bHkgc2V0XG4gICAqIHRvIGluY2x1ZGUgRGVidWcgbGV2ZWwgbWVzc2FnZXMuXG4gICAqL1xuICBwdWJsaWMgc2hvd0RlYnVnSW5mb3JtYXRpb24/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIFRoZSByZWRpcmVjdCB1cmkgdXNlZCB3aGVuIGRvaW5nIHNpbGVudCByZWZyZXNoLlxuICAgKi9cbiAgcHVibGljIHNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaT8gPSAnJztcblxuICBwdWJsaWMgc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXg/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFNldCB0aGlzIHRvIHRydWUgdG8gZGlzcGxheSB0aGUgaWZyYW1lIHVzZWQgZm9yXG4gICAqIHNpbGVudCByZWZyZXNoIGZvciBkZWJ1Z2dpbmcuXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaFNob3dJRnJhbWU/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIFRpbWVvdXQgZm9yIHNpbGVudCByZWZyZXNoLlxuICAgKiBAaW50ZXJuYWxcbiAgICogZGVwcmVhY3RlZCBiL2Mgb2YgdHlwbywgc2VlIHNpbGVudFJlZnJlc2hUaW1lb3V0XG4gICAqL1xuICBwdWJsaWMgc2lsZXRSZWZyZXNoVGltZW91dD86IG51bWJlciA9IDEwMDAgKiAyMDtcblxuICAvKipcbiAgICogVGltZW91dCBmb3Igc2lsZW50IHJlZnJlc2guXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaFRpbWVvdXQ/OiBudW1iZXIgPSAxMDAwICogMjA7XG5cbiAgLyoqXG4gICAqIFNvbWUgYXV0aCBzZXJ2ZXJzIGRvbid0IGFsbG93IHVzaW5nIHBhc3N3b3JkIGZsb3dcbiAgICogdy9vIGEgY2xpZW50IHNlY3JldCB3aGlsZSB0aGUgc3RhbmRhcmRzIGRvIG5vdFxuICAgKiBkZW1hbmQgZm9yIGl0LiBJbiB0aGlzIGNhc2UsIHlvdSBjYW4gc2V0IGEgcGFzc3dvcmRcbiAgICogaGVyZS4gQXMgdGhpcyBwYXNzd29yZCBpcyBleHBvc2VkIHRvIHRoZSBwdWJsaWNcbiAgICogaXQgZG9lcyBub3QgYnJpbmcgYWRkaXRpb25hbCBzZWN1cml0eSBhbmQgaXMgdGhlcmVmb3JlXG4gICAqIGFzIGdvb2QgYXMgdXNpbmcgbm8gcGFzc3dvcmQuXG4gICAqL1xuICBwdWJsaWMgZHVtbXlDbGllbnRTZWNyZXQ/OiBzdHJpbmcgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgaHR0cHMgaXMgcmVxdWlyZWQuXG4gICAqIFRoZSBkZWZhdWx0IHZhbHVlIGlzIHJlbW90ZU9ubHkgd2hpY2ggb25seSBhbGxvd3NcbiAgICogaHR0cCBmb3IgbG9jYWxob3N0LCB3aGlsZSBldmVyeSBvdGhlciBkb21haW5zIG5lZWRcbiAgICogdG8gYmUgdXNlZCB3aXRoIGh0dHBzLlxuICAgKi9cbiAgcHVibGljIHJlcXVpcmVIdHRwcz86IGJvb2xlYW4gfCAncmVtb3RlT25seScgPSAncmVtb3RlT25seSc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciBldmVyeSB1cmwgcHJvdmlkZWQgYnkgdGhlIGRpc2NvdmVyeVxuICAgKiBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyJ3MgdXJsLlxuICAgKi9cbiAgcHVibGljIHN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbj8gPSB0cnVlO1xuXG4gIC8qKlxuICAgKiBKU09OIFdlYiBLZXkgU2V0IChodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzUxNylcbiAgICogd2l0aCBrZXlzIHVzZWQgdG8gdmFsaWRhdGUgcmVjZWl2ZWQgaWRfdG9rZW5zLlxuICAgKiBUaGlzIGlzIHRha2VuIG91dCBvZiB0aGUgZGlzb3ZlcnkgZG9jdW1lbnQuIENhbiBiZSBzZXQgbWFudWFsbHkgdG9vLlxuICAgKi9cbiAgcHVibGljIGp3a3M/OiBvYmplY3QgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBNYXAgd2l0aCBhZGRpdGlvbmFsIHF1ZXJ5IHBhcmFtZXRlciB0aGF0IGFyZSBhcHBlbmRlZCB0b1xuICAgKiB0aGUgcmVxdWVzdCB3aGVuIGluaXRpYWxpemluZyBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIGN1c3RvbVF1ZXJ5UGFyYW1zPzogb2JqZWN0ID0gbnVsbDtcblxuICBwdWJsaWMgc2lsZW50UmVmcmVzaElGcmFtZU5hbWU/ID0gJ2FuZ3VsYXItb2F1dGgtb2lkYy1zaWxlbnQtcmVmcmVzaC1pZnJhbWUnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZW4gdGhlIHRva2VuX3RpbWVvdXQgZXZlbnQgc2hvdWxkIGJlIHJhaXNlZC5cbiAgICogSWYgeW91IHNldCB0aGlzIHRvIHRoZSBkZWZhdWx0IHZhbHVlIDAuNzUsIHRoZSBldmVudFxuICAgKiBpcyB0cmlnZ2VyZWQgYWZ0ZXIgNzUlIG9mIHRoZSB0b2tlbidzIGxpZmUgdGltZS5cbiAgICovXG4gIHB1YmxpYyB0aW1lb3V0RmFjdG9yPyA9IDAuNzU7XG5cbiAgLyoqXG4gICAqIElmIHRydWUsIHRoZSBsaWIgd2lsbCB0cnkgdG8gY2hlY2sgd2hldGhlciB0aGUgdXNlclxuICAgKiBpcyBzdGlsbCBsb2dnZWQgaW4gb24gYSByZWd1bGFyIGJhc2lzIGFzIGRlc2NyaWJlZFxuICAgKiBpbiBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1zZXNzaW9uLTFfMC5odG1sI0NoYW5nZU5vdGlmaWNhdGlvblxuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja3NFbmFibGVkPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBJbnRlcnZhbCBpbiBtc2VjIGZvciBjaGVja2luZyB0aGUgc2Vzc2lvblxuICAgKiBhY2NvcmRpbmcgdG8gaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3Qtc2Vzc2lvbi0xXzAuaHRtbCNDaGFuZ2VOb3RpZmljYXRpb25cbiAgICovXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tJbnRlcnZhbGw/ID0gMyAqIDEwMDA7XG5cbiAgLyoqXG4gICAqIFVybCBmb3IgdGhlIGlmcmFtZSB1c2VkIGZvciBzZXNzaW9uIGNoZWNrc1xuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja0lGcmFtZVVybD86IHN0cmluZyA9IG51bGw7XG5cbiAgLyoqXG4gICAqIE5hbWUgb2YgdGhlIGlmcmFtZSB0byB1c2UgZm9yIHNlc3Npb24gY2hlY2tzXG4gICAqL1xuICBwdWJsaWMgc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZT8gPSAnYW5ndWxhci1vYXV0aC1vaWRjLWNoZWNrLXNlc3Npb24taWZyYW1lJztcblxuICAvKipcbiAgICogVGhpcyBwcm9wZXJ0eSBoYXMgYmVlbiBpbnRyb2R1Y2VkIHRvIGRpc2FibGUgYXRfaGFzaCBjaGVja3NcbiAgICogYW5kIGlzIGluZGVudGVkIGZvciBJZGVudGl0eSBQcm92aWRlciB0aGF0IGRvZXMgbm90IGRlbGl2ZXJcbiAgICogYW4gYXRfaGFzaCBFVkVOIFRIT1VHSCBpdHMgcmVjb21tZW5kZWQgYnkgdGhlIE9JREMgc3BlY3MuXG4gICAqIE9mIGNvdXJzZSwgd2hlbiBkaXNhYmxpbmcgdGhlc2UgY2hlY2tzIHRoZW4gd2UgYXJlIGJ5cGFzc2luZ1xuICAgKiBhIHNlY3VyaXR5IGNoZWNrIHdoaWNoIG1lYW5zIHdlIGFyZSBtb3JlIHZ1bG5lcmFibGUuXG4gICAqL1xuICBwdWJsaWMgZGlzYWJsZUF0SGFzaENoZWNrPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdldGhlciB0byBjaGVjayB0aGUgc3ViamVjdCBvZiBhIHJlZnJlc2hlZCB0b2tlbiBhZnRlciBzaWxlbnQgcmVmcmVzaC5cbiAgICogTm9ybWFsbHksIGl0IHNob3VsZCBiZSB0aGUgc2FtZSBhcyBiZWZvcmUuXG4gICAqL1xuICBwdWJsaWMgc2tpcFN1YmplY3RDaGVjaz8gPSBmYWxzZTtcblxuICBwdWJsaWMgdXNlSWRUb2tlbkhpbnRGb3JTaWxlbnRSZWZyZXNoPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVkIHdoZXRoZXIgdG8gc2tpcCB0aGUgdmFsaWRhdGlvbiBvZiB0aGUgaXNzdWVyIGluIHRoZSBkaXNjb3ZlcnkgZG9jdW1lbnQuXG4gICAqIE5vcm1hbGx5LCB0aGUgZGlzY292ZXkgZG9jdW1lbnQncyB1cmwgc3RhcnRzIHdpdGggdGhlIHVybCBvZiB0aGUgaXNzdWVyLlxuICAgKi9cbiAgcHVibGljIHNraXBJc3N1ZXJDaGVjaz8gPSBmYWxzZTtcblxuICAvKipcbiAgICogQWNjb3JkaW5nIHRvIHJmYzY3NDkgaXQgaXMgcmVjb21tZW5kZWQgKGJ1dCBub3QgcmVxdWlyZWQpIHRoYXQgdGhlIGF1dGhcbiAgICogc2VydmVyIGV4cG9zZXMgdGhlIGFjY2Vzc190b2tlbidzIGxpZmUgdGltZSBpbiBzZWNvbmRzLlxuICAgKiBUaGlzIGlzIGEgZmFsbGJhY2sgdmFsdWUgZm9yIHRoZSBjYXNlIHRoaXMgdmFsdWUgaXMgbm90IGV4cG9zZWQuXG4gICAqL1xuICBwdWJsaWMgZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWM/OiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIGZpbmFsIHN0YXRlIHNlbnQgdG8gaXNzdWVyIGlzIGJ1aWx0IGFzIGZvbGxvd3M6XG4gICAqIHN0YXRlID0gbm9uY2UgKyBub25jZVN0YXRlU2VwYXJhdG9yICsgYWRkaXRpb25hbCBzdGF0ZVxuICAgKiBEZWZhdWx0IHNlcGFyYXRvciBpcyAnOycgKGVuY29kZWQgJTNCKS5cbiAgICogSW4gcmFyZSBjYXNlcywgdGhpcyBjaGFyYWN0ZXIgbWlnaHQgYmUgZm9yYmlkZGVuIG9yIGluY29udmVuaWVudCB0byB1c2UgYnkgdGhlIGlzc3VlciBzbyBpdCBjYW4gYmUgY3VzdG9taXplZC5cbiAgICovXG4gIHB1YmxpYyBub25jZVN0YXRlU2VwYXJhdG9yPyA9ICc7JztcblxuICAvKipcbiAgICogU2V0IHRoaXMgdG8gdHJ1ZSB0byB1c2UgSFRUUCBCQVNJQyBhdXRoIGZvciBBSkFYIGNhbGxzXG4gICAqL1xuICBwdWJsaWMgdXNlSHR0cEJhc2ljQXV0aD8gPSBmYWxzZTtcblxuICAvKipcbiAgICogVGhlIHdpbmRvdyBvZiB0aW1lIChpbiBzZWNvbmRzKSB0byBhbGxvdyB0aGUgY3VycmVudCB0aW1lIHRvIGRldmlhdGUgd2hlbiB2YWxpZGF0aW5nIGlkX3Rva2VuJ3MgaWF0IGFuZCBleHAgdmFsdWVzLlxuICAgKi9cbiAgcHVibGljIGNsb2NrU2tld0luU2VjPzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBUaGUgaW50ZXJjZXB0b3JzIHdhaXRzIHRoaXMgdGltZSBzcGFuIGlmIHRoZXJlIGlzIG5vIHRva2VuXG4gICAqL1xuICBwdWJsaWMgd2FpdEZvclRva2VuSW5Nc2VjPyA9IDA7XG5cbiAgLyoqXG4gICAqIFNldCB0aGlzIHRvIHRydWUgaWYgeW91IHdhbnQgdG8gdXNlIHNpbGVudCByZWZyZXNoIHRvZ2V0aGVyIHdpdGhcbiAgICogY29kZSBmbG93LiBBcyBzaWxlbnQgcmVmcmVzaCBpcyB0aGUgb25seSBvcHRpb24gZm9yIHJlZnJlc2hpbmdcbiAgICogd2l0aCBpbXBsaWNpdCBmbG93LCB5b3UgZG9uJ3QgbmVlZCB0byBleHBsaWNpdGx5IHR1cm4gaXQgb24gaW5cbiAgICogdGhpcyBjYXNlLlxuICAgKi9cbiAgcHVibGljIHVzZVNpbGVudFJlZnJlc2g/O1xuXG4gIC8qKlxuICAgKiBDb2RlIEZsb3cgaXMgYnkgZGVmYXVsZCB1c2VkIHRvZ2V0aGVyIHdpdGggUEtDSSB3aGljaCBpcyBhbHNvIGhpZ2x5IHJlY29tbWVudGVkLlxuICAgKiBZb3UgY2FuIGRpc2JhbGUgaXQgaGVyZSBieSBzZXR0aW5nIHRoaXMgZmxhZyB0byB0cnVlLlxuICAgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzYzNiNzZWN0aW9uLTEuMVxuICAgKi9cbiAgcHVibGljIGRpc2FibGVQS0NFPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBTZXQgdGhpcyB0byB0cnVlIHRvIHByZXNlcnZlIHRoZSByZXF1ZXN0ZWQgcm91dGUgaW5jbHVkaW5nIHF1ZXJ5IHBhcmFtZXRlcnMgYWZ0ZXIgY29kZSBmbG93IGxvZ2luLlxuICAgKiBUaGlzIHNldHRpbmcgZW5hYmxlcyBkZWVwIGxpbmtpbmcgZm9yIHRoZSBjb2RlIGZsb3cuXG4gICAqL1xuICBwdWJsaWMgcHJlc2VydmVSZXF1ZXN0ZWRSb3V0ZT8gPSBmYWxzZTtcblxuICBjb25zdHJ1Y3Rvcihqc29uPzogUGFydGlhbDxBdXRoQ29uZmlnPikge1xuICAgIGlmIChqc29uKSB7XG4gICAgICBPYmplY3QuYXNzaWduKHRoaXMsIGpzb24pO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIHByb3BlcnR5IGFsbG93cyB5b3UgdG8gb3ZlcnJpZGUgdGhlIG1ldGhvZCB0aGF0IGlzIHVzZWQgdG8gb3BlbiB0aGUgbG9naW4gdXJsLFxuICAgKiBhbGxvd2luZyBhIHdheSBmb3IgaW1wbGVtZW50YXRpb25zIHRvIHNwZWNpZnkgdGhlaXIgb3duIG1ldGhvZCBvZiByb3V0aW5nIHRvIG5ld1xuICAgKiB1cmxzLlxuICAgKi9cbiAgcHVibGljIG9wZW5Vcmk/OiAodXJpOiBzdHJpbmcpID0+IHZvaWQgPSAodXJpKSA9PiB7XG4gICAgbG9jYXRpb24uaHJlZiA9IHVyaTtcbiAgfTtcbn1cbiJdfQ==