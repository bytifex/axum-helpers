# Todo
* add the possibility to be able to choose where to store and accept the access token and the refresh token (http only cookie set by the server or in some http header)
* consider implementing automatic login refresh when the access token is expired
* implement a template app with refresh tokens and with a frontend
  * access tokens should expire in maximum of 10 minutes
  * refresh tokens should live for a few days (1 to 5)
  * access tokens should contain their expiration time and should be accepted only if it didn't expired yet
  * refresh tokens should be stored backend side and should be checked periodically whether they have to be removed or not
