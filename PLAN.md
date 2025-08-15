# Learning OAuth 2.1 with Go

I want to create a simple example application to learn about OAuth 2.1.
The final goal is to understand OAuth messages and exchanges good enough to be able to implement it in the MCP server that I'm working on.

## Application requirements

- The application should be written in Go
- You should use Go standard library as much as possible and use other libraries only when something is not possible to implement using the standard library
- For web services use Chi library
- This project should consist of two parts: the client application requesting some resource and the resource provider that provides some resource only to properly authorized clients. The resource can be a simple file or something like that.
- The resource provider should also implement a simple login page that will be used when the client request authentication. Or it can be a separate (third) application to follow the classic flow diagram.
- The login application should have three sample accounts with username and password. The can be stored in the source code or in a JSON file. No need to use databases. For simplicity and demonstration purposes, we can skip password encryption, but if it doesn't make the application significantly more complex, let's add password encryption too.
- Both the client application and the resource provider should show all OAuth-related messages they exchange and show them in formatted text for better readability. The messages should be clearly marked to show who is sending what to whom.

The whole project should provided detailed documentation with step-by-step explanation of the authentication flow.
